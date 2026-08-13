mod support;

use std::{convert::Infallible, sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{Request, Response, StatusCode, Version, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tlsplus_core::{start_local_server, stop_local_server};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    net::TcpStream,
    sync::{Mutex, oneshot},
};

static TEST_MUTEX: Mutex<()> = Mutex::const_new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preserves_http2_across_both_proxy_legs() {
    let _guard = TEST_MUTEX.lock().await;

    // Given: an HTTP/2-only upstream that records the received protocol version.
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind HTTP/2 upstream");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (observed_tx, observed_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.expect("accept upstream client");
        let observed_tx = Arc::new(std::sync::Mutex::new(Some(observed_tx)));
        let service = service_fn(move |request: Request<Incoming>| {
            if let Some(sender) = observed_tx.lock().expect("lock protocol observer").take() {
                let _ = sender.send(request.version());
            }
            async move { Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"h2-body")))) }
        });
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await
            .expect("serve HTTP/2 upstream connection");
    });

    let proxy_addr = support::ephemeral_listen_addr();
    let _ = stop_local_server();
    let started = start_local_server(proxy_addr.clone());
    assert!(
        started.running,
        "failed to start TLS+ proxy: {}",
        started.message
    );

    // When: a regular HTTP/2 request is forwarded through TLS+.
    let stream = TcpStream::connect(&proxy_addr)
        .await
        .expect("connect to TLS+ proxy");
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .expect("perform HTTP/2 handshake with TLS+");
    let connection_task = tokio::spawn(async move {
        connection.await.expect("drive TLS+ HTTP/2 connection");
    });
    let request = Request::builder()
        .version(Version::HTTP_2)
        .uri(format!("http://{proxy_addr}/resource"))
        .header(
            "x-tlsplus-target",
            format!("http://{upstream_addr}/resource"),
        )
        .header("x-tlsplus-profile", "pass-through")
        .header("x-tlsplus-timeout", "5")
        .header("x-tlsplus-http-version", "HTTP/2")
        .body(Empty::<Bytes>::new())
        .expect("build downstream HTTP/2 request");
    let response = tokio::time::timeout(Duration::from_secs(5), sender.send_request(request))
        .await
        .expect("TLS+ HTTP/2 response timed out")
        .expect("TLS+ HTTP/2 request failed");
    let response_version = response.version();
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("collect HTTP/2 response")
        .to_bytes();

    // Then: both legs and the response remain HTTP/2.
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response_version, Version::HTTP_2);
    assert_eq!(
        observed_rx.await.expect("observe upstream version"),
        Version::HTTP_2
    );
    assert_eq!(body, Bytes::from_static(b"h2-body"));

    drop(sender);
    assert!(!stop_local_server().running);
    tokio::time::timeout(Duration::from_secs(2), connection_task)
        .await
        .expect("downstream HTTP/2 connection did not close")
        .expect("downstream connection task failed");
    upstream_task.abort();
    let _ = upstream_task.await;
}

#[tokio::test]
async fn rejects_http2_marker_on_an_http1_connection() {
    let _guard = TEST_MUTEX.lock().await;

    // Given: a running TLS+ proxy and an HTTP/1.1 client claiming the request originated as HTTP/2.
    let proxy_addr = support::ephemeral_listen_addr();
    let _ = stop_local_server();
    let started = start_local_server(proxy_addr.clone());
    assert!(
        started.running,
        "failed to start TLS+ proxy: {}",
        started.message
    );
    let mut stream = TcpStream::connect(&proxy_addr)
        .await
        .expect("connect HTTP/1.1 client to TLS+");

    // When: the downgraded request is submitted.
    stream
        .write_all(
            b"GET /resource HTTP/1.1\r\n\
              Host: 127.0.0.1\r\n\
              X-Tlsplus-Target: http://127.0.0.1:1/resource\r\n\
              X-Tlsplus-Profile: pass-through\r\n\
              X-Tlsplus-Http-Version: HTTP/2\r\n\
              Connection: close\r\n\r\n",
        )
        .await
        .expect("write downgraded request");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("downgrade rejection timed out")
        .expect("read downgrade rejection");

    // Then: TLS+ rejects the downgrade instead of silently forwarding over HTTP/1.1.
    let response = String::from_utf8(response).expect("HTTP response is UTF-8");
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "unexpected response: {response}"
    );
    assert!(response.contains("HTTP version changed"));
    assert!(!stop_local_server().running);
}
