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
async fn preserves_http1_across_both_proxy_legs() {
    let _guard = TEST_MUTEX.lock().await;

    // Given: an HTTP/1.1-only upstream that records the received protocol version.
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind HTTP/1.1 upstream");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (observed_tx, observed_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.expect("accept upstream client");
        let observed_tx = Arc::new(std::sync::Mutex::new(Some(observed_tx)));
        let service = service_fn(move |request: Request<Incoming>| {
            if let Some(sender) = observed_tx.lock().expect("lock protocol observer").take() {
                let _ = sender.send(request.version());
            }
            async move { Ok::<_, Infallible>(Response::new(Full::new(Bytes::new()))) }
        });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
            .expect("serve HTTP/1.1 upstream connection");
    });

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

    // When: a regular HTTP/1.1 request is forwarded through TLS+.
    let request = format!(
        "GET /resource HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n\
         X-Tlsplus-Target: http://{upstream_addr}/resource\r\n\
         X-Tlsplus-Profile: pass-through\r\n\
         Connection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write HTTP/1.1 request");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("proxy response timed out")
        .expect("read proxy response");

    // Then: both proxy legs remain HTTP/1.1.
    let response = String::from_utf8(response).expect("HTTP response is UTF-8");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected response: {response}"
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), observed_rx)
            .await
            .expect("upstream protocol observation timed out")
            .expect("observe upstream version"),
        Version::HTTP_11
    );
    assert!(!stop_local_server().running);
    upstream_task.abort();
    let _ = upstream_task.await;
}

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preserves_http2_origin_across_an_http1_proxy_hop() {
    let _guard = TEST_MUTEX.lock().await;

    // Given: an HTTP/2-only upstream and a local proxy hop serialized as HTTP/1.1.
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
            async move { Ok::<_, Infallible>(Response::new(Full::new(Bytes::new()))) }
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
    let mut stream = TcpStream::connect(&proxy_addr)
        .await
        .expect("connect HTTP/1.1 client to TLS+");

    // When: an HTTP/2-origin request crosses the HTTP/1.1 loopback hop.
    let request = format!(
        "GET /resource HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n\
         X-Tlsplus-Target: http://{upstream_addr}/resource\r\n\
         X-Tlsplus-Profile: pass-through\r\n\
         X-Tlsplus-Http-Version: HTTP/2\r\n\
         Connection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write HTTP/2-origin request");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("proxy response timed out")
        .expect("read proxy response");

    // Then: the local hop succeeds while the original HTTP/2 version reaches upstream.
    let response = String::from_utf8(response).expect("HTTP response is UTF-8");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected response: {response}"
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), observed_rx)
            .await
            .expect("upstream protocol observation timed out")
            .expect("observe upstream version"),
        Version::HTTP_2
    );
    assert!(!stop_local_server().running);
    upstream_task.abort();
    let _ = upstream_task.await;
}

#[tokio::test]
async fn rejects_http2_connect_marker_on_an_http1_proxy_hop() {
    let _guard = TEST_MUTEX.lock().await;

    // Given: a running TLS+ proxy reached through an HTTP/1.1 loopback connection.
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

    // When: an HTTP/2 CONNECT request is claimed across that incompatible hop.
    stream
        .write_all(
            b"CONNECT example.com:443 HTTP/1.1\r\n\
              Host: example.com:443\r\n\
              X-Tlsplus-Target: https://example.com/\r\n\
              X-Tlsplus-Profile: pass-through\r\n\
              X-Tlsplus-Http-Version: HTTP/2\r\n\
              Connection: close\r\n\r\n",
        )
        .await
        .expect("write incompatible CONNECT request");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("CONNECT rejection timed out")
        .expect("read CONNECT rejection");

    // Then: TLS+ keeps tunnel semantics strict instead of reconstructing HTTP/2 CONNECT.
    let response = String::from_utf8(response).expect("HTTP response is UTF-8");
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "unexpected response: {response}"
    );
    assert!(response.contains("HTTP version changed"));
    assert!(!stop_local_server().running);
}
