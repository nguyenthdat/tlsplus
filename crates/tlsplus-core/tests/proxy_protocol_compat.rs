mod support;

use std::{convert::Infallible, sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{Method, Request, Response, StatusCode, Version, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tlsplus_core::{start_local_server, stop_local_server};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, oneshot},
};

static TEST_MUTEX: Mutex<()> = Mutex::const_new(());

#[tokio::test]
async fn accepts_legacy_http10_without_an_http2_guard() {
    let _guard = TEST_MUTEX.lock().await;

    // Given: an HTTP/1 upstream that records the request version.
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind HTTP/1 upstream");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (observed_tx, observed_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.expect("accept upstream client");
        let observed_tx = Arc::new(std::sync::Mutex::new(Some(observed_tx)));
        hyper::server::conn::http1::Builder::new()
            .serve_connection(
                TokioIo::new(stream),
                service_fn(move |request: Request<Incoming>| {
                    if let Some(sender) = observed_tx.lock().expect("lock version observer").take()
                    {
                        let _ = sender.send(request.version());
                    }
                    async move {
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                            b"http10-body",
                        ))))
                    }
                }),
            )
            .await
            .expect("serve HTTP/1 upstream connection");
    });

    let proxy_addr = support::ephemeral_listen_addr();
    let _ = stop_local_server();
    let started = start_local_server(proxy_addr.clone());
    assert!(
        started.running,
        "failed to start TLS+ proxy: {}",
        started.message
    );

    // When: an HTTP/1.0 request is sent through TLS+ without an HTTP/2 guard.
    let mut stream = TcpStream::connect(&proxy_addr)
        .await
        .expect("connect HTTP/1.0 client to TLS+");
    let request = format!(
        "GET /legacy HTTP/1.0\r\n\
         Host: {upstream_addr}\r\n\
         X-Tlsplus-Target: http://{upstream_addr}/legacy\r\n\
         X-Tlsplus-Profile: pass-through\r\n\
         Connection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write HTTP/1.0 request");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("HTTP/1.0 response timed out")
        .expect("read HTTP/1.0 response");

    // Then: the legacy request remains accepted with the pre-existing H1 transport behavior.
    let response = String::from_utf8(response).expect("HTTP response is UTF-8");
    assert!(
        response.starts_with("HTTP/1.0 200"),
        "unexpected response: {response}"
    );
    assert!(response.contains("http10-body"));
    assert_eq!(
        observed_rx.await.expect("observe upstream version"),
        Version::HTTP_11
    );

    assert!(!stop_local_server().running);
    upstream_task.abort();
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forwards_standard_http2_connect_without_websocket_protocol() {
    let _guard = TEST_MUTEX.lock().await;

    // Given: an HTTP/2 endpoint that accepts a standard CONNECT request.
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind HTTP/2 upstream");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (observed_tx, observed_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.expect("accept upstream client");
        let observed_tx = Arc::new(std::sync::Mutex::new(Some(observed_tx)));
        let service = service_fn(move |request: Request<Incoming>| {
            if let Some(sender) = observed_tx.lock().expect("lock CONNECT observer").take() {
                let observation = (
                    request.method().clone(),
                    request.version(),
                    request.extensions().get::<hyper::ext::Protocol>().is_some(),
                );
                let _ = sender.send(observation);
            }
            async move {
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Full::new(Bytes::from_static(b"connect-denied")))
                        .expect("build CONNECT response"),
                )
            }
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

    // When: a standard HTTP/2 CONNECT without :protocol is sent through TLS+.
    let stream = TcpStream::connect(&proxy_addr)
        .await
        .expect("connect HTTP/2 client to TLS+");
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .expect("perform HTTP/2 handshake with TLS+");
    let connection_task = tokio::spawn(async move {
        connection.await.expect("drive TLS+ HTTP/2 connection");
    });
    let request = Request::builder()
        .method(Method::CONNECT)
        .version(Version::HTTP_2)
        .uri(format!("http://{proxy_addr}/tunnel"))
        .header("x-tlsplus-target", format!("http://{upstream_addr}/tunnel"))
        .header("x-tlsplus-profile", "pass-through")
        .header("x-tlsplus-timeout", "5")
        .header("x-tlsplus-http-version", "HTTP/2")
        .body(Empty::<Bytes>::new())
        .expect("build standard CONNECT request");
    let response = sender
        .send_request(request)
        .await
        .expect("send standard CONNECT through TLS+");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("collect CONNECT response")
        .to_bytes();

    // Then: the request reaches upstream unchanged and is not treated as WebSocket traffic.
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, Bytes::from_static(b"connect-denied"));
    let (method, version, has_protocol) = observed_rx.await.expect("observe CONNECT request");
    assert_eq!(method, Method::CONNECT);
    assert_eq!(version, Version::HTTP_2);
    assert!(!has_protocol);

    drop(sender);
    assert!(!stop_local_server().running);
    tokio::time::timeout(Duration::from_secs(2), connection_task)
        .await
        .expect("downstream HTTP/2 connection did not close")
        .expect("downstream connection task failed");
    upstream_task.abort();
    let _ = upstream_task.await;
}
