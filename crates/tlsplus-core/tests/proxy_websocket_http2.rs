mod support;

use std::{convert::Infallible, sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::Empty;
use hyper::{
    Method, Request, Response, StatusCode, Version, body::Incoming, ext::Protocol,
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tlsplus_core::{start_local_server, stop_local_server};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, oneshot},
};

static TEST_MUTEX: Mutex<()> = Mutex::const_new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preserves_extended_connect_across_both_proxy_legs() {
    let _guard = TEST_MUTEX.lock().await;

    // Given: an HTTP/2 endpoint that accepts RFC 8441 Extended CONNECT.
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind HTTP/2 upstream");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (observed_tx, observed_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.expect("accept upstream client");
        let observed_tx = Arc::new(Mutex::new(Some(observed_tx)));
        let service = service_fn(move |request: Request<Incoming>| {
            let observed_tx = Arc::clone(&observed_tx);
            async move {
                let protocol = request
                    .extensions()
                    .get::<Protocol>()
                    .map(|protocol| protocol.as_str().to_owned());
                if let Some(sender) = observed_tx.lock().await.take() {
                    let observation = (
                        request.method().clone(),
                        request.version(),
                        protocol,
                        request.uri().scheme_str().map(str::to_owned),
                        request.uri().authority().map(ToString::to_string),
                        request.uri().path().to_owned(),
                        request.headers().contains_key(hyper::header::CONNECTION),
                        request.headers().contains_key(hyper::header::UPGRADE),
                    );
                    let _ = sender.send(observation);
                }

                tokio::spawn(async move {
                    let mut upgraded = TokioIo::new(
                        hyper::upgrade::on(request)
                            .await
                            .expect("upgrade upstream CONNECT stream"),
                    );
                    let mut request_bytes = [0; 7];
                    upgraded
                        .read_exact(&mut request_bytes)
                        .await
                        .expect("read upstream tunnel bytes");
                    assert_eq!(&request_bytes, b"h2-ping");
                    upgraded
                        .write_all(b"h2-pong")
                        .await
                        .expect("write upstream tunnel bytes");
                });

                Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
            }
        });
        let mut server = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
        server.http2().enable_connect_protocol();
        server
            .serve_connection_with_upgrades(TokioIo::new(stream), service)
            .await
            .expect("serve upstream HTTP/2 connection");
    });

    let proxy_addr = support::ephemeral_listen_addr();
    let _ = stop_local_server();
    let started = start_local_server(proxy_addr.clone());
    assert!(
        started.running,
        "failed to start TLS+ proxy: {}",
        started.message
    );

    // When: an HTTP/2 Extended CONNECT stream is sent through TLS+.
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

    let mut request = Request::builder()
        .method(Method::CONNECT)
        .version(Version::HTTP_2)
        .uri(format!("http://{proxy_addr}/echo"))
        .header("x-tlsplus-target", format!("ws://{upstream_addr}/echo"))
        .header("x-tlsplus-profile", "pass-through")
        .header("x-tlsplus-timeout", "5")
        .header("x-tlsplus-http-version", "HTTP/2")
        .header("sec-websocket-version", "13")
        .body(Empty::<Bytes>::new())
        .expect("build downstream Extended CONNECT request");
    request
        .extensions_mut()
        .insert(Protocol::from_static("websocket"));

    let response = tokio::time::timeout(Duration::from_secs(5), sender.send_request(request))
        .await
        .expect("TLS+ Extended CONNECT response timed out")
        .expect("TLS+ Extended CONNECT request failed");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_2);
    let mut tunnel = TokioIo::new(
        hyper::upgrade::on(response)
            .await
            .expect("upgrade downstream CONNECT stream"),
    );
    tunnel
        .write_all(b"h2-ping")
        .await
        .expect("write downstream tunnel bytes");
    let mut reply = [0; 7];
    tunnel
        .read_exact(&mut reply)
        .await
        .expect("read downstream tunnel bytes");

    // Then: both legs are HTTP/2 Extended CONNECT and bytes remain opaque.
    assert_eq!(&reply, b"h2-pong");
    let (method, version, protocol, scheme, authority, path, connection, upgrade) =
        observed_rx.await.expect("observe upstream request");
    assert_eq!(method, Method::CONNECT);
    assert_eq!(version, Version::HTTP_2);
    assert_eq!(protocol.as_deref(), Some("websocket"));
    assert_eq!(scheme.as_deref(), Some("http"));
    assert_eq!(
        authority.as_deref(),
        Some(upstream_addr.to_string().as_str())
    );
    assert_eq!(path, "/echo");
    assert!(!connection);
    assert!(!upgrade);

    drop(tunnel);
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
async fn rejects_extended_connect_when_upstream_does_not_enable_it() {
    let _guard = TEST_MUTEX.lock().await;

    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind HTTP/2 upstream without Extended CONNECT");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let (observed_tx, mut observed_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.expect("accept upstream client");
        let observed_tx = Arc::new(Mutex::new(Some(observed_tx)));
        let service = service_fn(move |_request: Request<Incoming>| {
            let observed_tx = Arc::clone(&observed_tx);
            async move {
                if let Some(sender) = observed_tx.lock().await.take() {
                    let _ = sender.send(());
                }
                Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
            }
        });
        let server = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
        let _ = server
            .serve_connection_with_upgrades(TokioIo::new(stream), service)
            .await;
    });

    let _ = stop_local_server();
    let started = start_local_server("127.0.0.1:0".to_owned());
    assert!(
        started.running,
        "failed to start TLS+ proxy: {}",
        started.message
    );
    let proxy_addr = started.listen_addr.expect("proxy listen address");

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

    let mut request = Request::builder()
        .method(Method::CONNECT)
        .version(Version::HTTP_2)
        .uri(format!("http://{proxy_addr}/echo"))
        .header("x-tlsplus-target", format!("ws://{upstream_addr}/echo"))
        .header("x-tlsplus-profile", "pass-through")
        .header("x-tlsplus-timeout", "2")
        .header("x-tlsplus-http-version", "HTTP/2")
        .body(Empty::<Bytes>::new())
        .expect("build downstream Extended CONNECT request");
    request
        .extensions_mut()
        .insert(Protocol::from_static("websocket"));

    let response = tokio::time::timeout(Duration::from_secs(5), sender.send_request(request))
        .await
        .expect("TLS+ response timed out")
        .expect("TLS+ request failed");

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(
        observed_rx.try_recv().is_err(),
        "upstream observed an unnegotiated Extended CONNECT"
    );

    drop(sender);
    assert!(!stop_local_server().running);
    tokio::time::timeout(Duration::from_secs(2), connection_task)
        .await
        .expect("downstream HTTP/2 connection did not close")
        .expect("downstream connection task failed");
    upstream_task.abort();
    let _ = upstream_task.await;
}
