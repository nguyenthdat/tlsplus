mod support;

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tlsplus_core::{start_local_server, stop_local_server};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tokio_tungstenite::{
    accept_async, client_async,
    tungstenite::{
        client::IntoClientRequest,
        http::{HeaderValue, header::HOST},
        protocol::Message,
    },
};

static TEST_MUTEX: Mutex<()> = Mutex::const_new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxies_websocket_frames_in_both_directions() {
    let _guard = TEST_MUTEX.lock().await;

    // Given: a real local WebSocket echo server and the TLS+ proxy.
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream WebSocket server");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.expect("accept upstream client");
        let mut websocket = accept_async(stream)
            .await
            .expect("upgrade upstream connection");

        while let Some(message) = websocket.next().await {
            let message = message.expect("read upstream WebSocket frame");
            if message.is_close() {
                break;
            }
            websocket
                .send(message)
                .await
                .expect("echo upstream WebSocket frame");
        }
    });

    let proxy_addr = support::ephemeral_listen_addr();
    let _ = stop_local_server();
    let started = start_local_server(proxy_addr.clone());
    assert!(
        started.running,
        "failed to start TLS+ proxy: {}",
        started.message
    );

    let stream = TcpStream::connect(&proxy_addr)
        .await
        .expect("connect to TLS+ proxy");
    let mut request = format!("ws://{proxy_addr}/echo")
        .into_client_request()
        .expect("build WebSocket request");
    request.headers_mut().insert(
        "x-tlsplus-target",
        HeaderValue::from_str(&format!("ws://{upstream_addr}/echo")).expect("target header value"),
    );
    request.headers_mut().insert(
        "x-tlsplus-profile",
        HeaderValue::from_static("pass-through"),
    );
    request
        .headers_mut()
        .insert("x-tlsplus-timeout", HeaderValue::from_static("5"));
    request.headers_mut().insert(
        HOST,
        HeaderValue::from_str(&upstream_addr.to_string()).expect("host header value"),
    );

    // When: a WebSocket client upgrades through TLS+ and exchanges text and binary frames.
    let (mut websocket, response) =
        tokio::time::timeout(Duration::from_secs(5), client_async(request, stream))
            .await
            .expect("TLS+ WebSocket handshake timed out")
            .expect("TLS+ WebSocket handshake failed");
    assert_eq!(response.status(), 101);

    websocket
        .send(Message::Text("through-tlsplus".into()))
        .await
        .expect("send text frame");
    let text = tokio::time::timeout(Duration::from_secs(5), websocket.next())
        .await
        .expect("text echo timed out")
        .expect("WebSocket closed before text echo")
        .expect("read text echo");

    websocket
        .send(Message::Binary(vec![0, 1, 2, 3, 255].into()))
        .await
        .expect("send binary frame");
    let binary = tokio::time::timeout(Duration::from_secs(5), websocket.next())
        .await
        .expect("binary echo timed out")
        .expect("WebSocket closed before binary echo")
        .expect("read binary echo");

    // Then: both frame types survive the TLS+ duplex tunnel unchanged.
    assert_eq!(text, Message::Text("through-tlsplus".into()));
    assert_eq!(binary, Message::Binary(vec![0, 1, 2, 3, 255].into()));

    websocket.close(None).await.expect("close WebSocket");
    tokio::time::timeout(Duration::from_secs(5), upstream_task)
        .await
        .expect("upstream server shutdown timed out")
        .expect("upstream server task failed");
    let stopped = stop_local_server();
    assert!(!stopped.running);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forwards_an_upstream_websocket_rejection_as_http() {
    let _guard = TEST_MUTEX.lock().await;

    // Given: an upstream endpoint that rejects the WebSocket handshake with HTTP 403.
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind rejecting upstream");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.expect("accept upstream client");
        let mut request = vec![0; 4096];
        let count = stream
            .read(&mut request)
            .await
            .expect("read upstream request");
        let request = String::from_utf8_lossy(&request[..count]);
        assert!(request.to_ascii_lowercase().contains("upgrade: websocket"));
        stream
            .write_all(
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied",
            )
            .await
            .expect("write rejection");
    });

    let proxy_addr = support::ephemeral_listen_addr();
    let _ = stop_local_server();
    let started = start_local_server(proxy_addr.clone());
    assert!(
        started.running,
        "failed to start TLS+ proxy: {}",
        started.message
    );

    // When: a WebSocket opening request is sent through TLS+.
    let mut stream = TcpStream::connect(&proxy_addr)
        .await
        .expect("connect to TLS+ proxy");
    let request = format!(
        "GET /echo HTTP/1.1\r\n\
         Host: {upstream_addr}\r\n\
         X-Tlsplus-Target: ws://{upstream_addr}/echo\r\n\
         X-Tlsplus-Profile: pass-through\r\n\
         X-Tlsplus-Timeout: 5\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write WebSocket request");
    let mut response = vec![0; 4096];
    let count = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut response))
        .await
        .expect("HTTP rejection timed out")
        .expect("read HTTP rejection");
    let response = String::from_utf8_lossy(&response[..count]);

    // Then: the original HTTP rejection is forwarded instead of a false 101 tunnel.
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("denied"),
        "missing rejection body: {response}"
    );

    upstream_task.await.expect("rejecting upstream task failed");
    assert!(!stop_local_server().running);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stops_with_an_active_websocket_and_rebinds_the_listener() {
    let _guard = TEST_MUTEX.lock().await;

    // Given: an active WebSocket tunnel through TLS+.
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream WebSocket server");
    let upstream_addr = upstream.local_addr().expect("upstream address");
    let upstream_task = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.expect("accept upstream client");
        let mut websocket = accept_async(stream)
            .await
            .expect("upgrade upstream connection");
        while let Some(message) = websocket.next().await {
            if message.is_err() || message.is_ok_and(|message| message.is_close()) {
                break;
            }
        }
    });

    let proxy_addr = support::ephemeral_listen_addr();
    let _ = stop_local_server();
    let started = start_local_server(proxy_addr.clone());
    assert!(
        started.running,
        "failed to start TLS+ proxy: {}",
        started.message
    );
    let stream = TcpStream::connect(&proxy_addr)
        .await
        .expect("connect to TLS+ proxy");
    let mut request = format!("ws://{proxy_addr}/echo")
        .into_client_request()
        .expect("build WebSocket request");
    request.headers_mut().insert(
        "x-tlsplus-target",
        HeaderValue::from_str(&format!("ws://{upstream_addr}/echo")).expect("target header value"),
    );
    request.headers_mut().insert(
        "x-tlsplus-profile",
        HeaderValue::from_static("pass-through"),
    );
    request.headers_mut().insert(
        HOST,
        HeaderValue::from_str(&upstream_addr.to_string()).expect("host header value"),
    );
    let (mut websocket, _) = client_async(request, stream)
        .await
        .expect("TLS+ WebSocket handshake failed");

    // When: the embedded proxy stops while the tunnel is open.
    let started_at = tokio::time::Instant::now();
    let stopped = tokio::task::spawn_blocking(stop_local_server)
        .await
        .expect("stop task failed");

    // Then: stop is bounded, the socket closes, and the same address can be rebound.
    assert!(!stopped.running);
    assert!(started_at.elapsed() < Duration::from_secs(4));
    tokio::time::timeout(Duration::from_secs(2), websocket.next())
        .await
        .expect("WebSocket remained open after proxy stop");

    let restarted = start_local_server(proxy_addr);
    assert!(
        restarted.running,
        "proxy listener did not rebind: {}",
        restarted.message
    );
    assert!(!stop_local_server().running);
    tokio::time::timeout(Duration::from_secs(2), upstream_task)
        .await
        .expect("upstream did not observe tunnel shutdown")
        .expect("upstream task failed");
}
