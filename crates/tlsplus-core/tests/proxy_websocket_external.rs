mod support;

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tlsplus_core::{start_local_server, stop_local_server};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    client_async,
    tungstenite::{
        client::IntoClientRequest,
        http::{HeaderValue, header::HOST},
        protocol::Message,
    },
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "external network — connects to the websocket.org secure echo service"]
async fn wss_echo_uses_the_selected_tls_profile() {
    // Given: the TLS+ proxy configured to reach a public WSS echo service with a browser profile.
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
    let mut request = format!("ws://{proxy_addr}/raw")
        .into_client_request()
        .expect("build WebSocket request");
    request.headers_mut().insert(
        "x-tlsplus-target",
        HeaderValue::from_static("wss://echo.websocket.org"),
    );
    request
        .headers_mut()
        .insert("x-tlsplus-profile", HeaderValue::from_static("chrome_149"));
    request
        .headers_mut()
        .insert("x-tlsplus-timeout", HeaderValue::from_static("15"));
    request
        .headers_mut()
        .insert(HOST, HeaderValue::from_static("echo.websocket.org"));

    // When: text and binary frames traverse the secure profiled connection.
    let (mut websocket, response) =
        tokio::time::timeout(Duration::from_secs(20), client_async(request, stream))
            .await
            .expect("WSS handshake through TLS+ timed out")
            .expect("WSS handshake through TLS+ failed");
    assert_eq!(response.status(), 101);

    let greeting = tokio::time::timeout(Duration::from_secs(10), websocket.next())
        .await
        .expect("server greeting timed out")
        .expect("WebSocket closed before server greeting")
        .expect("read server greeting");
    assert!(
        greeting
            .to_text()
            .is_ok_and(|text| text.starts_with("Request served by ")),
        "unexpected server greeting: {greeting:?}"
    );

    websocket
        .send(Message::Text("tlsplus-wss-text".into()))
        .await
        .expect("send text frame");
    let text = tokio::time::timeout(Duration::from_secs(10), websocket.next())
        .await
        .expect("text echo timed out")
        .expect("WebSocket closed before text echo")
        .expect("read text echo");

    websocket
        .send(Message::Binary(vec![9, 8, 7, 0, 255].into()))
        .await
        .expect("send binary frame");
    let binary = tokio::time::timeout(Duration::from_secs(10), websocket.next())
        .await
        .expect("binary echo timed out")
        .expect("WebSocket closed before binary echo")
        .expect("read binary echo");

    // Then: the public WSS service echoes both payloads unchanged through TLS+.
    assert_eq!(text, Message::Text("tlsplus-wss-text".into()));
    assert_eq!(binary, Message::Binary(vec![9, 8, 7, 0, 255].into()));

    websocket.close(None).await.expect("close WebSocket");
    assert!(!stop_local_server().running);
}
