mod support;

use std::time::Duration;

use tlsplus_core::{start_local_server, stop_local_server};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_an_unrepresentable_websocket_timeout_without_stopping_the_proxy() {
    // Given: a running TLS+ proxy and an otherwise valid WebSocket upgrade request.
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
        .expect("connect to TLS+ proxy");
    let request = "GET /echo HTTP/1.1\r\n\
                   Host: 127.0.0.1:9\r\n\
                   X-Tlsplus-Target: ws://127.0.0.1:9/echo\r\n\
                   X-Tlsplus-Profile: pass-through\r\n\
                   X-Tlsplus-Timeout: 18446744073709551615\r\n\
                   Connection: Upgrade\r\n\
                   Upgrade: websocket\r\n\
                   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                   Sec-WebSocket-Version: 13\r\n\r\n";

    // When: the request attempts to create an Instant beyond the platform range.
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write oversized-timeout request");
    let mut response = vec![0; 4096];
    let count = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut response))
        .await
        .expect("oversized-timeout response timed out")
        .expect("read oversized-timeout response");
    let response = String::from_utf8_lossy(&response[..count]);

    // Then: TLS+ rejects the timeout and remains available for a subsequent request.
    assert!(
        response.starts_with("HTTP/1.1 400"),
        "unexpected response: {response}"
    );

    let mut health = TcpStream::connect(&proxy_addr)
        .await
        .expect("proxy stopped after invalid timeout");
    health
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write health request");
    let mut health_response = Vec::new();
    health
        .read_to_end(&mut health_response)
        .await
        .expect("read health response");
    assert!(String::from_utf8_lossy(&health_response).starts_with("HTTP/1.1 400"));
    assert!(!stop_local_server().running);
}
