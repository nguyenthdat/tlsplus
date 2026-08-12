//! Proxy streaming integration test.
//!
//! Verifies that the local hyper proxy server streams request and response
//! bodies without buffering — the fix for the blank-page bug on YouTube and
//! heavy SPAs where large/chunked responses previously hung or timed out.
//!
//! # Run:
//! ```bash
//! # All tests (including ignored external-network tests):
//! cargo test --test proxy_streaming -- --ignored --nocapture
//! # CI-safe (local-only):
//! cargo test --test proxy_streaming
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

use tlsplus_core::{start_local_server, stop_local_server};

/// Serialize proxy tests to avoid port conflicts on fixed port 43119.
static TEST_MUTEX: Mutex<()> = Mutex::new(());

/// Acquire the test mutex, recovering from poison if a previous test panicked.
fn acquire_test_lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_MUTEX
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

/// Test proxy port — fixed to avoid ephemeral port tracking issues.
/// The `start_local_server` stores the literal string, not the bound port.
const PROXY_PORT: &str = "127.0.0.1:43119";

/// Connect to the proxy server with retries. The server binds asynchronously
/// so the port may not be immediately available.
fn connect_with_retry(addr: &str, max_attempts: u32) -> TcpStream {
    for attempt in 1..=max_attempts {
        match TcpStream::connect(addr) {
            Ok(s) => return s,
            Err(e) => {
                if attempt == max_attempts {
                    panic!(
                        "failed to connect to proxy at {addr} after {max_attempts} attempts: {e}"
                    );
                }
                eprintln!(
                    "  connect attempt {attempt}/{max_attempts} to {addr}: {e} (retrying in 200ms)"
                );
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
    unreachable!()
}

/// Fetch a URL through the local proxy server via raw TCP.
///
/// Opens a TCP connection to the proxy, sends an HTTP/1.1 request with
/// `X-Tlsplus-Target` header, and reads the full response. This exercises
/// the streaming path where `Incoming` bodies flow directly through the
/// hyper server to the hyper client — zero buffering on both request
/// and response sides.
fn fetch_via_proxy(target_url: &str, proxy_addr: &str) -> (u16, Vec<u8>, Vec<String>) {
    let mut stream = connect_with_retry(proxy_addr, 10);
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("set read timeout");

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: example.com\r\n\
         X-Tlsplus-Target: {target_url}\r\n\
         X-Tlsplus-Profile: pass-through\r\n\
         X-Tlsplus-Timeout: 15\r\n\
         User-Agent: tlsplus-streaming-test/1.0\r\n\
         Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
         Accept-Encoding: gzip, deflate, br\r\n\
         Accept-Language: en-US,en;q=0.9\r\n\
         Connection: close\r\n\
         \r\n"
    );

    stream.write_all(request.as_bytes()).expect("write request");
    stream.flush().expect("flush");

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .expect("read response from proxy");

    // Parse HTTP response
    let response_str = String::from_utf8_lossy(&raw);
    let mut lines = response_str.lines();

    // Status line: "HTTP/1.1 200 OK"
    let status_line = lines.next().expect("no status line");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("invalid status line");

    // Headers
    let mut headers = Vec::new();
    for line in &mut lines {
        if line.is_empty() {
            break;
        }
        headers.push(line.to_owned());
    }

    // Body — everything after the blank line
    let header_end = response_str.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let body = raw[header_end..].to_vec();

    (status_code, body, headers)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
#[ignore = "external network — hits google.com via local proxy; use `cargo test --test proxy_streaming -- --ignored --nocapture`"]
fn google_via_local_proxy_streams_full_body() {
    let _guard = acquire_test_lock();
    // Ensure the proxy is stopped first (in case a previous test left it running)
    let _ = stop_local_server();

    let started = start_local_server(PROXY_PORT.to_owned());
    assert!(
        started.running,
        "Failed to start proxy: {}",
        started.message
    );

    println!("Proxy listening on {PROXY_PORT}");

    // Give the server a moment to start accepting
    std::thread::sleep(Duration::from_millis(100));

    let (status, body, _headers) = fetch_via_proxy("https://www.google.com/", PROXY_PORT);

    println!("Status: {status}, Body length: {} bytes", body.len());

    // Verify success
    assert!(
        (200..400).contains(&status),
        "Expected 2xx/3xx, got {status}"
    );

    // The body should be substantial — Google's homepage is large
    assert!(
        body.len() > 10_000,
        "Body too small ({} bytes) — likely truncated. Blank-page bug!",
        body.len()
    );

    // For compressed responses, we can't check HTML tags directly.
    // But we CAN verify the body is non-trivial and not empty.
    assert!(!body.is_empty(), "Body is empty — streaming failed");

    // Also verify we got headers
    assert!(!_headers.is_empty(), "No response headers received");

    // Stop the proxy
    let stopped = stop_local_server();
    assert!(!stopped.running);
}

#[test]
fn missing_target_header_returns_error() {
    let _guard = acquire_test_lock();
    let _ = stop_local_server();
    let started = start_local_server(PROXY_PORT.to_owned());
    assert!(started.running);

    let mut stream = connect_with_retry(PROXY_PORT, 10);
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set timeout");

    // Send request WITHOUT X-Tlsplus-Target
    let request = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    stream.write_all(request.as_bytes()).expect("write");
    stream.flush().expect("flush");

    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("read");

    let response_str = String::from_utf8_lossy(&response);
    println!("Response (no target):\n{response_str}");

    assert!(
        response_str.contains("400") || response_str.contains("Bad Request"),
        "Expected 400 Bad Request, got: {:.200}",
        response_str
    );

    stop_local_server();
}

#[test]
#[ignore = "external network — hits example.com via local proxy; use `cargo test --test proxy_streaming -- --ignored --nocapture`"]
fn example_via_local_proxy_returns_complete_page() {
    let _guard = acquire_test_lock();
    let _ = stop_local_server();
    let started = start_local_server(PROXY_PORT.to_owned());
    assert!(started.running);

    // example.com returns a small page. It may or may not be compressed
    // depending on the server config. We just verify it streams through
    // successfully without truncation.
    let (status, body, _headers) = fetch_via_proxy("https://example.com/", PROXY_PORT);

    println!("Status: {status}, Body length: {} bytes", body.len());

    assert_eq!(status, 200);
    // Body must be non-trivial — at least 200 bytes
    assert!(
        body.len() > 200,
        "Body too small ({} bytes) — likely truncated or empty",
        body.len()
    );

    // Try to decode as UTF-8 to check completeness
    let body_str = String::from_utf8_lossy(&body);
    if body_str.contains("<html") || body_str.contains("<HTML") {
        assert!(
            body_str.contains("</html>") || body_str.contains("</HTML>"),
            "Body appears truncated — missing closing </html> tag.\n\
             Body starts: {:.200}...\nBody ends: ...{:.200}",
            &body_str[..body_str.len().min(200)],
            &body_str[body_str.len().saturating_sub(200)..]
        );
    } else {
        // Compressed response — just verify it's non-empty and non-trivial
        println!("  (response appears compressed; HTML tag check skipped)");
    }

    stop_local_server();
}
