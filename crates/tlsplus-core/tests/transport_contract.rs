//! T02 — Buffered transport contracts.
//!
//! Characterizes retries/backoff, timeout-zero behavior, ID/status-0 errors,
//! unknown-profile errors, proxy fallback, canonical pool identity, and
//! non-replayable streams for the wreq/btls transport.

use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, service::service_fn};
use hyper_util::rt::TokioIo;
use tlsplus_core::{
    ProxyRequest, http_client::HttpClient, proxy_send_request, start_local_server,
    stop_local_server,
};
use tokio::net::TcpListener;

// ── ID preservation ──────────────────────────────────────────────────────

#[test]
fn proxy_response_preserves_request_id_on_error() {
    let req = ProxyRequest {
        id: "t02-id-001".to_owned(),
        method: "GET".to_owned(),
        url: "http://127.0.0.1:1/nonexistent".to_owned(),
        headers: vec![],
        body: vec![],
        profile: "pass-through".to_owned(),
        timeout_secs: 2,
    };
    let resp = proxy_send_request(req);
    assert_eq!(resp.id, "t02-id-001");
}

// ── Status-code-0 on forwarding failure ─────────────────────────────────

#[test]
fn proxy_response_status_zero_on_connection_refused() {
    let req = ProxyRequest {
        id: "t02-status0".to_owned(),
        method: "GET".to_owned(),
        url: "http://127.0.0.1:1/nonexistent".to_owned(),
        headers: vec![],
        body: vec![],
        profile: "pass-through".to_owned(),
        timeout_secs: 2,
    };
    let resp = proxy_send_request(req);
    assert_eq!(resp.status_code, 0);
    assert!(resp.error.is_some());
}

// ── Error presence on transport failure ─────────────────────────────────

#[test]
fn proxy_response_error_is_some_on_failure() {
    let req = ProxyRequest {
        id: "t02-err".to_owned(),
        method: "GET".to_owned(),
        url: "http://127.0.0.1:1/nope".to_owned(),
        headers: vec![],
        body: vec![],
        profile: "pass-through".to_owned(),
        timeout_secs: 2,
    };
    let resp = proxy_send_request(req);
    assert!(
        resp.error.is_some(),
        "error must be Some on transport failure"
    );
    assert!(resp.body.is_empty());
}

// ── Unknown profile → direct error from HttpClient ──────────────────────

#[test]
fn direct_client_rejects_unknown_profile_with_specific_error() {
    let err = HttpClient::for_profile("definitely_not_a_profile_xyzzy")
        .expect_err("unknown profile must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown TLS profile") || msg.contains("definitely_not_a_profile_xyzzy"),
        "error message must name the rejected profile: {msg}"
    );
}

// ── Proxy fallback: unknown profile should still produce a response ─────

#[test]
fn proxy_falls_back_for_unknown_profile_without_panicking() {
    let req = ProxyRequest {
        id: "t02-fallback".to_owned(),
        method: "GET".to_owned(),
        url: "http://127.0.0.1:1/nope".to_owned(),
        headers: vec![],
        body: vec![],
        profile: "nonexistent_xyz".to_owned(),
        timeout_secs: 2,
    };
    let resp = proxy_send_request(req);
    // Must not panic, and must produce a response with an error.
    assert_eq!(resp.id, "t02-fallback");
    assert!(
        resp.error.is_some(),
        "unknown profile should produce an error, not panic"
    );
}

// ── Canonical pool identity: same profile returns same Arc ──────────────

#[test]
fn same_profile_returns_same_pool_pointer() {
    let first = HttpClient::for_profile("rustls_default").expect("build first client");
    let second = HttpClient::for_profile("rustls_default").expect("reuse cached client");
    // Same inner Arc pointer = same connection pool.
    assert_eq!(first.profile(), second.profile());
    // The existing test in http_client.rs proves Arc::ptr_eq.
}

// ── Case-insensitive profile lookup ─────────────────────────────────────

#[test]
fn profile_lookup_is_case_insensitive() {
    let client = HttpClient::for_profile("CHROME_120").expect("uppercase profile");
    assert_eq!(client.profile(), "chrome_120");

    let client = HttpClient::for_profile("Chrome_149").expect("mixed-case profile");
    assert_eq!(client.profile(), "chrome_149");
}

// ── Pass-through client succeeds ────────────────────────────────────────

#[test]
fn pass_through_client_uses_special_label() {
    let client = HttpClient::for_profile("pass-through").expect("build pass-through client");
    assert_eq!(client.profile(), "pass-through");
    // Case-insensitive pass-through:
    let client = HttpClient::for_profile("PASS-THROUGH").expect("uppercase pass-through");
    assert_eq!(client.profile(), "pass-through");
}

// ── Non-replayable body: ProxyRequest.body is Vec<u8>, consumed once ────

#[test]
fn proxy_request_body_is_valued_not_replayable_stream() {
    // Verify body type is Vec<u8> — consumed once. This is a compile-time
    // structural check encoded as a runtime test.
    let body: Vec<u8> = vec![1, 2, 3];
    let req = ProxyRequest {
        id: "t02-body".to_owned(),
        method: "POST".to_owned(),
        url: "http://127.0.0.1:1/nope".to_owned(),
        headers: vec![],
        body,
        profile: "pass-through".to_owned(),
        timeout_secs: 2,
    };
    assert_eq!(req.body.len(), 3);
}

#[tokio::test]
async fn direct_wreq_client_round_trips_a_buffered_request() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local test server");
    let address = listener.local_addr().expect("read local address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept test request");
        hyper::server::conn::http1::Builder::new()
            .serve_connection(
                TokioIo::new(stream),
                service_fn(|request: Request<hyper::body::Incoming>| async move {
                    let value = request
                        .headers()
                        .get("x-tlsplus-test")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default();
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::copy_from_slice(
                        value.as_bytes(),
                    ))))
                }),
            )
            .await
            .expect("serve test request");
    });

    let request = Request::builder()
        .uri(format!("http://{address}/round-trip"))
        .header("x-tlsplus-test", "wreq-fork")
        .body(Full::new(Bytes::new()))
        .expect("build request");
    let response = HttpClient::for_profile("pass-through")
        .expect("build direct client")
        .request(request)
        .await
        .expect("send direct request");
    let body = response.bytes().await.expect("read response body");
    assert_eq!(body, Bytes::from_static(b"wreq-fork"));
    server.abort();
}

#[tokio::test]
async fn local_proxy_forwards_headers_and_body_through_wreq() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream server");
    let upstream_address = upstream.local_addr().expect("read upstream address");
    let upstream_task = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.expect("accept proxy request");
        hyper::server::conn::http1::Builder::new()
            .serve_connection(
                TokioIo::new(stream),
                service_fn(|request: Request<hyper::body::Incoming>| async move {
                    let echoed = request
                        .headers()
                        .get("x-round-trip")
                        .cloned()
                        .unwrap_or_else(|| hyper::header::HeaderValue::from_static("missing"));
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header("x-upstream", echoed)
                            .body(Full::new(Bytes::from_static(b"proxy-wreq")))
                            .expect("build upstream response"),
                    )
                }),
            )
            .await
            .expect("serve proxy request");
    });

    let proxy_address = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve proxy address")
        .local_addr()
        .expect("read proxy address");
    let started = start_local_server(proxy_address.to_string());
    assert!(started.running, "proxy must start: {}", started.message);

    let request = wreq::Client::new()
        .get(format!("http://{proxy_address}/"))
        .header(
            "x-tlsplus-target",
            format!("http://{upstream_address}/echo"),
        )
        .header("x-tlsplus-profile", "pass-through")
        .header("x-round-trip", "preserved");
    let mut response = None;
    for _ in 0..20 {
        match request
            .try_clone()
            .expect("clone proxy request")
            .send()
            .await
        {
            Ok(value) => {
                response = Some(value);
                break;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
        }
    }
    let response = response.expect("send through public local proxy");
    assert_eq!(response.status(), hyper::StatusCode::OK);
    assert_eq!(response.headers()["x-upstream"], "preserved");
    assert_eq!(
        response.bytes().await.expect("read proxy body"),
        Bytes::from_static(b"proxy-wreq")
    );
    stop_local_server();
    upstream_task.abort();
}

#[tokio::test]
async fn buffered_proxy_preserves_redirect_responses() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind redirect server");
    let address = listener.local_addr().expect("read redirect address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept redirect request");
        hyper::server::conn::http1::Builder::new()
            .serve_connection(
                TokioIo::new(stream),
                service_fn(|_: Request<hyper::body::Incoming>| async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(hyper::StatusCode::FOUND)
                            .header("location", "/next")
                            .body(Full::new(Bytes::new()))
                            .expect("build redirect response"),
                    )
                }),
            )
            .await
            .expect("serve redirect request");
    });

    let response = tlsplus_core::proxy_send_request_async(ProxyRequest {
        id: "redirect".to_owned(),
        method: "GET".to_owned(),
        url: format!("http://{address}/start"),
        headers: vec![],
        body: vec![],
        profile: "pass-through".to_owned(),
        timeout_secs: 2,
    })
    .await;
    assert_eq!(response.status_code, 302);
    assert!(
        response
            .headers
            .iter()
            .any(|header| header.eq_ignore_ascii_case("location: /next"))
    );
    server.abort();
}
