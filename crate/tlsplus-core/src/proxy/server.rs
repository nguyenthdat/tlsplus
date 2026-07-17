//! Raw hyper HTTP/1 proxy server with header case preservation and request
//! body streaming — no buffering, no normalization.
//!
//! Replaces the previous axum-based server that buffered entire request bodies
//! (via `Bytes` extractor) and normalized headers. The hyper-native server
//! passes `Incoming` request bodies straight through to the outbound
//! connection, which fixes blank-page rendering on YouTube and heavy SPAs
//! where POST API calls must stream.
//!
//! Key properties:
//! - `preserve_header_case(true)` + `title_case_headers(true)` on both server
//!   and client connections — header names flow through with Chrome-style
//!   Title-Case, matching real browser fingerprints.
//! - Request body streams (`Incoming` → `BoxBody`) — zero buffering.
//! - Response body streams (`Incoming` → `BoxBody`) — zero buffering.
//! - Full hop-by-hop header stripping per RFC 7230 §6.1.

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::Arc,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, Response, StatusCode, Uri,
    body::Incoming,
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::{SERVER_STATE, ServerStatus};

use super::RUNTIME;
use super::client::{get_client, get_passthrough_client};

// ---------------------------------------------------------------------------
// Box body helpers
// ---------------------------------------------------------------------------

/// Wrap a plaintext error string in a `BoxBody` for HTTP error responses.
fn boxed_error(msg: &str) -> http_body_util::combinators::BoxBody<Bytes, hyper::Error> {
    Full::new(Bytes::from(msg.to_owned()))
        .map_err(|never: Infallible| match never {})
        .boxed()
}

// ---------------------------------------------------------------------------
// Hop-by-hop header name set (all lowercase)
// ---------------------------------------------------------------------------

/// Returns true if `name` (lowercase) is a hop-by-hop or internal header that
/// must NOT be forwarded to the target.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

// ---------------------------------------------------------------------------
// Proxy service — the core forwarding logic
// ---------------------------------------------------------------------------

/// Stateless proxy handler: reads `X-Tlsplus-Target` (and optional
/// `X-Tlsplus-Profile`, `X-Tlsplus-Timeout`), strips internal + hop-by-hop
/// headers, forwards the streaming request body to the target, and streams the
/// response body back.
async fn proxy_service(req: Request<Incoming>) -> Result<Response<http_body_util::combinators::BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    // ── Decompose the incoming request ──
    // Extract all metadata BEFORE touching the body stream to avoid borrow-
    // checker issues when moving parts out of the request.
    let (parts, body) = req.into_parts();
    let req_method = parts.method;
    let req_headers = parts.headers;

    // ── Extract forwarding metadata from request headers ──
    let target = req_headers
        .get("x-tlsplus-target")
        .or_else(|| req_headers.get("X-Tlsplus-Target"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    if target.is_empty() {
        let mut resp = Response::new(boxed_error("Missing X-Tlsplus-Target header"));
        *resp.status_mut() = StatusCode::BAD_REQUEST;
        return Ok(resp);
    }

    let profile = req_headers
        .get("x-tlsplus-profile")
        .or_else(|| req_headers.get("X-Tlsplus-Profile"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("pass-through");

    let timeout_str = req_headers
        .get("x-tlsplus-timeout")
        .or_else(|| req_headers.get("X-Tlsplus-Timeout"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("30");
    let timeout_secs: u64 = timeout_str.parse().unwrap_or(30);

    // ── Parse target URL ──
    let uri: Uri = match target.parse() {
        Ok(uri) => uri,
        Err(e) => {
            let mut resp = Response::new(boxed_error(&format!("Invalid target URL: {e}")));
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(resp);
        }
    };

    // ── Resolve profile client ──
    let client = if profile == "pass-through" {
        match get_passthrough_client() {
            Ok(c) => c,
            Err(e) => {
                let mut resp = Response::new(boxed_error(&e));
                *resp.status_mut() = StatusCode::BAD_GATEWAY;
                return Ok(resp);
            }
        }
    } else {
        match get_client(profile) {
            Ok(c) => c,
            Err(e) => {
                let mut resp = Response::new(boxed_error(&e));
                *resp.status_mut() = StatusCode::BAD_GATEWAY;
                return Ok(resp);
            }
        }
    };

    // ── Build outgoing request ──
    //
    // Copy headers from the incoming request, removing:
    //   1. X-Tlsplus-* (internal proxy metadata)
    //   2. Host (re-set from target URI authority)
    //   3. All hop-by-hop headers (Connection, TE, Transfer-Encoding, etc.)
    //
    // The `Accept-Encoding` header is preserved so the server responds
    // with an encoding the browser natively decompresses.
    let mut req_builder = Request::builder()
        .method(req_method)
        .uri(uri.clone());

    // NOTE: Do NOT set the Host header explicitly — hyper's legacy client
    // handles it via `set_host: true` (default). Explicitly setting `host`
    // as a regular header can cause HTTP/2 PROTOCOL_ERROR on strict servers
    // like Google that reject duplicate `host` / `:authority` pseudo-headers.
    //
    // Copy qualifying headers — preserve Accept-Encoding, strip internal + hop-by-hop
    if let Some(hdrs) = req_builder.headers_mut() {
        for (name, value) in req_headers.iter() {
            let lower = name.as_str();
            if lower.starts_with("x-tlsplus-") || lower == "host" || is_hop_by_hop(lower) {
                continue;
            }
            hdrs.append(name.clone(), value.clone());
        }
    }

    // ── Send with streaming body ──
    // The incoming body (Incoming) is boxed directly — no buffering.
    let outbound_body = body.boxed();
    let req = match req_builder.body(outbound_body) {
        Ok(r) => r,
        Err(e) => {
            let mut resp = Response::new(boxed_error(&format!("Failed to build request: {e}")));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            return Ok(resp);
        }
    };

    let effective_timeout = std::time::Duration::from_secs(timeout_secs.max(1));

    match tokio::time::timeout(effective_timeout, client.request(req)).await {
        Ok(Ok(resp)) => {
            // ── Stream response back ──
            // Pass headers + streaming body through. Only strip
            // transfer-encoding since hyper de-chunked the incoming body.
            let (resp_parts, resp_body) = resp.into_parts();
            let status = resp_parts.status;

            let mut resp_builder = Response::builder().status(status);

            if let Some(hdrs) = resp_builder.headers_mut() {
                for (name, value) in resp_parts.headers.iter() {
                    let lower = name.as_str();
                    if lower == "transfer-encoding" {
                        continue;
                    }
                    hdrs.append(name.clone(), value.clone());
                }
            }

            let streaming_body = resp_body.boxed();
            Ok(resp_builder.body(streaming_body).unwrap_or_else(|_| {
                let mut err = Response::new(boxed_error("Failed to build streaming response"));
                *err.status_mut() = StatusCode::BAD_GATEWAY;
                err
            }))
        }
        Ok(Err(e)) => {
            let mut resp = Response::new(boxed_error(&format!(
                "Request to {target} failed (profile: {profile}): {e}"
            )));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            Ok(resp)
        }
        Err(_elapsed) => {
            let mut resp = Response::new(boxed_error(&format!(
                "Request to {target} timed out after {effective_timeout:?}"
            )));
            *resp.status_mut() = StatusCode::GATEWAY_TIMEOUT;
            Ok(resp)
        }
    }
}

// ---------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------

/// Start the local HTTP forward proxy server.
///
/// Spawns a raw hyper HTTP/1 server on the given address inside the global
/// Tokio runtime. The server uses `service_fn` for stateless per-request
/// forwarding with header case preservation and streaming bodies.
/// Graceful shutdown is triggered via `stop_local_server_impl`.
pub fn start_local_server_impl(listen_addr: String) -> ServerStatus {
    let mut state = SERVER_STATE.lock().expect("server state lock poisoned");

    if state.running {
        return ServerStatus {
            running: true,
            listen_addr: state.listen_addr.clone(),
            message: "Server is already running".to_owned(),
        };
    }

    let addr: SocketAddr = match listen_addr.parse() {
        Ok(addr) => addr,
        Err(e) => {
            return ServerStatus {
                running: false,
                listen_addr: None,
                message: format!("Invalid listen address '{listen_addr}': {e}"),
            };
        }
    };

    let shutdown_notify = Arc::new(tokio::sync::Notify::new());
    let shutdown_notify_clone = shutdown_notify.clone();

    RUNTIME.spawn(async move {
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("tlsplus proxy: failed to bind {addr}: {e}");
                return;
            }
        };

        loop {
            tokio::select! {
                _ = shutdown_notify_clone.notified() => {
                    break;
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, _)) => {
                            let io = TokioIo::new(stream);
                            tokio::task::spawn(async move {
                                let result = http1::Builder::new()
                                    .preserve_header_case(true)
                                    .title_case_headers(true)
                                    .serve_connection(io, service_fn(proxy_service))
                                    .await;
                                if let Err(err) = result
                                    && !err.to_string().contains("connection closed")
                                    && !err.to_string().contains("broken pipe")
                                    && !err.to_string().contains("protocol error")
                                {
                                    eprintln!("tlsplus proxy: connection error: {err}");
                                }
                            });
                        }
                        Err(e) => {
                            eprintln!("tlsplus proxy: accept error: {e}");
                        }
                    }
                }
            }
        }
    });

    state.running = true;
    state.listen_addr = Some(listen_addr.clone());
    state.shutdown_notify = Some(shutdown_notify);

    ServerStatus {
        running: true,
        listen_addr: Some(listen_addr),
        message: "Local HTTP forward proxy started (hyper-native, streaming)".to_owned(),
    }
}

/// Query the current server state without mutation.
///
/// Reads `SERVER_STATE` and returns the live `running` / `listen_addr`
/// fields. If the lock is poisoned a best-effort status is returned with
/// `running: false` and an explanatory message — no panic.
pub fn server_status_impl() -> ServerStatus {
    match SERVER_STATE.lock() {
        Ok(state) => {
            let msg = if state.running {
                format!(
                    "Server is running{}",
                    state
                        .listen_addr
                        .as_deref()
                        .map(|a| format!(" on {a}"))
                        .unwrap_or_default()
                )
            } else {
                "Server is stopped".to_owned()
            };
            ServerStatus {
                running: state.running,
                listen_addr: state.listen_addr.clone(),
                message: msg,
            }
        }
        Err(_poison) => ServerStatus {
            running: false,
            listen_addr: None,
            message: "Server state lock poisoned — restart recommended".to_owned(),
        },
    }
}

/// Stop the local HTTP forward proxy server.
///
/// Sends a shutdown notification to the running server and updates the shared
/// server state.
pub fn stop_local_server_impl() -> ServerStatus {
    let mut state = SERVER_STATE.lock().expect("server state lock poisoned");

    let previous_addr = state.listen_addr.take();

    if let Some(notify) = state.shutdown_notify.take() {
        notify.notify_one();
        state.running = false;
        ServerStatus {
            running: false,
            listen_addr: previous_addr,
            message: "Local HTTP forward proxy stopped".to_owned(),
        }
    } else {
        state.running = false;
        ServerStatus {
            running: false,
            listen_addr: previous_addr,
            message: "Server was not running".to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// Synchronous proxy_send_request
// ---------------------------------------------------------------------------

async fn send_request(request: crate::ProxyRequest) -> crate::ProxyResponse {
    let result = super::forward::forward_request(
        &request.url,
        &request.method,
        request.headers,
        request.body,
        &request.profile,
        request.timeout_secs,
    )
    .await;

    match result {
        Ok(mut resp) => {
            resp.id = request.id;
            resp
        }
        Err(err) => crate::ProxyResponse {
            id: request.id,
            status_code: 0,
            headers: vec![],
            body: vec![],
            ja4: None,
            error: Some(err),
        },
    }
}

/// Asynchronously forward a single request through the profile-specific client.
///
/// This is the non-blocking Rust entry point used by higher-level clients. It
/// does not start or route through the local proxy server.
pub async fn proxy_send_request_async_impl(request: crate::ProxyRequest) -> crate::ProxyResponse {
    send_request(request).await
}

/// Synchronously forward a single request through the profile-specific client.
///
/// This function blocks the calling thread using `Runtime::block_on`. It does
/// NOT use the local proxy server — it directly constructs and sends an HTTP
/// request via the cached per-profile hyper client on the global Tokio
/// runtime.
pub fn proxy_send_request_impl(request: crate::ProxyRequest) -> crate::ProxyResponse {
    RUNTIME.block_on(send_request(request))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
