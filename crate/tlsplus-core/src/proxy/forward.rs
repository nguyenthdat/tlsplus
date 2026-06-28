//! Request forwarding with retry/backoff/timeout logic.
//!
//! Handles building forwarded headers, constructing hyper requests, and
//! forwarding through the per-profile client with retries for transient
//! errors on idempotent methods. Supports multipart bodies and transparent
//! response forwarding (no decompression — the browser handles compression).
//!
//! Uses `BoxBody` for request bodies so both buffered (`Full`) and streaming
//! (`Incoming`) bodies work through the same client type.

use std::{convert::Infallible, sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Uri, header::HeaderName};

use crate::ProxyResponse;

use super::client::{ProfileClient, ProxyBody, get_client, get_passthrough_client};

// ---------------------------------------------------------------------------
// Header helpers
// ---------------------------------------------------------------------------

/// Build a `hyper::HeaderMap` from a list of "Name: Value" header strings.
///
/// Preserves the original case of the header name as provided in the string.
/// With `http1_title_case_headers(true)` on the client, these names will be
/// sent in Title-Case on the wire, matching Chrome's behavior.
pub(crate) fn build_hyper_headers(headers: &[String]) -> hyper::HeaderMap {
    let mut map = hyper::HeaderMap::new();
    for h in headers {
        if let Some((name, value)) = h.split_once(':') {
            let name_trimmed = name.trim();
            let value_trimmed = value.trim();
            if let (Ok(header_name), Ok(header_value)) =
                (name_trimmed.parse::<HeaderName>(), value_trimmed.parse())
            {
                map.insert(header_name, header_value);
            }
        }
    }
    map
}

/// Build a boxed streaming body from a buffered byte vector.
///
/// Used by the buffered forwarding path (`forward_request`) to produce a
/// `ProxyBody` from pre-read bytes. The `Infallible` → `hyper::Error` map
/// is a no-op required for type compatibility with `BoxBody`.
pub(crate) fn boxed_body_full(bytes: Vec<u8>) -> ProxyBody {
    Full::new(Bytes::from(bytes))
        .map_err(|never: Infallible| match never {})
        .boxed()
}

// ---------------------------------------------------------------------------
// Retry / error classification
// ---------------------------------------------------------------------------

/// Returns true if the HTTP method is considered idempotent (safe to retry).
fn is_idempotent(method: &str) -> bool {
    matches!(
        method.to_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS" | "PUT" | "DELETE"
    )
}

/// Returns true if the error is transient (worth retrying).
fn is_transient_error(err: &str) -> bool {
    let lower = err.to_lowercase();
    lower.contains("connection refused")
        || lower.contains("connection reset")
        || lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("broken pipe")
        || lower.contains("eof")
        || lower.contains("connect error")
}

// ---------------------------------------------------------------------------
// Response conversion
// ---------------------------------------------------------------------------

/// Convert a hyper response into our `ProxyResponse` record.
///
/// Passes headers and body through transparently — no decompression.
/// The browser handles Content-Encoding natively. This avoids the
/// Content-Length mismatch bug that caused truncated JS/CSS resources.
async fn convert_response(resp: hyper::Response<Incoming>) -> Result<ProxyResponse, String> {
    let status = resp.status().as_u16();

    // Pass ALL response headers through as-is. The browser handles
    // Content-Encoding (gzip/br/zstd) natively, and Content-Length
    // correctly reflects the (still-compressed) body size.
    let response_headers: Vec<String> = resp
        .headers()
        .iter()
        .filter(|(k, _)| {
            let name = k.as_str().to_lowercase();
            // Only strip transfer-encoding since hyper already de-chunked the body
            name != "transfer-encoding"
        })
        .map(|(k, v)| format!("{}: {}", k, v.to_str().unwrap_or("")))
        .collect();

    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("Failed to read response body: {e}"))?
        .to_bytes()
        .to_vec();

    Ok(ProxyResponse {
        id: String::new(),
        status_code: status,
        headers: response_headers,
        body,
        ja4: None,
        error: None,
    })
}

// ---------------------------------------------------------------------------
// Forward request (buffered — for proxy_send_request UniFFI path)
// ---------------------------------------------------------------------------

/// Maximum body size for retry on POST/PATCH (1 MiB).
/// Bodies larger than this are NOT cloned for retries.
const MAX_RETRY_BODY_SIZE: usize = 1024 * 1024;

/// Forward an HTTP request to the target URL using the profile-specific client.
///
/// Uses the per-profile client cache for connection pooling. Applies
/// per-request timeouts and retries for transient errors on idempotent methods.
///
/// # Multipart support
/// Content-Type headers (including multipart boundaries) are preserved
/// and forwarded to the target server. Bodies up to 1 MiB are retried
/// on transient errors.
///
/// # Compression transparency
/// The browser's `Accept-Encoding` header passes through unchanged, and
/// response bodies are forwarded as-is (compressed). The browser handles
/// decompression natively, including zstd which we cannot decompress.
/// This avoids the Content-Length mismatch bug from decompression.
pub(crate) async fn forward_request(
    target_url: &str,
    method: &str,
    headers: Vec<String>,
    body: Vec<u8>,
    profile: &str,
    timeout_secs: u32,
) -> Result<ProxyResponse, String> {
    // Resolve client: pass-through uses default BoringSSL, profiles use custom TLS
    let client: Arc<ProfileClient> = if profile == "pass-through" {
        get_passthrough_client()?
    } else {
        get_client(profile)?
    };

    // Parse URI and method
    let uri: Uri = target_url
        .parse()
        .map_err(|e| format!("Invalid URL '{target_url}': {e}"))?;

    let req_method: Method = method.parse().map_err(|e| {
        format!(
            "Unsupported HTTP method '{method}' for target {target_url} (profile: {profile}): {e}"
        )
    })?;

    let method_upper = method.to_uppercase();
    let body_size = body.len();

    // Only retry idempotent methods or small POST/PATCH bodies
    let max_retries = if is_idempotent(&method_upper) {
        2
    } else if body_size <= MAX_RETRY_BODY_SIZE {
        1 // allow 1 retry for small non-idempotent requests
    } else {
        0 // no retries for large uploads
    };

    let mut last_error = String::new();

    let effective_timeout = if timeout_secs > 0 {
        Duration::from_secs(timeout_secs as u64)
    } else {
        Duration::from_secs(30)
    };

    for attempt in 0..=max_retries {
        if attempt > 0 {
            let backoff_ms = match attempt {
                1 => 100,
                _ => 400,
            };
            eprintln!(
                "tlsplus: retry attempt {attempt} for {method_upper} {target_url} (profile: {profile})",
            );
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        }

        // Build hyper request
        let mut req_builder = Request::builder()
            .method(req_method.clone())
            .uri(uri.clone());

        // Merge forwarded headers — the browser's original Accept-Encoding
        // passes through so the server responds with an encoding the browser
        // can natively decompress.
        {
            let hmap = build_hyper_headers(&headers);
            if let Some(hdrs) = req_builder.headers_mut() {
                hdrs.extend(hmap);
            }
        }

        // Clone the body for retry safety. `boxed_body_full` takes a Vec<u8>
        // and wraps it into a `BoxBody` via `Full` + `.boxed()`.
        let req_body = boxed_body_full(body.clone());

        let req = match req_builder.body(req_body) {
            Ok(r) => r,
            Err(e) => {
                return Err(format!(
                    "Failed to build request to {target_url} (profile: {profile}): {e}"
                ));
            }
        };

        let send_future = client.request(req);
        let response = match tokio::time::timeout(effective_timeout, send_future).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                let err_str = e.to_string();
                last_error =
                    format!("Request to {target_url} failed (profile: {profile}): {err_str}");
                if attempt < max_retries && is_transient_error(&err_str) {
                    continue;
                }
                return Err(last_error);
            }
            Err(_elapsed) => {
                last_error = format!(
                    "Request to {target_url} timed out after {effective_timeout:?} (profile: {profile})"
                );
                if attempt < max_retries {
                    continue;
                }
                return Err(last_error);
            }
        };

        let status_code = response.status().as_u16();

        // Retry on 5xx for idempotent methods
        if status_code >= 500 && attempt < max_retries {
            last_error =
                format!("Server error {status_code} from {target_url} (profile: {profile})");
            continue;
        }

        // Convert and return (transparent — no decompression)
        let mut proxy_resp = convert_response(response).await?;
        proxy_resp.status_code = status_code;
        return Ok(proxy_resp);
    }

    Err(last_error)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_idempotent() {
        assert!(is_idempotent("GET"));
        assert!(is_idempotent("HEAD"));
        assert!(is_idempotent("OPTIONS"));
        assert!(is_idempotent("PUT"));
        assert!(is_idempotent("DELETE"));
        assert!(!is_idempotent("POST"));
        assert!(!is_idempotent("PATCH"));
    }

    #[test]
    fn test_is_transient_error() {
        assert!(is_transient_error("connection refused"));
        assert!(is_transient_error("Connection Reset by peer"));
        assert!(is_transient_error("request timeout"));
        assert!(is_transient_error("timed out"));
        assert!(is_transient_error("broken pipe"));
        assert!(is_transient_error("unexpected EOF"));
        assert!(!is_transient_error("404 not found"));
        assert!(!is_transient_error("invalid url"));
    }
}
