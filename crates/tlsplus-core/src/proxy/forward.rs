//! Buffered request forwarding for the UniFFI proxy API.

use std::time::Duration;

use bytes::Bytes;
use hyper::{HeaderMap, Method, header::HeaderName};

use crate::{ProxyResponse, transport::get_wreq_client};

const MAX_RETRY_BODY_SIZE: usize = 1024 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn build_forward_headers(headers: &[String]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for header in headers {
        if let Some((name, value)) = header.split_once(':')
            && let (Ok(name), Ok(value)) = (name.trim().parse::<HeaderName>(), value.trim().parse())
        {
            map.append(name, value);
        }
    }
    map
}

fn is_idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::PUT | Method::DELETE
    )
}

fn is_transient_error(error: &wreq::Error) -> bool {
    error.is_timeout() || error.is_connect() || error.is_connection_reset() || error.is_dns()
}

fn response_headers(response: &wreq::Response) -> Vec<String> {
    response
        .headers()
        .iter()
        .filter(|(name, _)| name.as_str() != "transfer-encoding")
        .map(|(name, value)| format!("{name}: {}", String::from_utf8_lossy(value.as_bytes())))
        .collect()
}

async fn convert_response(response: wreq::Response) -> Result<ProxyResponse, String> {
    let status_code = response.status().as_u16();
    let headers = response_headers(&response);
    let body = response
        .bytes()
        .await
        .map_err(|error| format!("Failed to read response body: {error}"))?
        .to_vec();

    Ok(ProxyResponse {
        id: String::new(),
        status_code,
        headers,
        body,
        ja4: None,
        error: None,
    })
}

pub(crate) async fn forward_request(
    target_url: &str,
    method: &str,
    headers: Vec<String>,
    body: Vec<u8>,
    profile: &str,
    timeout_secs: u32,
) -> Result<ProxyResponse, String> {
    let client = get_wreq_client(profile)?;
    let uri: wreq::Uri = target_url
        .parse()
        .map_err(|error| format!("Invalid URL '{target_url}': {error}"))?;
    let method: Method = method.parse().map_err(|error| {
        format!("Unsupported HTTP method '{method}' for target {target_url}: {error}")
    })?;
    let headers = build_forward_headers(&headers);
    let body = Bytes::from(body);
    let max_retries = if is_idempotent(&method) {
        2
    } else if body.len() <= MAX_RETRY_BODY_SIZE {
        1
    } else {
        0
    };
    let effective_timeout = if timeout_secs == 0 {
        DEFAULT_TIMEOUT
    } else {
        Duration::from_secs(u64::from(timeout_secs))
    };
    let mut last_error = String::new();

    for attempt in 0..=max_retries {
        if attempt > 0 {
            let backoff = if attempt == 1 { 100 } else { 400 };
            tokio::time::sleep(Duration::from_millis(backoff)).await;
        }

        let send = client
            .request(method.clone(), uri.clone())
            .headers(headers.clone())
            .body(body.clone())
            .send();

        let response = match tokio::time::timeout(effective_timeout, send).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                last_error =
                    format!("Request to {target_url} failed (profile: {profile}): {error}");
                if attempt < max_retries && is_transient_error(&error) {
                    continue;
                }
                return Err(last_error);
            }
            Err(_) => {
                last_error = format!(
                    "Request to {target_url} timed out after {effective_timeout:?} (profile: {profile})"
                );
                if attempt < max_retries {
                    continue;
                }
                return Err(last_error);
            }
        };

        if response.status().is_server_error() && attempt < max_retries {
            last_error = format!(
                "Server error {} from {target_url} (profile: {profile})",
                response.status()
            );
            continue;
        }

        return convert_response(response).await;
    }

    Err(last_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_idempotent_methods() {
        for method in [
            Method::GET,
            Method::HEAD,
            Method::OPTIONS,
            Method::PUT,
            Method::DELETE,
        ] {
            assert!(is_idempotent(&method));
        }
        assert!(!is_idempotent(&Method::POST));
        assert!(!is_idempotent(&Method::PATCH));
    }

    #[test]
    fn preserves_repeated_header_values() {
        let headers = vec!["X-Value: one".to_owned(), "X-Value: two".to_owned()];
        let map = build_forward_headers(&headers);
        let values: Vec<_> = map
            .get_all("x-value")
            .iter()
            .map(|value| value.to_str().expect("test header is UTF-8"))
            .collect();
        assert_eq!(values, ["one", "two"]);
    }
}
