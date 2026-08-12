use std::convert::Infallible;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, Uri, body::Incoming};

use super::client::{get_client, get_passthrough_client_cached};

pub(crate) fn boxed_error(msg: &str) -> http_body_util::combinators::BoxBody<Bytes, hyper::Error> {
    Full::new(Bytes::from(msg.to_owned()))
        .map_err(|never: Infallible| match never {})
        .boxed()
}

pub(crate) fn is_hop_by_hop(name: &str) -> bool {
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

pub(crate) async fn proxy_service(
    req: Request<Incoming>,
) -> Result<Response<http_body_util::combinators::BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let (parts, body) = req.into_parts();
    let req_method = parts.method;
    let req_headers = parts.headers;

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

    let uri: Uri = match target.parse() {
        Ok(uri) => uri,
        Err(e) => {
            let mut resp = Response::new(boxed_error(&format!("Invalid target URL: {e}")));
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(resp);
        }
    };

    let client = if profile == "pass-through" {
        match get_passthrough_client_cached() {
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

    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            let mut resp = Response::new(boxed_error("Failed to read request body"));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            return Ok(resp);
        }
    };

    let effective_timeout = Duration::from_secs(timeout_secs.max(1));

    let mut wreq_req = client.request(req_method, uri.to_string());

    for (name, value) in req_headers.iter() {
        let lower = name.as_str();
        if lower.starts_with("x-tlsplus-") || lower == "host" || is_hop_by_hop(lower) {
            continue;
        }
        wreq_req = wreq_req.header(name.as_str(), value.to_str().unwrap_or(""));
    }

    wreq_req = wreq_req.body(body_bytes.to_vec());
    wreq_req = wreq_req.timeout(effective_timeout);

    match wreq_req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let response_headers = resp.headers().clone();
            let resp_bytes = match resp.bytes().await {
                Ok(b) => b,
                Err(_) => {
                    let mut err = Response::new(boxed_error("Failed to read response body"));
                    *err.status_mut() = StatusCode::BAD_GATEWAY;
                    return Ok(err);
                }
            };

            let mut resp_builder = Response::builder().status(status);
            if let Some(hdrs) = resp_builder.headers_mut() {
                for (name, value) in response_headers.iter() {
                    let lower = name.as_str();
                    if lower == "transfer-encoding" {
                        continue;
                    }
                    hdrs.append(name.clone(), value.clone());
                }
            }

            Ok(resp_builder
                .body(
                    Full::new(resp_bytes)
                        .map_err(|never: Infallible| match never {})
                        .boxed(),
                )
                .unwrap_or_else(|_| {
                    let mut err = Response::new(boxed_error("Failed to build response"));
                    *err.status_mut() = StatusCode::BAD_GATEWAY;
                    err
                }))
        }
        Err(e) => {
            let mut resp = Response::new(boxed_error(&format!(
                "Request to {target} failed (profile: {profile}): {e}"
            )));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            Ok(resp)
        }
    }
}
