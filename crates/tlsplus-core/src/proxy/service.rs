use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, Uri, Version, body::Incoming};
use tokio::sync::mpsc;

use super::websocket::{BridgeJob, UpgradeRequest};

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type ServerBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

pub(crate) fn boxed_error(message: &str) -> ServerBody {
    Full::new(Bytes::copy_from_slice(message.as_bytes()))
        .map_err(|never: Infallible| -> BoxError { match never {} })
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
    request: Request<Incoming>,
    bridge_tx: mpsc::Sender<BridgeJob>,
) -> Result<Response<ServerBody>, Infallible> {
    if !declared_version_matches(&request) {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "HTTP version changed between Burp and the TLS+ proxy",
        ));
    }

    match super::websocket::classify(&request) {
        UpgradeRequest::WebSocket(transport) => {
            return Ok(super::websocket::proxy(request, bridge_tx, transport).await);
        }
        UpgradeRequest::Invalid => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Invalid WebSocket upgrade request",
            ));
        }
        UpgradeRequest::None => {}
    }

    let (parts, body) = request.into_parts();
    let target = parts
        .headers
        .get("x-tlsplus-target")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();

    if target.is_empty() {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "Missing X-Tlsplus-Target header",
        ));
    }

    let profile = parts
        .headers
        .get("x-tlsplus-profile")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("pass-through")
        .to_owned();
    let timeout_secs = parts
        .headers
        .get("x-tlsplus-timeout")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(30);
    let uri: Uri = match target.parse() {
        Ok(uri) => uri,
        Err(error) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                &format!("Invalid target URL: {error}"),
            ));
        }
    };
    let client = match crate::transport::get_wreq_client(&profile) {
        Ok(client) => client,
        Err(error) => return Ok(error_response(StatusCode::BAD_GATEWAY, &error)),
    };

    let headers = parts
        .headers
        .iter()
        .filter(|(name, _)| {
            let name = name.as_str();
            !name.starts_with("x-tlsplus-") && name != "host" && !is_hop_by_hop(name)
        })
        .fold(hyper::HeaderMap::new(), |mut headers, (name, value)| {
            headers.append(name.clone(), value.clone());
            headers
        });

    let outbound = client
        .request(parts.method, uri)
        .version(parts.version)
        .headers(headers)
        .body(wreq::Body::wrap_stream(body.into_data_stream()))
        .send();
    let effective_timeout = std::time::Duration::from_secs(timeout_secs.max(1));
    let response = match tokio::time::timeout(effective_timeout, outbound).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Request to {target} failed (profile: {profile}): {error}"),
            ));
        }
        Err(_) => {
            return Ok(error_response(
                StatusCode::GATEWAY_TIMEOUT,
                &format!("Request to {target} timed out after {effective_timeout:?}"),
            ));
        }
    };

    Ok(convert_response(response))
}

fn declared_version_matches(request: &Request<Incoming>) -> bool {
    match request
        .headers()
        .get("x-tlsplus-http-version")
        .and_then(|value| value.to_str().ok())
    {
        Some(version) if version.eq_ignore_ascii_case("HTTP/2") => {
            request.version() == Version::HTTP_2
        }
        Some(_) => false,
        None => true,
    }
}

pub(crate) fn convert_response(response: wreq::Response) -> Response<ServerBody> {
    let mut response: hyper::Response<wreq::Body> = response.into();
    response.headers_mut().remove("transfer-encoding");
    let (parts, body) = response.into_parts();
    let body = body
        .map_err(|error| -> BoxError { Box::new(error) })
        .boxed();
    Response::from_parts(parts, body)
}

pub(crate) fn error_response(status: StatusCode, message: &str) -> Response<ServerBody> {
    let mut response = Response::new(boxed_error(message));
    *response.status_mut() = status;
    response
}
