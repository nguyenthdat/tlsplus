use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Method, Request, Response, StatusCode, Version, body::Incoming, upgrade::OnUpgrade};
use hyper_util::rt::TokioIo;
use tokio::sync::mpsc;

use super::service::{BoxError, ServerBody, convert_response, error_response};

mod headers;

const INBOUND_UPGRADE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct BridgeJob {
    inbound: OnUpgrade,
    outbound: wreq::Upgraded,
}

pub(crate) enum UpgradeRequest {
    None,
    Invalid,
    WebSocket,
}

pub(crate) fn classify(request: &Request<Incoming>) -> UpgradeRequest {
    let connection_upgrade =
        headers::contains_token(request.headers(), hyper::header::CONNECTION, "upgrade");
    let websocket_upgrade =
        headers::contains_token(request.headers(), hyper::header::UPGRADE, "websocket");

    if !connection_upgrade && !websocket_upgrade {
        return UpgradeRequest::None;
    }

    if request.method() == Method::GET
        && request.version() == Version::HTTP_11
        && connection_upgrade
        && websocket_upgrade
    {
        UpgradeRequest::WebSocket
    } else {
        UpgradeRequest::Invalid
    }
}

pub(crate) async fn proxy(
    mut request: Request<Incoming>,
    bridge_tx: mpsc::Sender<BridgeJob>,
) -> Response<ServerBody> {
    let target = request
        .headers()
        .get("x-tlsplus-target")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    if target.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "Missing X-Tlsplus-Target header");
    }

    let profile = request
        .headers()
        .get("x-tlsplus-profile")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("pass-through")
        .to_owned();
    let timeout = request
        .headers()
        .get("x-tlsplus-timeout")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map_or(Duration::from_secs(30), |seconds| {
            Duration::from_secs(seconds.max(1))
        });
    let uri = match headers::normalize_target(&target) {
        Ok(uri) => uri,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, &error),
    };
    let client = match crate::transport::get_wreq_client(&profile) {
        Ok(client) => client,
        Err(error) => return error_response(StatusCode::BAD_GATEWAY, &error),
    };

    let inbound = hyper::upgrade::on(&mut request);
    let headers = headers::request_headers(request.headers());
    let (parts, body) = request.into_parts();
    let deadline = match tokio::time::Instant::now().checked_add(timeout) {
        Some(deadline) => deadline,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "X-Tlsplus-Timeout exceeds the supported range",
            );
        }
    };
    let response = match tokio::time::timeout_at(
        deadline,
        client
            .request(parts.method, uri)
            .version(wreq::Version::HTTP_11)
            .headers(headers)
            .body(wreq::Body::wrap_stream(body.into_data_stream()))
            .send(),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                &format!("WebSocket request to {target} failed (profile: {profile}): {error}"),
            );
        }
        Err(_) => {
            return error_response(
                StatusCode::GATEWAY_TIMEOUT,
                &format!("WebSocket request to {target} timed out after {timeout:?}"),
            );
        }
    };

    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        return convert_response(response);
    }
    if !headers::is_websocket_upgrade(response.headers()) {
        return error_response(
            StatusCode::BAD_GATEWAY,
            "Upstream returned an invalid WebSocket upgrade response",
        );
    }

    let version = response.version();
    let headers = headers::response_headers(response.headers());
    let outbound = match tokio::time::timeout_at(deadline, response.upgrade()).await {
        Ok(Ok(upgraded)) => upgraded,
        Ok(Err(error)) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Upstream WebSocket upgrade failed: {error}"),
            );
        }
        Err(_) => {
            return error_response(
                StatusCode::GATEWAY_TIMEOUT,
                "Upstream WebSocket upgrade timed out",
            );
        }
    };

    if bridge_tx
        .send(BridgeJob { inbound, outbound })
        .await
        .is_err()
    {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "WebSocket bridge is unavailable",
        );
    }

    let body = Empty::<Bytes>::new()
        .map_err(|never| -> BoxError { match never {} })
        .boxed();
    let mut downstream = Response::new(body);
    *downstream.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    *downstream.version_mut() = version;
    *downstream.headers_mut() = headers;
    downstream
}

pub(crate) async fn run_bridge(job: BridgeJob) -> Result<(), String> {
    let inbound = tokio::time::timeout(INBOUND_UPGRADE_TIMEOUT, job.inbound)
        .await
        .map_err(|_| "inbound WebSocket upgrade timed out".to_owned())?
        .map_err(|error| format!("inbound WebSocket upgrade failed: {error}"))?;
    let mut inbound = TokioIo::new(inbound);
    let mut outbound = job.outbound;

    tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
        .await
        .map(|_| ())
        .map_err(|error| format!("WebSocket tunnel failed: {error}"))
}
