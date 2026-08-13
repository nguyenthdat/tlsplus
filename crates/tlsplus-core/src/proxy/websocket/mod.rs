use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Method, Request, Response, StatusCode, Version, body::Incoming, upgrade::OnUpgrade};
use hyper_util::rt::TokioIo;
use tokio::sync::mpsc;

use super::service::{BoxError, ServerBody, convert_response, error_response};

mod headers;
mod outbound;

const INBOUND_UPGRADE_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct BridgeJob {
    inbound: OnUpgrade,
    outbound: wreq::Upgraded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WebSocketTransport {
    Http1,
    Http2,
}

pub(crate) enum UpgradeRequest {
    None,
    Invalid,
    WebSocket(WebSocketTransport),
}

pub(crate) fn classify(request: &Request<Incoming>) -> UpgradeRequest {
    let extended_protocol = request.extensions().get::<hyper::ext::Protocol>();
    if extended_protocol.is_some() {
        return if request.method() == Method::CONNECT
            && request.version() == Version::HTTP_2
            && extended_protocol.is_some_and(|protocol| protocol.as_str() == "websocket")
        {
            UpgradeRequest::WebSocket(WebSocketTransport::Http2)
        } else {
            UpgradeRequest::Invalid
        };
    }

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
        UpgradeRequest::WebSocket(WebSocketTransport::Http1)
    } else {
        UpgradeRequest::Invalid
    }
}

pub(crate) async fn proxy(
    mut request: Request<Incoming>,
    bridge_tx: mpsc::Sender<BridgeJob>,
    transport: WebSocketTransport,
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
    let headers = headers::request_headers(request.headers(), transport);
    let deadline = match tokio::time::Instant::now().checked_add(timeout) {
        Some(deadline) => deadline,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "X-Tlsplus-Timeout exceeds the supported range",
            );
        }
    };
    let response =
        match tokio::time::timeout_at(deadline, outbound::send(&client, transport, uri, headers))
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

    if !outbound::is_success(&response, transport) {
        return convert_response(response);
    }
    if transport == WebSocketTransport::Http1 && !headers::is_websocket_upgrade(response.headers())
    {
        return error_response(
            StatusCode::BAD_GATEWAY,
            "Upstream returned an invalid WebSocket upgrade response",
        );
    }

    let version = response.version();
    let status = response.status();
    let headers = headers::response_headers(response.headers(), transport);
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
    *downstream.status_mut() = status;
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
