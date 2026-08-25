use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri, Version, body::Incoming};
use tokio::sync::mpsc;

use super::websocket::{BridgeJob, UpgradeRequest};

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub(crate) type ServerBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeclaredHttpVersion {
    Absent,
    Http2,
    Invalid,
}

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
    let declared_version = match declared_http_version(request.headers()) {
        DeclaredHttpVersion::Absent => None,
        DeclaredHttpVersion::Http2 => Some(Version::HTTP_2),
        DeclaredHttpVersion::Invalid => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Invalid X-Tlsplus-Http-Version header",
            ));
        }
    };
    let wire_version = request.version();
    let upgrade = super::websocket::classify(&request);
    let tunnel_requires_matching_version =
        request.method() == Method::CONNECT || !matches!(&upgrade, UpgradeRequest::None);
    if tunnel_requires_matching_version
        && declared_version.is_some_and(|version| version != wire_version)
    {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "HTTP version changed between Burp and the TLS+ proxy",
        ));
    }

    match upgrade {
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
    let target = match internal_header(&parts.headers, "x-tlsplus-target") {
        Ok(Some(target)) if !target.is_empty() => target.to_owned(),
        Ok(_) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Missing X-Tlsplus-Target header",
            ));
        }
        Err(message) => return Ok(error_response(StatusCode::BAD_REQUEST, message)),
    };

    let profile = match internal_header(&parts.headers, "x-tlsplus-profile") {
        Ok(Some(profile)) if !profile.is_empty() => profile.to_owned(),
        Ok(_) => "pass-through".to_owned(),
        Err(message) => return Ok(error_response(StatusCode::BAD_REQUEST, message)),
    };
    let timeout_secs = match internal_header(&parts.headers, "x-tlsplus-timeout") {
        Ok(Some(value)) => match value.parse::<u64>() {
            Ok(value) => value,
            Err(_) => {
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    "Invalid X-Tlsplus-Timeout header",
                ));
            }
        },
        Ok(None) => 30,
        Err(message) => return Ok(error_response(StatusCode::BAD_REQUEST, message)),
    };
    let uri = match target.parse::<Uri>() {
        Ok(uri)
            if matches!(uri.scheme_str(), Some("http" | "https")) && uri.authority().is_some() =>
        {
            uri
        }
        Ok(_) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "X-Tlsplus-Target must be an absolute HTTP(S) URL",
            ));
        }
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

    let outbound_version = outbound_http_version(declared_version, parts.version);
    let outbound = client
        .request(parts.method, uri)
        .version(outbound_version)
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

fn outbound_http_version(declared: Option<Version>, wire: Version) -> Version {
    declared.unwrap_or(wire)
}

fn internal_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, &'static str> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err("Duplicate X-Tlsplus metadata header");
    }

    value
        .to_str()
        .map(Some)
        .map_err(|_| "Invalid X-Tlsplus metadata header encoding")
}

fn declared_http_version(headers: &HeaderMap) -> DeclaredHttpVersion {
    let mut values = headers.get_all("x-tlsplus-http-version").iter();
    let Some(value) = values.next() else {
        return DeclaredHttpVersion::Absent;
    };
    if values.next().is_some() {
        return DeclaredHttpVersion::Invalid;
    }

    match value.to_str() {
        Ok(version) if version.eq_ignore_ascii_case("HTTP/2") => DeclaredHttpVersion::Http2,
        Ok(_) | Err(_) => DeclaredHttpVersion::Invalid,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_http2_version_wins_over_an_http1_proxy_hop() {
        assert_eq!(
            outbound_http_version(Some(Version::HTTP_2), Version::HTTP_11),
            Version::HTTP_2
        );
    }

    #[test]
    fn absent_version_marker_preserves_the_wire_version() {
        assert_eq!(
            outbound_http_version(None, Version::HTTP_11),
            Version::HTTP_11
        );
        assert_eq!(
            outbound_http_version(None, Version::HTTP_2),
            Version::HTTP_2
        );
    }

    #[test]
    fn internal_headers_reject_duplicates_and_non_text_values() {
        let mut duplicates = HeaderMap::new();
        duplicates.append("x-tlsplus-target", "https://example.com".parse().unwrap());
        duplicates.append(
            "x-tlsplus-target",
            "https://other.example.com".parse().unwrap(),
        );
        assert!(internal_header(&duplicates, "x-tlsplus-target").is_err());

        let mut invalid = HeaderMap::new();
        invalid.insert(
            "x-tlsplus-target",
            hyper::header::HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        assert!(internal_header(&invalid, "x-tlsplus-target").is_err());
    }
}
