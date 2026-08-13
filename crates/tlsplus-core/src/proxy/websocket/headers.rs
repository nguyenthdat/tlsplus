use hyper::{
    HeaderMap, Uri,
    header::{
        CONNECTION, CONTENT_LENGTH, HOST, HeaderName, HeaderValue, TRANSFER_ENCODING, UPGRADE,
    },
};

use super::WebSocketTransport;

pub(super) fn normalize_target(target: &str) -> Result<Uri, String> {
    let (scheme, remainder) = target
        .split_once("://")
        .ok_or_else(|| format!("Invalid target URL '{target}': missing scheme"))?;
    let transport_scheme = match scheme.to_ascii_lowercase().as_str() {
        "http" | "ws" => "http",
        "https" | "wss" => "https",
        _ => return Err(format!("Unsupported WebSocket target scheme '{scheme}'")),
    };

    format!("{transport_scheme}://{remainder}")
        .parse()
        .map_err(|error| format!("Invalid target URL '{target}': {error}"))
}

pub(super) fn contains_token(headers: &HeaderMap, name: HeaderName, expected: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
    })
}

pub(super) fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    contains_token(headers, CONNECTION, "upgrade") && contains_token(headers, UPGRADE, "websocket")
}

fn connection_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

pub(super) fn request_headers(source: &HeaderMap, transport: WebSocketTransport) -> HeaderMap {
    let nominated = connection_tokens(source);
    let mut headers = source
        .iter()
        .filter(|(name, _)| {
            let name = name.as_str();
            !name.starts_with("x-tlsplus-")
                && name != HOST
                && name != CONNECTION
                && name != UPGRADE
                && !matches!(
                    name,
                    "proxy-connection"
                        | "proxy-authorization"
                        | "proxy-authenticate"
                        | "keep-alive"
                        | "te"
                        | "trailer"
                        | "transfer-encoding"
                )
                && !nominated.iter().any(|token| token == name)
        })
        .fold(HeaderMap::new(), |mut headers, (name, value)| {
            headers.append(name.clone(), value.clone());
            headers
        });
    if transport == WebSocketTransport::Http1 {
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    }
    headers
}

pub(super) fn response_headers(source: &HeaderMap, transport: WebSocketTransport) -> HeaderMap {
    let nominated = connection_tokens(source);
    let mut headers = source
        .iter()
        .filter(|(name, _)| {
            let name = name.as_str();
            name != CONNECTION
                && name != UPGRADE
                && name != CONTENT_LENGTH
                && name != TRANSFER_ENCODING
                && !matches!(
                    name,
                    "proxy-connection" | "proxy-authorization" | "proxy-authenticate"
                )
                && !nominated.iter().any(|token| token == name)
        })
        .fold(HeaderMap::new(), |mut headers, (name, value)| {
            headers.append(name.clone(), value.clone());
            headers
        });
    if transport == WebSocketTransport::Http1 {
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    }
    headers
}
