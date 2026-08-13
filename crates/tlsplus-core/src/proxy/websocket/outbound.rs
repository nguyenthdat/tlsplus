use hyper::{HeaderMap, Method, StatusCode, Uri, Version};

use super::WebSocketTransport;

pub(super) async fn send(
    client: &wreq::Client,
    transport: WebSocketTransport,
    uri: Uri,
    headers: HeaderMap,
) -> Result<wreq::Response, wreq::Error> {
    let (method, version) = match transport {
        WebSocketTransport::Http1 => (Method::GET, Version::HTTP_11),
        WebSocketTransport::Http2 => (Method::CONNECT, Version::HTTP_2),
    };
    let mut request = client
        .request(method, uri)
        .version(version)
        .headers(headers)
        .build()?;
    if transport == WebSocketTransport::Http2 {
        request
            .extensions_mut()
            .insert(http2::ext::Protocol::from_static("websocket"));
    }
    client.execute(request).await
}

pub(super) fn is_success(response: &wreq::Response, transport: WebSocketTransport) -> bool {
    match transport {
        WebSocketTransport::Http1 => {
            response.version() == Version::HTTP_11
                && response.status() == StatusCode::SWITCHING_PROTOCOLS
        }
        WebSocketTransport::Http2 => {
            response.version() == Version::HTTP_2 && response.status().is_success()
        }
    }
}
