use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use serde::de::DeserializeOwned;
use url::Url;

use crate::{Error, Result};

/// Fully buffered HTTP response returned by [`crate::RequestBuilder::send`].
///
/// The current TLS+ core buffers direct-request responses. The async body
/// methods deliberately mirror reqwest's call shape so a future streaming core
/// can preserve source compatibility.
#[derive(Clone, Debug)]
pub struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    url: Url,
    profile: String,
}

impl Response {
    pub(crate) fn from_core(
        response: tlsplus_core::ProxyResponse,
        url: Url,
        profile: String,
    ) -> Result<Self> {
        let status = StatusCode::from_u16(response.status_code).map_err(|_| {
            Error::InvalidResponseStatus {
                status: response.status_code,
            }
        })?;
        let mut headers = HeaderMap::new();

        for raw in response.headers {
            let (name, value) =
                raw.split_once(':')
                    .ok_or_else(|| Error::InvalidResponseHeader {
                        header: raw.clone(),
                        reason: "missing ':' separator".to_owned(),
                    })?;
            let header_name = HeaderName::from_bytes(name.trim().as_bytes()).map_err(|error| {
                Error::InvalidResponseHeader {
                    header: raw.clone(),
                    reason: error.to_string(),
                }
            })?;
            let header_value = HeaderValue::from_str(value.trim()).map_err(|error| {
                Error::InvalidResponseHeader {
                    header: raw.clone(),
                    reason: error.to_string(),
                }
            })?;
            headers.append(header_name, header_value);
        }

        Ok(Self {
            status,
            headers,
            body: Bytes::from(response.body),
            url,
            profile,
        })
    }

    /// Returns the response status.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns the response headers.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns the final request URL.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Returns the TLS fingerprint profile used for the request.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Returns `true` for a 2xx status.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// Returns the buffered body length.
    #[must_use]
    pub fn content_length(&self) -> usize {
        self.body.len()
    }

    /// Returns a borrowed view of the buffered body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Converts 4xx and 5xx responses into [`Error::Status`].
    pub fn error_for_status(self) -> Result<Self> {
        self.error_for_status_ref()?;
        Ok(self)
    }

    /// Checks for a 4xx or 5xx status without consuming the response.
    pub fn error_for_status_ref(&self) -> Result<&Self> {
        if self.status.is_client_error() || self.status.is_server_error() {
            return Err(Error::Status {
                status: self.status,
                url: Box::new(self.url.clone()),
            });
        }
        Ok(self)
    }

    /// Consumes the response and returns its buffered bytes.
    pub async fn bytes(self) -> Result<Bytes> {
        Ok(self.body)
    }

    /// Consumes the response and decodes its body as UTF-8 text.
    pub async fn text(self) -> Result<String> {
        String::from_utf8(self.body.to_vec()).map_err(Error::TextDecode)
    }

    /// Consumes the response and deserializes its body as JSON.
    pub async fn json<T: DeserializeOwned>(self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(Error::JsonDecode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16, body: &[u8]) -> Response {
        Response::from_core(
            tlsplus_core::ProxyResponse {
                id: "test".to_owned(),
                status_code: status,
                headers: vec!["Content-Type: application/json".to_owned()],
                body: body.to_vec(),
                ja4: None,
                error: None,
            },
            Url::parse("https://example.com/").expect("static URL is valid"),
            "pass-through".to_owned(),
        )
        .expect("test response is valid")
    }

    #[test]
    fn error_for_status_only_rejects_4xx_and_5xx() {
        assert!(response(302, b"").error_for_status().is_ok());

        let error = response(404, b"")
            .error_for_status()
            .expect_err("404 should be rejected");
        assert_eq!(error.status(), Some(StatusCode::NOT_FOUND));
        assert!(error.is_status());
    }

    #[tokio::test]
    async fn body_decoders_use_buffered_body() {
        let value: serde_json::Value = response(200, br#"{"ok":true}"#)
            .json()
            .await
            .expect("valid JSON");
        assert_eq!(value["ok"], true);

        let text = response(200, b"hello").text().await.expect("valid UTF-8");
        assert_eq!(text, "hello");
    }
}
