use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use http::{HeaderMap, HeaderName, HeaderValue, Method, header::CONTENT_TYPE};
use serde::Serialize;
use url::Url;

use crate::{Error, Response, Result};

const DEFAULT_PROFILE: &str = "pass-through";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
struct ClientConfig {
    profile: String,
    timeout: Duration,
    default_headers: HeaderMap,
}

/// Reusable asynchronous HTTP client backed by TLS+ profiles.
///
/// Cloning a client is cheap and preserves its connection-pool identity inside
/// `tlsplus-core`.
#[derive(Clone, Debug)]
pub struct Client {
    config: Arc<ClientConfig>,
}

impl Client {
    /// Creates a client using the `pass-through` TLS profile and a 30-second
    /// total request timeout.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts a configurable client builder.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Creates a client for one TLS fingerprint profile.
    pub fn with_profile(profile: impl Into<String>) -> Result<Self> {
        Self::builder().profile(profile).build()
    }

    /// Starts an arbitrary-method request.
    pub fn request(&self, method: Method, url: impl Into<String>) -> RequestBuilder {
        RequestBuilder::new(self.clone(), method, url.into())
    }

    /// Starts a GET request.
    pub fn get(&self, url: impl Into<String>) -> RequestBuilder {
        self.request(Method::GET, url)
    }

    /// Starts a POST request.
    pub fn post(&self, url: impl Into<String>) -> RequestBuilder {
        self.request(Method::POST, url)
    }

    /// Starts a PUT request.
    pub fn put(&self, url: impl Into<String>) -> RequestBuilder {
        self.request(Method::PUT, url)
    }

    /// Starts a PATCH request.
    pub fn patch(&self, url: impl Into<String>) -> RequestBuilder {
        self.request(Method::PATCH, url)
    }

    /// Starts a DELETE request.
    pub fn delete(&self, url: impl Into<String>) -> RequestBuilder {
        self.request(Method::DELETE, url)
    }

    /// Starts a HEAD request.
    pub fn head(&self, url: impl Into<String>) -> RequestBuilder {
        self.request(Method::HEAD, url)
    }
}

impl Default for Client {
    fn default() -> Self {
        Self {
            config: Arc::new(ClientConfig {
                profile: DEFAULT_PROFILE.to_owned(),
                timeout: DEFAULT_TIMEOUT,
                default_headers: HeaderMap::new(),
            }),
        }
    }
}

/// Builder for reusable [`Client`] configuration.
#[derive(Debug)]
#[must_use = "a ClientBuilder does nothing until build() is called"]
pub struct ClientBuilder {
    profile: String,
    timeout: Duration,
    default_headers: HeaderMap,
    error: Option<Error>,
}

impl ClientBuilder {
    /// Creates a builder with pass-through TLS and a 30-second timeout.
    pub fn new() -> Self {
        Self {
            profile: DEFAULT_PROFILE.to_owned(),
            timeout: DEFAULT_TIMEOUT,
            default_headers: HeaderMap::new(),
            error: None,
        }
    }

    /// Selects a built-in TLS fingerprint profile.
    pub fn profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = profile.into();
        self
    }

    /// Sets the total timeout applied to each request.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Replaces all default headers.
    pub fn default_headers(mut self, headers: HeaderMap) -> Self {
        self.default_headers = headers;
        self
    }

    /// Adds one default header.
    pub fn default_header(mut self, name: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        if self.error.is_none()
            && let Err(error) =
                append_header(&mut self.default_headers, name.as_ref(), value.as_ref())
        {
            self.error = Some(error);
        }
        self
    }

    /// Validates the configuration and creates a reusable client.
    pub fn build(self) -> Result<Client> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if self.timeout.is_zero() {
            return Err(Error::InvalidTimeout);
        }
        validate_header_map(&self.default_headers)?;

        Ok(Client {
            config: Arc::new(ClientConfig {
                profile: canonical_profile(&self.profile)?,
                timeout: self.timeout,
                default_headers: self.default_headers,
            }),
        })
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Fluent request builder similar to `reqwest::RequestBuilder`.
#[derive(Debug)]
#[must_use = "a RequestBuilder does nothing until send() is awaited"]
pub struct RequestBuilder {
    client: Client,
    method: Method,
    url: String,
    headers: HeaderMap,
    body: Vec<u8>,
    profile: Option<String>,
    timeout: Option<Duration>,
    error: Option<Error>,
}

#[derive(Debug)]
struct PreparedRequest {
    core_request: tlsplus_core::ProxyRequest,
    url: Url,
    profile: String,
    timeout: Duration,
}

impl RequestBuilder {
    fn new(client: Client, method: Method, url: String) -> Self {
        Self {
            client,
            method,
            url,
            headers: HeaderMap::new(),
            body: Vec::new(),
            profile: None,
            timeout: None,
            error: None,
        }
    }

    /// Adds one request header. Repeating a name appends another value.
    pub fn header(mut self, name: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        if self.error.is_none()
            && let Err(error) = append_header(&mut self.headers, name.as_ref(), value.as_ref())
        {
            self.error = Some(error);
        }
        self
    }

    /// Merges a header map into this request, replacing values with matching
    /// names while preserving unrelated headers.
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        replace_headers(&mut self.headers, headers);
        self
    }

    /// Sets a fully buffered request body.
    pub fn body(mut self, body: impl AsRef<[u8]>) -> Self {
        self.body = body.as_ref().to_vec();
        self
    }

    /// Serializes a JSON body and sets `Content-Type: application/json` when
    /// that header is not already present.
    pub fn json<T: Serialize + ?Sized>(mut self, value: &T) -> Self {
        if self.error.is_some() {
            return self;
        }

        match serde_json::to_vec(value) {
            Ok(body) => {
                self.body = body;
                if !self.headers.contains_key(CONTENT_TYPE) {
                    self.headers
                        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                }
            }
            Err(error) => self.error = Some(Error::JsonEncode(error)),
        }
        self
    }

    /// Serializes and appends query parameters to the URL.
    pub fn query<T: Serialize + ?Sized>(mut self, query: &T) -> Self {
        if self.error.is_some() {
            return self;
        }

        let encoded = match serde_urlencoded::to_string(query) {
            Ok(encoded) => encoded,
            Err(error) => {
                self.error = Some(Error::QueryEncode(error));
                return self;
            }
        };
        if encoded.is_empty() {
            return self;
        }

        match normalize_url(&self.url) {
            Ok(mut url) => {
                let combined = match url.query() {
                    Some(existing) if !existing.is_empty() => format!("{existing}&{encoded}"),
                    _ => encoded,
                };
                url.set_query(Some(&combined));
                self.url = url.into();
            }
            Err(error) => self.error = Some(error),
        }
        self
    }

    /// Overrides the client's TLS profile for this request.
    pub fn profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Overrides the client's total timeout for this request.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sends the request asynchronously through `tlsplus-core`.
    pub async fn send(self) -> Result<Response> {
        let prepared = self.prepare()?;
        let core_response = tokio::time::timeout(
            prepared.timeout,
            tlsplus_core::proxy_send_request_async(prepared.core_request),
        )
        .await
        .map_err(|_| Error::Timeout {
            url: Box::new(prepared.url.clone()),
            timeout: prepared.timeout,
        })?;

        if let Some(message) = core_response.error {
            return Err(Error::Request {
                url: Box::new(prepared.url),
                profile: prepared.profile,
                message,
            });
        }

        Response::from_core(core_response, prepared.url, prepared.profile)
    }

    fn prepare(self) -> Result<PreparedRequest> {
        if let Some(error) = self.error {
            return Err(error);
        }

        let url = normalize_url(&self.url)?;
        let profile = canonical_profile(
            self.profile
                .as_deref()
                .unwrap_or(self.client.config.profile.as_str()),
        )?;
        let timeout = self.timeout.unwrap_or(self.client.config.timeout);
        if timeout.is_zero() {
            return Err(Error::InvalidTimeout);
        }

        let mut headers = self.client.config.default_headers.clone();
        replace_headers(&mut headers, self.headers);
        let headers = header_strings(&headers)?;
        let timeout_secs = duration_to_core_seconds(timeout);
        let request_number = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);

        Ok(PreparedRequest {
            core_request: tlsplus_core::ProxyRequest {
                id: format!("tlsplus-client-{request_number}"),
                method: self.method.as_str().to_owned(),
                url: url.as_str().to_owned(),
                headers,
                body: self.body,
                profile: profile.clone(),
                timeout_secs,
            },
            url,
            profile,
            timeout,
        })
    }
}

fn normalize_url(input: &str) -> Result<Url> {
    let url = Url::parse(input).map_err(|error| Error::InvalidUrl {
        input: input.to_owned(),
        reason: error.to_string(),
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::UnsupportedUrlScheme {
            scheme: url.scheme().to_owned(),
        });
    }
    if url.host_str().is_none() {
        return Err(Error::InvalidUrl {
            input: input.to_owned(),
            reason: "URL must include a host".to_owned(),
        });
    }
    Ok(url)
}

fn canonical_profile(input: &str) -> Result<String> {
    let profile = input.trim();
    if profile.eq_ignore_ascii_case(DEFAULT_PROFILE) {
        return Ok(DEFAULT_PROFILE.to_owned());
    }

    tlsplus_core::get_tls_profile(profile.to_owned())
        .map(|info| info.name)
        .ok_or_else(|| Error::UnknownProfile {
            profile: profile.to_owned(),
        })
}

fn append_header(headers: &mut HeaderMap, name: &str, value: &str) -> Result<()> {
    let header_name =
        HeaderName::from_bytes(name.as_bytes()).map_err(|error| Error::InvalidHeader {
            name: name.to_owned(),
            reason: error.to_string(),
        })?;
    let header_value = HeaderValue::from_str(value).map_err(|error| Error::InvalidHeader {
        name: name.to_owned(),
        reason: error.to_string(),
    })?;
    headers.append(header_name, header_value);
    Ok(())
}

fn replace_headers(destination: &mut HeaderMap, source: HeaderMap) {
    for name in source.keys() {
        destination.remove(name);
    }
    for (name, value) in &source {
        destination.append(name.clone(), value.clone());
    }
}

fn validate_header_map(headers: &HeaderMap) -> Result<()> {
    for (name, value) in headers {
        value.to_str().map_err(|error| Error::InvalidHeader {
            name: name.as_str().to_owned(),
            reason: error.to_string(),
        })?;
    }
    Ok(())
}

fn header_strings(headers: &HeaderMap) -> Result<Vec<String>> {
    validate_header_map(headers)?;
    headers
        .iter()
        .map(|(name, value)| {
            value
                .to_str()
                .map(|value| format!("{}: {value}", name.as_str()))
                .map_err(|error| Error::InvalidHeader {
                    name: name.as_str().to_owned(),
                    reason: error.to_string(),
                })
        })
        .collect()
}

fn duration_to_core_seconds(timeout: Duration) -> u32 {
    let rounded_up = timeout
        .as_secs()
        .saturating_add(u64::from(timeout.subsec_nanos() > 0));
    u32::try_from(rounded_up).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_builder_validates_and_canonicalizes_profile() {
        let client = Client::builder()
            .profile("CHROME_120")
            .build()
            .expect("known profile");
        assert_eq!(client.config.profile, "chrome_120");

        let error = Client::builder()
            .profile("does-not-exist")
            .build()
            .expect_err("unknown profile should fail");
        assert!(matches!(error, Error::UnknownProfile { .. }));
    }

    #[test]
    fn zero_timeout_is_rejected() {
        let error = Client::builder()
            .timeout(Duration::ZERO)
            .build()
            .expect_err("zero timeout should fail");
        assert!(matches!(error, Error::InvalidTimeout));
    }

    #[test]
    fn request_preparation_merges_query_headers_json_and_profile() {
        let client = Client::builder()
            .profile("pass-through")
            .default_header("x-source", "default")
            .build()
            .expect("valid client");
        let prepared = client
            .post("https://example.com/api?existing=1")
            .query(&[("next", "two words")])
            .header("x-source", "request")
            .json(&serde_json::json!({"ok": true}))
            .profile("chrome_120")
            .timeout(Duration::from_millis(1500))
            .prepare()
            .expect("valid request");

        assert_eq!(prepared.profile, "chrome_120");
        assert_eq!(prepared.timeout, Duration::from_millis(1500));
        assert_eq!(prepared.core_request.timeout_secs, 2);
        assert!(
            prepared
                .core_request
                .url
                .contains("existing=1&next=two+words")
        );
        assert!(
            prepared
                .core_request
                .headers
                .contains(&"x-source: request".to_owned())
        );
        assert!(
            prepared
                .core_request
                .headers
                .contains(&"content-type: application/json".to_owned())
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&prepared.core_request.body)
                .expect("JSON body"),
            serde_json::json!({"ok": true})
        );
    }

    #[test]
    fn request_rejects_non_http_urls_before_sending() {
        let error = Client::new()
            .get("file:///tmp/data")
            .prepare()
            .expect_err("file URLs must be rejected");
        assert!(matches!(error, Error::UnsupportedUrlScheme { .. }));
    }
}
