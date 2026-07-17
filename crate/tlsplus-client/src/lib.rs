//! Ergonomic asynchronous HTTP client for TLS+ fingerprint profiles.
//!
//! `tlsplus-client` keeps Hyper and BoringSSL details inside `tlsplus-core` and
//! provides a request-builder API familiar to reqwest users.
//!
//! # Quick start
//!
//! ```no_run
//! # async fn example() -> Result<(), tlsplus_client::Error> {
//! let response = tlsplus_client::get("https://example.com")
//!     .profile("chrome_149")
//!     .header("accept", "text/html")
//!     .send()
//!     .await?
//!     .error_for_status()?;
//!
//! println!("{}", response.text().await?);
//! # Ok(())
//! # }
//! ```
//!
//! Reuse a [`Client`] when making multiple requests so the core can reuse its
//! per-profile connection pools.

#![forbid(unsafe_code)]

mod client;
mod error;
mod response;

pub use bytes::Bytes;
pub use client::{Client, ClientBuilder, RequestBuilder};
pub use error::{Error, Result};
pub use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
pub use response::Response;
pub use url::Url;

/// Starts an arbitrary-method request using the default pass-through client.
pub fn request(method: Method, url: impl Into<String>) -> RequestBuilder {
    Client::new().request(method, url)
}

/// Starts a GET request using the default pass-through client.
pub fn get(url: impl Into<String>) -> RequestBuilder {
    Client::new().get(url)
}

/// Starts a POST request using the default pass-through client.
pub fn post(url: impl Into<String>) -> RequestBuilder {
    Client::new().post(url)
}

/// Starts a PUT request using the default pass-through client.
pub fn put(url: impl Into<String>) -> RequestBuilder {
    Client::new().put(url)
}

/// Starts a PATCH request using the default pass-through client.
pub fn patch(url: impl Into<String>) -> RequestBuilder {
    Client::new().patch(url)
}

/// Starts a DELETE request using the default pass-through client.
pub fn delete(url: impl Into<String>) -> RequestBuilder {
    Client::new().delete(url)
}

/// Starts a HEAD request using the default pass-through client.
pub fn head(url: impl Into<String>) -> RequestBuilder {
    Client::new().head(url)
}
