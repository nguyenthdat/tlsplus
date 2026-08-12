//! Direct profile-aware wreq transport for Rust clients.
//!
//! This is a thin Rust-only wrapper over the shared profile-aware wreq pool.
//! It bypasses the proxy server, forwarding layer, and UniFFI request records
//! without changing their implementation or Kotlin-facing API.

use std::{fmt, sync::Arc};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use thiserror::Error;
use wreq::{Request, Response};

use crate::transport::{WreqClient, get_passthrough_client, get_wreq_client};

const PASS_THROUGH_PROFILE: &str = "pass-through";

/// Errors produced while selecting or using a profile-aware HTTP client.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HttpClientError {
    /// The requested TLS fingerprint profile is not built in.
    #[error("unknown TLS profile '{profile}'")]
    UnknownProfile {
        /// Rejected profile name.
        profile: String,
    },

    /// The profile-specific wreq client could not be initialized.
    #[error("failed to initialize HTTP client for TLS profile '{profile}': {message}")]
    Initialization {
        /// Canonical TLS profile name.
        profile: String,
        /// Connector or cache failure.
        message: String,
    },

    /// wreq could not complete a direct request.
    #[error("HTTP request using TLS profile '{profile}' failed: {source}")]
    Request {
        /// Canonical TLS profile name.
        profile: String,
        /// wreq client error.
        #[source]
        source: wreq::Error,
    },
}

/// Reusable direct wreq client for one TLS fingerprint profile.
///
/// Cloning this handle is cheap and preserves the underlying connection pool.
#[derive(Clone)]
pub struct HttpClient {
    profile: Arc<str>,
    inner: Arc<WreqClient>,
}

impl HttpClient {
    /// Retrieves the shared wreq client for a built-in TLS profile.
    ///
    /// Profile matching is case-insensitive. The special `pass-through`
    /// profile uses wreq defaults without fingerprint overrides.
    pub fn for_profile(profile: &str) -> Result<Self, HttpClientError> {
        let canonical = canonical_profile(profile)?;
        let inner = if canonical == PASS_THROUGH_PROFILE {
            get_passthrough_client()
        } else {
            get_wreq_client(canonical)
        }
        .map_err(|message| HttpClientError::Initialization {
            profile: canonical.to_owned(),
            message,
        })?;

        Ok(Self {
            profile: Arc::from(canonical),
            inner,
        })
    }

    /// Returns the canonical TLS profile name used by this client.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Sends a buffered request directly through this profile's pool.
    ///
    /// The returned wreq response body remains streaming; higher-level clients
    /// may choose whether to stream or buffer it.
    pub async fn request(
        &self,
        request: hyper::Request<Full<Bytes>>,
    ) -> Result<Response, HttpClientError> {
        let (parts, body) = request.into_parts();
        let body = match body.collect().await {
            Ok(body) => body.to_bytes(),
            Err(never) => match never {},
        };
        let request = hyper::Request::from_parts(parts, body);
        let request: Request = request.into();
        self.inner
            .execute(request)
            .await
            .map_err(|source| HttpClientError::Request {
                profile: self.profile.to_string(),
                source,
            })
    }
}

impl fmt::Debug for HttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpClient")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

fn canonical_profile(profile: &str) -> Result<&'static str, HttpClientError> {
    let profile = profile.trim();
    if profile.eq_ignore_ascii_case(PASS_THROUGH_PROFILE) {
        return Ok(PASS_THROUGH_PROFILE);
    }

    crate::profiles::by_name(profile)
        .map(|profile| profile.name.as_str())
        .ok_or_else(|| HttpClientError::UnknownProfile {
            profile: profile.to_owned(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_clients_reuse_existing_profile_pool() {
        let first = HttpClient::for_profile("rustls_default").expect("build first client");
        let second = HttpClient::for_profile("rustls_default").expect("reuse cached client");
        assert!(Arc::ptr_eq(&first.inner, &second.inner));
    }

    #[test]
    fn direct_client_canonicalizes_and_validates_profile() {
        let client = HttpClient::for_profile("CHROME_120").expect("known profile");
        assert_eq!(client.profile(), "chrome_120");

        let error = HttpClient::for_profile("does-not-exist").expect_err("unknown profile");
        assert!(matches!(error, HttpClientError::UnknownProfile { .. }));
    }

    #[test]
    fn direct_pass_through_client_succeeds() {
        HttpClient::for_profile(PASS_THROUGH_PROFILE).expect("build pass-through client");
    }
}
