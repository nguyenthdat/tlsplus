//! Direct Hyper/BoringSSL transport for Rust clients.
//!
//! This is a thin Rust-only wrapper over the existing profile-aware Hyper pool.
//! It bypasses the proxy server, forwarding layer, and UniFFI request records
//! without changing their implementation or Kotlin-facing API.

use std::{convert::Infallible, fmt, sync::Arc};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming};
use thiserror::Error;

use crate::proxy::client::{ProfileClient, ProxyBody, get_client, get_passthrough_client};

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

    /// The profile-specific Hyper/BoringSSL client could not be initialized.
    #[error("failed to initialize HTTP client for TLS profile '{profile}': {message}")]
    Initialization {
        /// Canonical TLS profile name.
        profile: String,
        /// Connector or cache failure.
        message: String,
    },

    /// Hyper could not complete a direct request.
    #[error("HTTP request using TLS profile '{profile}' failed: {source}")]
    Request {
        /// Canonical TLS profile name.
        profile: String,
        /// Hyper client error.
        #[source]
        source: hyper_util::client::legacy::Error,
    },
}

/// Reusable direct Hyper client for one TLS fingerprint profile.
///
/// Cloning this handle is cheap and preserves the underlying connection pool.
#[derive(Clone)]
pub struct HttpClient {
    profile: Arc<str>,
    inner: Arc<ProfileClient>,
}

impl HttpClient {
    /// Retrieves the shared Hyper client for a built-in TLS profile.
    ///
    /// Profile matching is case-insensitive. The special `pass-through`
    /// profile uses Hyper/BoringSSL defaults without fingerprint overrides.
    pub fn for_profile(profile: &str) -> Result<Self, HttpClientError> {
        let canonical = canonical_profile(profile)?;
        let inner = if canonical == PASS_THROUGH_PROFILE {
            get_passthrough_client()
        } else {
            get_client(canonical)
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

    /// Sends a buffered Hyper request directly through this profile's pool.
    ///
    /// The returned [`Incoming`] body remains streaming; higher-level clients
    /// may choose whether to stream or buffer it.
    pub async fn request(
        &self,
        request: Request<Full<Bytes>>,
    ) -> Result<Response<Incoming>, HttpClientError> {
        let request = request.map(boxed_full_body);
        self.inner
            .request(request)
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

fn boxed_full_body(body: Full<Bytes>) -> ProxyBody {
    body.map_err(|never: Infallible| match never {}).boxed()
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
