use std::{string::FromUtf8Error, time::Duration};

use http::StatusCode;
use thiserror::Error;
use url::Url;

/// Error returned while building, sending, or decoding an HTTP request.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The supplied URL is not a valid absolute HTTP(S) URL.
    #[error("invalid URL '{input}': {reason}")]
    InvalidUrl {
        /// Original URL input.
        input: String,
        /// Validation failure.
        reason: String,
    },

    /// The URL uses a scheme other than HTTP or HTTPS.
    #[error("unsupported URL scheme '{scheme}'; expected http or https")]
    UnsupportedUrlScheme {
        /// Unsupported scheme.
        scheme: String,
    },

    /// The selected TLS fingerprint profile does not exist.
    #[error("unknown TLS profile '{profile}'")]
    UnknownProfile {
        /// Rejected profile name.
        profile: String,
    },

    /// A zero-length timeout was configured.
    #[error("request timeout must be greater than zero")]
    InvalidTimeout,

    /// A request header name or value is invalid for the core string boundary.
    #[error("invalid header '{name}': {reason}")]
    InvalidHeader {
        /// Header name, or the unparsed name when name validation failed.
        name: String,
        /// Validation failure.
        reason: String,
    },

    /// JSON request serialization failed.
    #[error("failed to serialize JSON request body: {0}")]
    JsonEncode(#[source] serde_json::Error),

    /// Query-string serialization failed.
    #[error("failed to serialize query parameters: {0}")]
    QueryEncode(#[source] serde_urlencoded::ser::Error),

    /// The request exceeded its configured total timeout.
    #[error("request to {url} timed out after {timeout:?}")]
    Timeout {
        /// Target URL.
        url: Box<Url>,
        /// Configured timeout.
        timeout: Duration,
    },

    /// The TLS+ core could not complete the request.
    #[error("request to {url} with profile '{profile}' failed: {message}")]
    Request {
        /// Target URL.
        url: Box<Url>,
        /// Canonical TLS profile name.
        profile: String,
        /// Error reported by the core.
        message: String,
    },

    /// The core returned an invalid HTTP status code.
    #[error("core returned invalid HTTP status code {status}")]
    InvalidResponseStatus {
        /// Invalid numeric status.
        status: u16,
    },

    /// The core returned a malformed response header.
    #[error("core returned malformed response header '{header}': {reason}")]
    InvalidResponseHeader {
        /// Raw header line.
        header: String,
        /// Parse failure.
        reason: String,
    },

    /// The response status is a client or server error.
    #[error("HTTP status {status} for {url}")]
    Status {
        /// Error status.
        status: StatusCode,
        /// Target URL.
        url: Box<Url>,
    },

    /// The response body is not valid UTF-8.
    #[error("response body is not valid UTF-8: {0}")]
    TextDecode(#[source] FromUtf8Error),

    /// JSON response deserialization failed.
    #[error("failed to deserialize JSON response body: {0}")]
    JsonDecode(#[source] serde_json::Error),
}

impl Error {
    /// Returns the HTTP status attached to this error, when present.
    #[must_use]
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Status { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Returns the target URL attached to this error, when present.
    #[must_use]
    pub fn url(&self) -> Option<&Url> {
        match self {
            Self::Timeout { url, .. } | Self::Request { url, .. } | Self::Status { url, .. } => {
                Some(url.as_ref())
            }
            _ => None,
        }
    }

    /// Returns `true` when this error was caused by the configured timeout.
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout { .. })
    }

    /// Returns `true` for errors produced by [`crate::Response::error_for_status`].
    #[must_use]
    pub fn is_status(&self) -> bool {
        matches!(self, Self::Status { .. })
    }
}

/// Result type used by `tlsplus-client`.
pub type Result<T> = std::result::Result<T, Error>;
