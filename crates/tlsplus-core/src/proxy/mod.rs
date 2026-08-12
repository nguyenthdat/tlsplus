//! Embedded HTTP forward proxy (tokio + hyper + BoringSSL) with per-profile
//! TLS fingerprint spoofing and connection pooling.
//!
//! Provides:
//! - A raw hyper HTTP/1 server that accepts any HTTP request and forwards it to
//!   the real destination using a profile-specific hyper client. Request and
//!   response bodies are streamed without buffering. Header case is preserved.
//! - A synchronous `proxy_send_request_impl` that bypasses the local server and
//!   directly forwards a request through the cached per-profile client.
//! - Per-profile hyper `Client` caching with connection pooling, HTTP/2
//!   support, request-level timeouts, and retry logic for transient errors.
//! - Chrome-accurate TLS fingerprint spoofing via BoringSSL (GREASE, extension
//!   permutation, full cipher suite control).

use std::sync::LazyLock;

pub(crate) mod client;
#[cfg(test)]
mod diagnostics;
pub(crate) mod forward;
pub(crate) mod server;

// Re-export public API
pub use server::{
    proxy_send_request_async_impl, proxy_send_request_impl, server_status_impl,
    start_local_server_impl, stop_local_server_impl,
};

// ---------------------------------------------------------------------------
// Global async runtime — created lazily on first access
// ---------------------------------------------------------------------------

/// Shared Tokio runtime for the proxy server and `proxy_send_request`.
pub(crate) static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime")
});
