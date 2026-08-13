//! Embedded HTTP forward proxy with per-profile wreq clients and pooling.
//!
//! Provides:
//! - A raw hyper HTTP/1 server that accepts any HTTP request and forwards it to
//!   the real destination using a profile-specific wreq client.
//! - A synchronous `proxy_send_request_impl` that bypasses the local server and
//!   directly forwards a request through the cached per-profile client.
//! - Per-profile wreq client caching with connection pooling, HTTP/2 support,
//!   request-level timeouts, and buffered retry logic.

use std::sync::LazyLock;

pub(crate) mod forward;
pub(crate) mod server;
pub(crate) mod service;
pub(crate) mod websocket;

// Re-export public API
pub use server::{
    proxy_send_request_async_impl, proxy_send_request_impl, server_status_impl,
    start_local_server_impl, stop_local_server_impl,
};

// ---------------------------------------------------------------------------
// Global async runtime — created lazily on first access
// ---------------------------------------------------------------------------

/// Shared Tokio runtime for the proxy server and `proxy_send_request`.
pub(crate) static RUNTIME: LazyLock<Result<tokio::runtime::Runtime, String>> =
    LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .map_err(|error| format!("Failed to create Tokio runtime: {error}"))
    });
