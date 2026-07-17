//! Per-profile hyper client cache with BoringSSL TLS configuration.
//!
//! Manages `ProfileClient` instances keyed by profile name, building each
//! once and reusing across requests. Also provides a default "pass-through"
//! client with stock BoringSSL settings.

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};

use boring::ssl::{SslConnector, SslMethod};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper_boring::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::tls;

// ---------------------------------------------------------------------------
// Per-profile client type alias
// ---------------------------------------------------------------------------

/// Streaming-capable body type for both buffered and streamed requests.
pub(crate) type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// A hyper HTTP client using BoringSSL for TLS, accepting streaming bodies.
pub(crate) type ProfileClient = Client<HttpsConnector<HttpConnector>, ProxyBody>;

// ---------------------------------------------------------------------------
// Per-profile client cache
// ---------------------------------------------------------------------------

/// Cached clients keyed by profile name. Built once, reused across requests.
pub(crate) static PROFILE_CLIENTS: LazyLock<Mutex<HashMap<String, Arc<ProfileClient>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Retrieve or build a hyper `Client` for the given profile name.
///
/// Clients are cached indefinitely — profile changes require a restart.
pub(crate) fn get_client(profile_name: &str) -> Result<Arc<ProfileClient>, String> {
    let mut cache = PROFILE_CLIENTS
        .lock()
        .map_err(|e| format!("Profile client cache lock poisoned: {e}"))?;

    if let Some(client) = cache.get(profile_name) {
        return Ok(Arc::clone(client));
    }

    let client = build_client(profile_name)?;
    cache.insert(profile_name.to_owned(), Arc::clone(&client));
    Ok(client)
}

/// Retrieve or build the pass-through client with default BoringSSL TLS.
pub(crate) fn get_passthrough_client() -> Result<Arc<ProfileClient>, String> {
    let mut cache = PROFILE_CLIENTS
        .lock()
        .map_err(|e| format!("Profile client cache lock poisoned: {e}"))?;

    if let Some(c) = cache.get("pass-through") {
        return Ok(Arc::clone(c));
    }

    let c = build_passthrough_client()?;
    cache.insert("pass-through".to_owned(), Arc::clone(&c));
    Ok(c)
}

/// Build a new hyper `Client` with custom BoringSSL TLS configuration for the
/// given profile.
fn build_client(profile_name: &str) -> Result<Arc<ProfileClient>, String> {
    let profile = crate::profiles::by_name(profile_name).unwrap_or_else(|| {
        eprintln!(
            "tlsplus: unknown profile '{}', falling back to rustls_default",
            profile_name
        );
        crate::profiles::by_name("rustls_default").unwrap()
    });

    let mut ssl_builder = SslConnector::builder(SslMethod::tls())
        .map_err(|e| format!("Failed to create SslConnector builder: {e}"))?;

    // Apply profile settings via deref to SslContextBuilder
    tls::configure_context(&mut ssl_builder, profile)?;

    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_connect_timeout(Some(Duration::from_secs(10)));
    http.set_nodelay(true);

    let https = HttpsConnector::with_connector(http, ssl_builder).map_err(|e| {
        format!("Failed to create HTTPS connector for profile '{profile_name}': {e}")
    })?;

    // ── Chrome-matching HTTP/2 SETTINGS frame ──
    // Real Chrome 149 sends specific HTTP/2 settings. Matching these makes the
    // HTTP/2 fingerprint (Akamai hash) align with the TLS fingerprint, avoiding
    // bot detection that cross-checks both layers (e.g. Google).
    //
    // Chrome 149 HTTP/2 SETTINGS:
    //   SETTINGS_INITIAL_WINDOW_SIZE (4) = 6291456
    //   SETTINGS_MAX_HEADER_LIST_SIZE (6) = 262144
    //   Initial connection window = 15_631_505 (Chrome 149 observed)
    //     = 65535 (default) + 15_565_970 (WINDOW_UPDATE increment)
    let client: ProfileClient = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(32)
        .pool_idle_timeout(Duration::from_secs(90))
        .http2_initial_stream_window_size(6_291_456)
        .http2_initial_connection_window_size(15_631_505)
        .http2_max_header_list_size(262_144)
        .http2_adaptive_window(false)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .build(https);

    Ok(Arc::new(client))
}

/// Build a pass-through client with default BoringSSL TLS (no custom profile).
fn build_passthrough_client() -> Result<Arc<ProfileClient>, String> {
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_connect_timeout(Some(Duration::from_secs(10)));
    http.set_nodelay(true);

    let https = HttpsConnector::new()
        .map_err(|e| format!("Failed to create default HTTPS connector: {e}"))?;

    // Match Chrome's HTTP/2 settings for fingerprint consistency and
    // allow enough concurrent connections for modern SPAs.
    let client: ProfileClient = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(32)
        .pool_idle_timeout(Duration::from_secs(90))
        .http2_initial_stream_window_size(6_291_456)
        .http2_initial_connection_window_size(15_631_505)
        .http2_max_header_list_size(262_144)
        .http2_adaptive_window(false)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .build(https);

    Ok(Arc::new(client))
}
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_cache_same_profile_returns_same_client() {
        // Build a client for a profile
        let client1 = get_client("rustls_default");
        assert!(
            client1.is_ok(),
            "Failed to build client: {:?}",
            client1.err()
        );

        // Second call should return the same Arc (same allocation)
        let client2 = get_client("rustls_default");
        assert!(client2.is_ok());

        let c1 = client1.unwrap();
        let c2 = client2.unwrap();

        // Same pointer = same client
        assert!(Arc::ptr_eq(&c1, &c2));
    }

    #[test]
    fn build_passthrough_client_succeeds() {
        let client = build_passthrough_client();
        assert!(
            client.is_ok(),
            "Failed to build pass-through client: {:?}",
            client.err()
        );
    }

    #[test]
    fn get_client_unknown_profile_falls_back() {
        let client = get_client("totally_nonexistent_profile_xyz");
        assert!(
            client.is_ok(),
            "Should fall back to rustls_default, got: {:?}",
            client.err()
        );
    }
}
