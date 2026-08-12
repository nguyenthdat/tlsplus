//! Rust core for the TLS+ Burp extension.
//!
//! Powered by `huginn-net-tls` for JA4 TLS fingerprinting and an embedded
//! Hyper ingress proxy with wreq/wreq-util outbound connections.

use std::sync::{LazyLock, Mutex};

pub mod http_client;
pub mod ja4;
pub mod profiles;
pub mod proxy;
mod transport;

uniffi::setup_scaffolding!();

// ---------------------------------------------------------------------------
// Server lifecycle state shared between lib and proxy modules
// ---------------------------------------------------------------------------

pub(crate) struct ServerState {
    pub running: bool,
    pub listen_addr: Option<String>,
    pub shutdown: Option<ServerShutdown>,
}

pub(crate) struct ServerShutdown {
    pub sender: tokio::sync::oneshot::Sender<()>,
    pub completion: std::sync::mpsc::Receiver<()>,
}

pub(crate) static SERVER_STATE: LazyLock<Mutex<ServerState>> = LazyLock::new(|| {
    Mutex::new(ServerState {
        running: false,
        listen_addr: None,
        shutdown: None,
    })
});

// ---------------------------------------------------------------------------
// UniFFI Records
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, uniffi::Record)]
pub struct EngineInfo {
    pub name: String,
    pub version: String,
    pub foxio_reference: String,
    pub ja4_core: String,
    pub capabilities: Vec<String>,
    pub limitations: Vec<String>,
}

/// JA3 fingerprint result (legacy).
#[derive(Clone, Debug, uniffi::Record)]
pub struct Ja3Result {
    pub ok: bool,
    pub ja3: Option<String>,
    pub ja3_hash: Option<String>,
    pub error: Option<String>,
}

/// Comprehensive JA4 result with all fingerprint variants.
#[derive(Clone, Debug, uniffi::Record)]
pub struct Ja4Result {
    pub ok: bool,
    /// JA4 hashed fingerprint (sorted cipher/extension order): "t13d1516h2_8daaf6152771_e5627efa2ab1"
    pub ja4: Option<String>,
    /// JA4 raw fingerprint (sorted, full cipher+extension list)
    pub ja4_r: Option<String>,
    /// JA4_o hashed fingerprint (original/unsorted cipher+extension order)
    pub ja4_o: Option<String>,
    /// JA4_or raw fingerprint (original order, full list)
    pub ja4_or: Option<String>,
    /// JA4_s1 hashed fingerprint (stable, ephemeral extensions excluded)
    pub ja4_s1: Option<String>,
    /// JA4_s1r raw fingerprint (stable, full cipher+extension list)
    pub ja4_s1r: Option<String>,
    /// Server Name Indication hostname from ClientHello (if present)
    pub sni: Option<String>,
    /// ALPN negotiated protocol from ClientHello (if present)
    pub alpn: Option<String>,
    /// Human-readable TLS version string (e.g. "TLS 1.3")
    pub tls_version: Option<String>,
    /// Error message if parsing failed
    pub error: Option<String>,
    /// Source engine that computed this result
    pub source: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ServerStatus {
    pub running: bool,
    pub listen_addr: Option<String>,
    pub message: String,
}

/// Request to forward through the local HTTP proxy or via `proxy_send_request`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ProxyRequest {
    /// Unique request identifier
    pub id: String,
    /// HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)
    pub method: String,
    /// Full target URL (e.g. "https://example.com/api/v1")
    pub url: String,
    /// Headers in "Name: Value" format, preserving order
    pub headers: Vec<String>,
    /// Request body bytes
    pub body: Vec<u8>,
    /// Fingerprint profile to use ("pass-through", "ja4", "ja4_r", etc.)
    pub profile: String,
    /// Connection timeout in seconds
    pub timeout_secs: u32,
}

/// Response from the proxy or `proxy_send_request`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ProxyResponse {
    /// Matching request identifier
    pub id: String,
    /// HTTP status code (0 if a forwarding error occurred)
    pub status_code: u16,
    /// Response headers in "Name: Value" format, preserving order
    pub headers: Vec<String>,
    /// Response body bytes
    pub body: Vec<u8>,
    /// JA4 fingerprint observed on the outbound TLS connection (future)
    pub ja4: Option<String>,
    /// Error message if forwarding failed
    pub error: Option<String>,
}

/// Browser TLS profile metadata for the UniFFI boundary.
#[derive(Clone, Debug, uniffi::Record)]
pub struct TlsProfileInfo {
    pub name: String,
    pub description: String,
    pub cipher_count: u32,
    pub alpn_protocols: Vec<String>,
}

// ---------------------------------------------------------------------------
// Exported Functions
// ---------------------------------------------------------------------------

#[uniffi::export]
pub fn tlsplus_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

#[uniffi::export]
pub fn engine_info() -> EngineInfo {
    EngineInfo {
        name: "TLS+ Rust core".to_owned(),
        version: tlsplus_version(),
        foxio_reference: "huginn-net-tls v2.0.0-rc (biandratti/huginn-net)".to_owned(),
        ja4_core: "huginn-net-tls — pure-Rust JA4 implementation with all variants".to_owned(),
        capabilities: vec![
            "Compute JA4, JA4_r, JA4_o, JA4_or, JA4_s1, JA4_s1r from raw TLS ClientHello bytes"
                .to_owned(),
            "Compute JA3 legacy fingerprint with MD5 hash".to_owned(),
            "Parse SNI, ALPN, and TLS version from ClientHello".to_owned(),
            "Run an embedded HTTP forward proxy with Hyper ingress and wreq outbound transport"
                .to_owned(),
            "Synchronous proxy_send_request for Burp handler integration".to_owned(),
            "Expose a UniFFI/JNA-safe API to Kotlin".to_owned(),
            format!(
                "{} TLS/HTTP emulation profiles from wreq-util plus compatibility aliases",
                wreq_util::Profile::VARIANTS.len()
            ),
            "Per-profile TLS, HTTP/2, and header emulation via wreq-util".to_owned(),
            "Request-level timeouts, retry with exponential backoff".to_owned(),
            "HTTP/2 support with connection pooling".to_owned(),
        ],
        limitations: vec![
            "JA4 computation works on raw ClientHello bytes; Burp Montoya HTTP handlers do not expose raw TLS bytes directly"
                .to_owned(),
            "Certificate generation for full MITM mode not yet implemented".to_owned(),
        ],
    }
}

#[uniffi::export]
pub fn available_profiles() -> Vec<String> {
    let mut profiles = vec![
        "pass-through".to_owned(),
        "ja4".to_owned(),
        "ja4_r".to_owned(),
        "ja4_o".to_owned(),
        "ja4_s1".to_owned(),
    ];

    // Append browser TLS fingerprint profiles
    profiles.extend(profiles::profile_names());

    profiles
}

/// Look up metadata for a browser TLS fingerprint profile.
///
/// Returns `None` if the profile name is not recognized.
#[uniffi::export]
pub fn get_tls_profile(name: String) -> Option<TlsProfileInfo> {
    profiles::by_name(&name).map(|p| TlsProfileInfo {
        name: p.name.to_owned(),
        description: p.description.to_owned(),
        cipher_count: p.cipher_count(),
        alpn_protocols: p.alpn_protocols(),
    })
}

/// Compute JA3 legacy fingerprint from raw TLS ClientHello bytes.
#[uniffi::export]
pub fn ja3_calculate_client_hello(packet: Vec<u8>) -> Ja3Result {
    ja4::compute_ja3_from_client_hello(&packet)
}

/// Compute ALL JA4 fingerprint variants from raw TLS ClientHello bytes.
///
/// This parses the raw TLS record bytes, extracts a `Signature` via
/// `huginn_net_tls::parse_tls_client_hello`, and computes every available
/// JA4 variant: sorted (JA4/JA4_r), original-order (JA4_o/JA4_or), and
/// stable (JA4_s1/JA4_s1r).
#[uniffi::export]
pub fn ja4_calculate_client_hello(packet: Vec<u8>) -> Ja4Result {
    ja4::compute_ja4_from_client_hello(&packet)
}

/// Start the embedded HTTP forward proxy on `listen_addr` (e.g. "127.0.0.1:8443").
///
/// The proxy accepts any HTTP request, reads forwarding instructions from
/// `X-Tlsplus-*` headers, and forwards to the real destination via wreq.
#[uniffi::export]
pub fn start_local_server(listen_addr: String) -> ServerStatus {
    proxy::start_local_server_impl(listen_addr)
}

/// Stop the embedded HTTP forward proxy.
#[uniffi::export]
pub fn stop_local_server() -> ServerStatus {
    proxy::stop_local_server_impl()
}

/// Query the current state of the embedded HTTP forward proxy.
///
/// Returns the live `running` and `listen_addr` fields from the shared
/// `SERVER_STATE` without starting or stopping anything. Safe to call
/// from any thread, at any time.
#[uniffi::export]
pub fn server_status() -> ServerStatus {
    proxy::server_status_impl()
}

/// Synchronously forward a single `ProxyRequest` through the internal hyper
/// client, bypassing the local proxy server.
///
/// This function blocks the calling thread using `Runtime::block_on`. It is
/// safe to call from any non-Tokio thread (e.g. the JVM thread that invokes
/// the Kotlin Burp handler).
#[uniffi::export]
pub fn proxy_send_request(request: ProxyRequest) -> ProxyResponse {
    proxy::proxy_send_request_impl(request)
}

/// Asynchronously forward one [`ProxyRequest`] through the internal wreq client
/// without starting the local proxy server.
///
/// Rust applications can use this function without blocking a Tokio worker
/// thread. The UniFFI boundary continues to use [`proxy_send_request`].
pub async fn proxy_send_request_async(request: ProxyRequest) -> ProxyResponse {
    proxy::proxy_send_request_async_impl(request).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_engine_info() {
        let info = engine_info();
        assert!(info.foxio_reference.contains("huginn-net-tls"));
        assert!(info.capabilities.iter().any(|item| item.contains("JA4")));
    }

    #[test]
    fn empty_client_hello_does_not_panic() {
        let result = ja4_calculate_client_hello(Vec::new());
        assert!(!result.ok);
        assert!(result.ja4.is_none());
        assert!(result.error.is_some());
    }

    #[test]
    fn invalid_bytes_returns_error() {
        let result = ja4_calculate_client_hello(vec![0x00, 0x01, 0x02, 0x03]);
        assert!(!result.ok);
        assert!(result.error.is_some());
    }

    #[test]
    fn available_profiles_contains_expected() {
        let profiles = available_profiles();
        assert!(profiles.contains(&"pass-through".to_owned()));
        assert!(profiles.contains(&"ja4".to_owned()));
        assert!(profiles.contains(&"ja4_r".to_owned()));
        assert!(profiles.contains(&"ja4_o".to_owned()));
        assert!(profiles.contains(&"ja4_s1".to_owned()));
    }

    #[test]
    fn local_server_tracks_state() {
        let started = start_local_server("127.0.0.1:43118".to_owned());
        assert!(started.running);
        assert_eq!(started.listen_addr.as_deref(), Some("127.0.0.1:43118"));

        let stopped = stop_local_server();
        assert!(!stopped.running);
        assert_eq!(stopped.listen_addr.as_deref(), Some("127.0.0.1:43118"));
    }

    #[test]
    fn server_status_does_not_panic() {
        // Should not panic regardless of server state.
        // After stop_local_server in the previous test, the global state
        // is `running: false`. This test just verifies the status query
        // returns a well-formed ServerStatus without touching the lock
        // or spawning anything.
        let status = server_status();
        // The message field is always populated
        assert!(!status.message.is_empty());
        // listen_addr is optional — both Some and None are valid
        // running reflects the actual state (we don't assert a specific
        // value because global state may vary across test runs).
        let _ = status; // explicitly used
    }

    #[test]
    fn proxy_send_request_missing_runtime() {
        // When no runtime is available, the global RUNTIME is lazily created.
        let request = ProxyRequest {
            id: "test-1".to_owned(),
            method: "GET".to_owned(),
            url: "http://127.0.0.1:1/nonexistent".to_owned(),
            headers: vec![],
            body: vec![],
            profile: "pass-through".to_owned(),
            timeout_secs: 2,
        };
        let response = proxy_send_request(request);
        assert_eq!(response.id, "test-1");
        // Expected to fail (connection refused or timeout), but not panic
        assert!(response.error.is_some());
    }

    #[tokio::test]
    async fn proxy_send_request_async_returns_forwarding_errors() {
        let request = ProxyRequest {
            id: "test-async-1".to_owned(),
            method: "GET".to_owned(),
            url: "http://127.0.0.1:1/nonexistent".to_owned(),
            headers: vec![],
            body: vec![],
            profile: "pass-through".to_owned(),
            timeout_secs: 2,
        };

        let response = proxy_send_request_async(request).await;
        assert_eq!(response.id, "test-async-1");
        assert!(response.error.is_some());
    }

    #[test]
    fn available_profiles_includes_browser_profiles() {
        let profiles = available_profiles();
        // Core profiles still present
        assert!(profiles.contains(&"pass-through".to_owned()));
        assert!(profiles.contains(&"ja4".to_owned()));
        // Browser profiles are included
        assert!(profiles.contains(&"chrome_120".to_owned()));
        assert!(profiles.contains(&"firefox_130".to_owned()));
        assert!(profiles.contains(&"safari_17".to_owned()));
        assert!(profiles.contains(&"rustls_default".to_owned()));
    }

    #[test]
    fn get_tls_profile_returns_data_for_known_profile() {
        let info = get_tls_profile("chrome_120".to_owned());
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.name, "chrome_120");
        assert!(info.description.contains("Chrome 120"));
        assert!(info.cipher_count > 0);
        assert!(info.alpn_protocols.contains(&"h2".to_owned()));
    }

    #[test]
    fn get_tls_profile_returns_none_for_unknown() {
        let info = get_tls_profile("nonexistent_browser_v999".to_owned());
        assert!(info.is_none());
    }

    #[test]
    fn get_tls_profile_case_insensitive() {
        let info = get_tls_profile("CHROME_120".to_owned());
        assert!(info.is_some());
        assert_eq!(info.unwrap().name, "chrome_120");
    }

    #[test]
    fn get_tls_profile_rustls_default() {
        let info = get_tls_profile("rustls_default".to_owned());
        assert!(info.is_some());
        let info = info.unwrap();
        assert!(info.cipher_count > 0);
        assert!(info.alpn_protocols.contains(&"h2".to_owned()));
    }

    #[test]
    fn ja3_empty_input_returns_error() {
        let result = ja3_calculate_client_hello(vec![]);
        assert!(!result.ok);
        assert!(result.error.is_some());
        assert!(result.ja3.is_none());
    }
}
