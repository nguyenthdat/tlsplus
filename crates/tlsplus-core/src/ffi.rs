//! UniFFI records and exported functions extracted from `lib.rs`.
//!
//! These are re-exported at the crate root so all existing paths
//! (`tlsplus_core::ProxyRequest`, etc.) remain unchanged.

use std::sync::{LazyLock, Mutex};

// ---------------------------------------------------------------------------
// UniFFI Records (7)
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

#[derive(Clone, Debug, uniffi::Record)]
pub struct Ja3Result {
    pub ok: bool,
    pub ja3: Option<String>,
    pub ja3_hash: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct Ja4Result {
    pub ok: bool,
    pub ja4: Option<String>,
    pub ja4_r: Option<String>,
    pub ja4_o: Option<String>,
    pub ja4_or: Option<String>,
    pub ja4_s1: Option<String>,
    pub ja4_s1r: Option<String>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub tls_version: Option<String>,
    pub error: Option<String>,
    pub source: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ServerStatus {
    pub running: bool,
    pub listen_addr: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ProxyRequest {
    pub id: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<String>,
    pub body: Vec<u8>,
    pub profile: String,
    pub timeout_secs: u32,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ProxyResponse {
    pub id: String,
    pub status_code: u16,
    pub headers: Vec<String>,
    pub body: Vec<u8>,
    pub ja4: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct TlsProfileInfo {
    pub name: String,
    pub description: String,
    pub cipher_count: u32,
    pub alpn_protocols: Vec<String>,
}

// ---------------------------------------------------------------------------
// Shared server state
// ---------------------------------------------------------------------------

pub(crate) struct ServerState {
    pub running: bool,
    pub listen_addr: Option<String>,
    pub shutdown_notify: Option<std::sync::Arc<tokio::sync::Notify>>,
}

pub(crate) static SERVER_STATE: LazyLock<Mutex<ServerState>> = LazyLock::new(|| {
    Mutex::new(ServerState {
        running: false,
        listen_addr: None,
        shutdown_notify: None,
    })
});

// ---------------------------------------------------------------------------
// Exported Functions (10)
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
            "Run an embedded HTTP forward proxy (hyper-native + BoringSSL)".to_owned(),
            "Synchronous proxy_send_request for Burp handler integration".to_owned(),
            "Expose a UniFFI/JNA-safe API to Kotlin".to_owned(),
            "15 browser TLS fingerprint profiles (Chrome, Firefox, Safari, etc.)".to_owned(),
            "Per-profile TLS configuration via BoringSSL with GREASE support".to_owned(),
            "Extension permutation for Chrome-like ClientHello".to_owned(),
            "Full cipher suite coverage including CBC ciphers".to_owned(),
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
    profiles.extend(crate::profiles::profile_names());
    profiles
}

#[uniffi::export]
pub fn get_tls_profile(name: String) -> Option<TlsProfileInfo> {
    crate::profiles::by_name(&name).map(|p| TlsProfileInfo {
        name: p.name.clone(),
        description: p.description.clone(),
        cipher_count: p.cipher_suites.len() as u32,
        alpn_protocols: p.alpn_protocols.clone(),
    })
}

#[uniffi::export]
pub fn ja3_calculate_client_hello(packet: Vec<u8>) -> Ja3Result {
    crate::ja4::compute_ja3_from_client_hello(&packet)
}

#[uniffi::export]
pub fn ja4_calculate_client_hello(packet: Vec<u8>) -> Ja4Result {
    crate::ja4::compute_ja4_from_client_hello(&packet)
}

#[uniffi::export]
pub fn start_local_server(listen_addr: String) -> ServerStatus {
    crate::proxy::start_local_server_impl(listen_addr)
}

#[uniffi::export]
pub fn stop_local_server() -> ServerStatus {
    crate::proxy::stop_local_server_impl()
}

#[uniffi::export]
pub fn server_status() -> ServerStatus {
    crate::proxy::server_status_impl()
}

#[uniffi::export]
pub fn proxy_send_request(request: ProxyRequest) -> ProxyResponse {
    crate::proxy::proxy_send_request_impl(request)
}

pub async fn proxy_send_request_async(request: ProxyRequest) -> ProxyResponse {
    crate::proxy::proxy_send_request_async_impl(request).await
}
