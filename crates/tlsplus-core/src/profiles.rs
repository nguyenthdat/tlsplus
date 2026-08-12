//! Browser TLS fingerprint profiles for outbound connection spoofing.
//!
//! Each profile captures the real cipher suite ordering, signature algorithm
//! preferences, supported elliptic curves, and ALPN protocol ordering of a
//! specific browser (or tool). These are used by `tls.rs` to build a customized
//! BoringSSL `SslContext` that closely matches the target browser's fingerprint.

use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// TLS Profile struct
// ---------------------------------------------------------------------------

/// Describes a browser's TLS ClientHello fingerprint for spoofing.
#[derive(Debug, Clone)]
pub struct TlsProfile {
    /// Short machine-readable name (e.g. "chrome_120")
    pub name: String,
    /// Human-readable description
    pub description: String,
    /// TLS versions in preference order: "TLS 1.3", "TLS 1.2"
    pub tls_versions: Vec<String>,
    /// Cipher suite IDs in the exact order the browser sends them (hex u16 values)
    pub cipher_suites: Vec<u16>,
    /// Signature algorithm IDs in order
    pub signature_algorithms: Vec<u16>,
    /// Supported elliptic curve IDs in order
    pub supported_groups: Vec<u16>,
    /// ALPN protocols in order: ["h2", "http/1.1"]
    pub alpn_protocols: Vec<String>,
    /// Key share groups (for TLS 1.3)
    pub key_share_groups: Vec<u16>,
    /// Certificate compression algorithms (0 = none, 2 = Brotli)
    pub cert_compression_algorithms: Vec<u16>,
    /// PSK key exchange modes enabled
    pub psk_key_exchange_modes: bool,
    /// Add GREASE values to extensions (random per connection — causes JA4 drift)
    pub grease: bool,
    /// Randomize extension order (Chrome-like but causes JA4 drift)
    pub permute_extensions: bool,
    /// Enable Signed Certificate Timestamps + OCSP Stapling extensions
    pub enable_sct_ocsp: bool,
    /// Supported versions extension IDs
    pub supported_versions_ext: Vec<u16>,
}

// ---------------------------------------------------------------------------
// Cipher suite / sig alg / curve ID constants
// ---------------------------------------------------------------------------

mod ids {
    // -- TLS 1.3 Cipher Suites --
    pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
    pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
    pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

    // -- TLS 1.2 ECDHE Cipher Suites --
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02B;
    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xC02F;
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xC02C;
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xC030;
    pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xCCA9;
    pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xCCA8;
    /// ECDHE-RSA CBC with SHA-1. Chrome 149 sends these.
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0xC013;
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0xC014;
    /// ECDHE-ECDSA CBC — used by chrome_120/edge_120/android_chrome; Chrome 149 does NOT send these.
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: u16 = 0xC009;
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: u16 = 0xC00A;
    /// ECDHE-RSA CBC with SHA-256/384 — Firefox sends these; Chrome 149 does NOT.
    #[allow(dead_code)]
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: u16 = 0xC027;
    #[allow(dead_code)]
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: u16 = 0xC028;
    /// RSA key exchange ciphers — Chrome 149 sends these at the end of its cipher list.
    /// BoringSSL accepts them via set_cipher_list (they are in BoringSSL's cipher table).
    pub const TLS_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009C;
    pub const TLS_RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009D;
    pub const TLS_RSA_WITH_AES_128_CBC_SHA: u16 = 0x002F;
    pub const TLS_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0035;

    // -- Signature Algorithms --
    pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
    pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
    pub const ECDSA_SECP521R1_SHA512: u16 = 0x0603;
    pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
    pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
    pub const RSA_PSS_RSAE_SHA512: u16 = 0x0806;
    pub const RSA_PKCS1_SHA256: u16 = 0x0401;
    pub const RSA_PKCS1_SHA384: u16 = 0x0501;
    pub const RSA_PKCS1_SHA512: u16 = 0x0601;
    /// Legacy SHA-1 algorithms — Firefox includes these for backward compat.
    /// Real browsers include them; omitting reduces fingerprint accuracy.
    #[allow(dead_code)]
    pub const ECDSA_SHA1: u16 = 0x0203;
    #[allow(dead_code)]
    pub const RSA_PKCS1_SHA1: u16 = 0x0201;

    // -- Named Groups / Curves --
    pub const X25519: u16 = 0x001D;
    pub const SECP256R1: u16 = 0x0017;
    pub const SECP384R1: u16 = 0x0018;
    #[allow(dead_code)]
    pub const X448: u16 = 0x001E;
    /// Post-Quantum hybrid key exchange (Chrome 124+, Firefox 130+)
    #[allow(dead_code)]
    pub const X25519_KYBER768: u16 = 0x6399;

    // -- TLS Versions (for supported_versions extension) --
    pub const TLS13_ID: u16 = 0x0304;
    pub const TLS12_ID: u16 = 0x0303;

    // -- Certificate Compression Algorithms (IANA IDs) --
    #[allow(dead_code)]
    pub const CERT_COMPRESS_BROTLI: u16 = 2;
}

// ---------------------------------------------------------------------------
// Helper macros to reduce boilerplate
// ---------------------------------------------------------------------------

macro_rules! profile {
    (
        name: $name:expr,
        description: $desc:expr,
        tls_versions: [$($ver:expr),* $(,)?],
        cipher_suites: [$($cs:expr),* $(,)?],
        signature_algorithms: [$($sa:expr),* $(,)?],
        supported_groups: [$($sg:expr),* $(,)?],
        alpn_protocols: [$($alpn:expr),* $(,)?],
        key_share_groups: [$($ksg:expr),* $(,)?],
        cert_compression_algorithms: [$($cca:expr),* $(,)?],
        psk: $psk:expr,
        grease: $gr:expr,
        permute: $pm:expr,
        sct_ocsp: $so:expr,
        supported_versions_ext: [$($sv:expr),* $(,)?],
    ) => {
        TlsProfile {
            name: $name.to_owned(),
            description: $desc.to_owned(),
            tls_versions: vec![$($ver.to_owned()),*],
            cipher_suites: vec![$($cs),*],
            signature_algorithms: vec![$($sa),*],
            supported_groups: vec![$($sg),*],
            alpn_protocols: vec![$($alpn.to_owned()),*],
            key_share_groups: vec![$($ksg),*],
            cert_compression_algorithms: vec![$($cca),*],
            psk_key_exchange_modes: $psk,
            grease: $gr,
            permute_extensions: $pm,
            enable_sct_ocsp: $so,
            supported_versions_ext: vec![$($sv),*],
        }
    };
}

// ---------------------------------------------------------------------------
// All profiles
// ---------------------------------------------------------------------------

/// Return a static reference to all built-in TLS profiles.
pub fn all_profiles() -> &'static [TlsProfile] {
    &PROFILES
}

/// Look up a profile by its machine-readable name.
pub fn by_name(name: &str) -> Option<&'static TlsProfile> {
    PROFILES.iter().find(|p| p.name.eq_ignore_ascii_case(name))
}

/// Return the list of all profile names.
pub fn profile_names() -> Vec<String> {
    PROFILES.iter().map(|p| p.name.clone()).collect()
}

use ids::*;

static PROFILES: LazyLock<Vec<TlsProfile>> = LazyLock::new(|| {
    vec![
        // ──── chrome_120 ────
        // Chrome 120 on Windows (Dec 2023). AES-GCM first, GREASE enabled.
        // Includes all 13 cipher suites Chrome 120 actually sends (RSA + ECDSA CBC).
        profile! {
            name: "chrome_120",
            description: "Chrome 120 on Windows (Dec 2023)",
            tls_versions: ["TLS 1.3", "TLS 1.2"],
            cipher_suites: [
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            ],
            signature_algorithms: [
                ECDSA_SECP256R1_SHA256,
                RSA_PSS_RSAE_SHA256,
                RSA_PKCS1_SHA256,
                ECDSA_SECP384R1_SHA384,
                RSA_PSS_RSAE_SHA384,
                RSA_PKCS1_SHA384,
                ECDSA_SECP521R1_SHA512,
                RSA_PSS_RSAE_SHA512,
                RSA_PKCS1_SHA512,
            ],
            supported_groups: [X25519, SECP256R1, SECP384R1],
            alpn_protocols: ["h2", "http/1.1"],
            key_share_groups: [X25519],
            cert_compression_algorithms: [0],
            psk: false,
            grease: true,
            permute: true,
            sct_ocsp: true,
            supported_versions_ext: [TLS13_ID, TLS12_ID],
        },
        // ──── chrome_130 ────
        // Chrome 130 current-gen (late 2024). Post-quantum key share ready.
        profile! {
            name: "chrome_130",
            description: "Chrome 130 on Windows (late 2024)",
            tls_versions: ["TLS 1.3", "TLS 1.2"],
            cipher_suites: [
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            ],
            signature_algorithms: [
                ECDSA_SECP256R1_SHA256,
                RSA_PSS_RSAE_SHA256,
                RSA_PKCS1_SHA256,
                ECDSA_SECP384R1_SHA384,
                RSA_PSS_RSAE_SHA384,
                RSA_PKCS1_SHA384,
                ECDSA_SECP521R1_SHA512,
                RSA_PSS_RSAE_SHA512,
                RSA_PKCS1_SHA512,
            ],
            supported_groups: [X25519, SECP256R1, SECP384R1],
            alpn_protocols: ["h2", "http/1.1"],
            key_share_groups: [X25519],
            cert_compression_algorithms: [0],
            psk: false,
            grease: true,
            permute: true,
            sct_ocsp: true,
            supported_versions_ext: [TLS13_ID, TLS12_ID],
        },
        // ──── firefox_130 ────
        // Firefox 130 (Sep 2024). ChaCha20-Poly1305 first.
        // Includes 11 cipher suites matching real Firefox TLS 1.2+1.3 list.
        profile! {
            name: "firefox_130",
            description: "Firefox 130 on Windows (Sep 2024)",
            tls_versions: ["TLS 1.3", "TLS 1.2"],
            cipher_suites: [
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            ],
            signature_algorithms: [
                ECDSA_SECP256R1_SHA256,
                ECDSA_SECP384R1_SHA384,
                ECDSA_SECP521R1_SHA512,
                RSA_PKCS1_SHA256,
                RSA_PKCS1_SHA384,
                RSA_PKCS1_SHA512,
                RSA_PSS_RSAE_SHA256,
                RSA_PSS_RSAE_SHA384,
                RSA_PSS_RSAE_SHA512,
            ],
            supported_groups: [X25519, SECP256R1, SECP384R1],
            alpn_protocols: ["h2", "http/1.1"],
            key_share_groups: [X25519],
            cert_compression_algorithms: [0],
            psk: false,
            grease: true,
            permute: true,
            sct_ocsp: true,
            supported_versions_ext: [TLS13_ID, TLS12_ID],
        },
        // ──── firefox_135 ────
        // Firefox 135 (current 2026). ChaCha20 first, post-quantum ready.
        profile! {
            name: "firefox_135",
            description: "Firefox 135 on Windows (current 2026)",
            tls_versions: ["TLS 1.3", "TLS 1.2"],
            cipher_suites: [
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            ],
            signature_algorithms: [
                ECDSA_SECP256R1_SHA256,
                ECDSA_SECP384R1_SHA384,
                ECDSA_SECP521R1_SHA512,
                RSA_PSS_RSAE_SHA256,
                RSA_PSS_RSAE_SHA384,
                RSA_PSS_RSAE_SHA512,
                RSA_PKCS1_SHA256,
                RSA_PKCS1_SHA384,
                RSA_PKCS1_SHA512,
            ],
            supported_groups: [X25519, SECP256R1, SECP384R1],
            alpn_protocols: ["h2", "http/1.1"],
            key_share_groups: [X25519],
            cert_compression_algorithms: [0],
            psk: false,
            grease: true,
            permute: true,
            sct_ocsp: true,
            supported_versions_ext: [TLS13_ID, TLS12_ID],
        },
        // ──── safari_17 ────
        // Safari 17 on macOS (2023). No GREASE, AES-GCM first.
        profile! {
            name: "safari_17",
            description: "Safari 17 on macOS (2023)",
            tls_versions: ["TLS 1.3", "TLS 1.2"],
            cipher_suites: [
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ],
            signature_algorithms: [
                ECDSA_SECP256R1_SHA256,
                RSA_PSS_RSAE_SHA256,
                RSA_PKCS1_SHA256,
                ECDSA_SECP384R1_SHA384,
                RSA_PSS_RSAE_SHA384,
                RSA_PKCS1_SHA384,
                ECDSA_SECP521R1_SHA512,
                RSA_PSS_RSAE_SHA512,
                RSA_PKCS1_SHA512,
            ],
            supported_groups: [X25519, SECP256R1, SECP384R1],
            alpn_protocols: ["h2", "http/1.1"],
            key_share_groups: [X25519],
            cert_compression_algorithms: [0],
            psk: false,
            grease: false,
            permute: false,
            sct_ocsp: false,
            supported_versions_ext: [TLS13_ID, TLS12_ID],
        },
        // ──── safari_18 ────
        // Safari 18 on macOS (2024). TLS 1.3 only, post-quantum ready.
        profile! {
            name: "safari_18",
            description: "Safari 18 on macOS (2024)",
            tls_versions: ["TLS 1.3"],
            cipher_suites: [
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
            ],
            signature_algorithms: [
                ECDSA_SECP256R1_SHA256,
                RSA_PSS_RSAE_SHA256,
                RSA_PKCS1_SHA256,
                ECDSA_SECP384R1_SHA384,
                RSA_PSS_RSAE_SHA384,
                RSA_PKCS1_SHA384,
                ECDSA_SECP521R1_SHA512,
                RSA_PSS_RSAE_SHA512,
                RSA_PKCS1_SHA512,
            ],
            supported_groups: [X25519, SECP256R1, SECP384R1],
            alpn_protocols: ["h2", "http/1.1"],
            key_share_groups: [X25519],
            cert_compression_algorithms: [0],
            psk: false,
            grease: false,
            permute: false,
            sct_ocsp: false,
            supported_versions_ext: [TLS13_ID],
        },
        // ──── edge_120 ────
        // Edge 120 (Chromium-based, Dec 2023). Similar to Chrome 120.
        // Includes all 13 cipher suites matching real Edge (RSA + ECDSA CBC).
        profile! {
            name: "edge_120",
            description: "Edge 120 on Windows (Chromium, Dec 2023)",
            tls_versions: ["TLS 1.3", "TLS 1.2"],
            cipher_suites: [
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            ],
            signature_algorithms: [
                ECDSA_SECP256R1_SHA256,
                RSA_PSS_RSAE_SHA256,
                RSA_PKCS1_SHA256,
                ECDSA_SECP384R1_SHA384,
                RSA_PSS_RSAE_SHA384,
                RSA_PKCS1_SHA384,
                ECDSA_SECP521R1_SHA512,
                RSA_PSS_RSAE_SHA512,
                RSA_PKCS1_SHA512,
            ],
            supported_groups: [X25519, SECP256R1, SECP384R1],
            alpn_protocols: ["h2", "http/1.1"],
            key_share_groups: [X25519],
            cert_compression_algorithms: [0],
            psk: false,
            grease: true,
            permute: true,
            sct_ocsp: true,
            supported_versions_ext: [TLS13_ID, TLS12_ID],
        },
        // ──── ios_safari_17 ────
        // iOS 17 Safari. No GREASE, TLS 1.2 + 1.3.
        profile! {
            name: "ios_safari_17",
            description: "Safari on iOS 17",
            tls_versions: ["TLS 1.3", "TLS 1.2"],
            cipher_suites: [
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ],
            signature_algorithms: [
                ECDSA_SECP256R1_SHA256,
                RSA_PSS_RSAE_SHA256,
                RSA_PKCS1_SHA256,
                ECDSA_SECP384R1_SHA384,
                RSA_PSS_RSAE_SHA384,
                RSA_PKCS1_SHA384,
                ECDSA_SECP521R1_SHA512,
                RSA_PSS_RSAE_SHA512,
                RSA_PKCS1_SHA512,
            ],
            supported_groups: [X25519, SECP256R1, SECP384R1],
            alpn_protocols: ["h2", "http/1.1"],
            key_share_groups: [X25519],
            cert_compression_algorithms: [0],
            psk: false,
            grease: false,
            permute: false,
            sct_ocsp: false,
            supported_versions_ext: [TLS13_ID, TLS12_ID],
        },
        // ──── android_chrome ────
        // Chrome 130 on Android. Typical mobile fingerprint with CBC ciphers.
        profile! {
            name: "android_chrome",
            description: "Chrome 130 on Android",
            tls_versions: ["TLS 1.3", "TLS 1.2"],
            cipher_suites: [
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            ],
            signature_algorithms: [
                ECDSA_SECP256R1_SHA256,
                RSA_PSS_RSAE_SHA256,
                RSA_PKCS1_SHA256,
                ECDSA_SECP384R1_SHA384,
                RSA_PSS_RSAE_SHA384,
                RSA_PKCS1_SHA384,
                ECDSA_SECP521R1_SHA512,
                RSA_PSS_RSAE_SHA512,
                RSA_PKCS1_SHA512,
            ],
            supported_groups: [X25519, SECP256R1],
            alpn_protocols: ["h2", "http/1.1"],
            key_share_groups: [X25519],
            cert_compression_algorithms: [0],
            psk: false,
            grease: true,
            permute: true,
            sct_ocsp: true,
            supported_versions_ext: [TLS13_ID, TLS12_ID],
        },
        // ──── python_urllib3 ────
        // Python urllib3/requests with OpenSSL defaults (for API testing).
        // Includes CBC ciphers for realistic Python TLS fingerprint.
        profile! {
            name: "python_urllib3",
            description: "Python urllib3/requests default TLS (API testing)",
            tls_versions: ["TLS 1.3", "TLS 1.2"],
            cipher_suites: [
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            ],
            signature_algorithms: [
                ECDSA_SECP256R1_SHA256,
                RSA_PSS_RSAE_SHA256,
                RSA_PKCS1_SHA256,
                ECDSA_SECP384R1_SHA384,
                RSA_PSS_RSAE_SHA384,
                RSA_PKCS1_SHA384,
                ECDSA_SECP521R1_SHA512,
                RSA_PSS_RSAE_SHA512,
                RSA_PKCS1_SHA512,
            ],
            supported_groups: [X25519, SECP256R1, SECP384R1],
            alpn_protocols: ["http/1.1"],
            key_share_groups: [X25519],
            cert_compression_algorithms: [0],
            psk: false,
            grease: false,
            permute: false,
            sct_ocsp: false,
            supported_versions_ext: [TLS13_ID, TLS12_ID],
        },
        // ──── rustls_default ────
        // Default rustls v0.23 fingerprint. Matches out-of-box reqwest config.
        profile! {
            name: "rustls_default",
            description: "rustls v0.23 default TLS configuration",
            tls_versions: ["TLS 1.3", "TLS 1.2"],
            cipher_suites: [
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            ],
            signature_algorithms: [
                ECDSA_SECP256R1_SHA256,
                ECDSA_SECP384R1_SHA384,
                ECDSA_SECP521R1_SHA512,
                RSA_PSS_RSAE_SHA256,
                RSA_PSS_RSAE_SHA384,
                RSA_PSS_RSAE_SHA512,
                RSA_PKCS1_SHA256,
                RSA_PKCS1_SHA384,
                RSA_PKCS1_SHA512,
            ],
            supported_groups: [X25519, SECP256R1, SECP384R1],
            alpn_protocols: ["h2", "http/1.1"],
            key_share_groups: [X25519],
            cert_compression_algorithms: [0],
            psk: false,
            grease: false,
            permute: false,
            sct_ocsp: false,
            supported_versions_ext: [TLS13_ID, TLS12_ID],
        },
        // ──── curl_8 ────
        // curl 8.x default TLS settings.
        profile! {
            name: "curl_8",
            description: "curl 8.x default TLS configuration",
            tls_versions: ["TLS 1.3", "TLS 1.2"],
            cipher_suites: [
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ],
            signature_algorithms: [
                ECDSA_SECP256R1_SHA256,
                RSA_PSS_RSAE_SHA256,
                RSA_PKCS1_SHA256,
                ECDSA_SECP384R1_SHA384,
                RSA_PSS_RSAE_SHA384,
                RSA_PKCS1_SHA384,
                ECDSA_SECP521R1_SHA512,
                RSA_PSS_RSAE_SHA512,
                RSA_PKCS1_SHA512,
            ],
            supported_groups: [X25519, SECP256R1, SECP384R1],
            alpn_protocols: ["http/1.1", "h2"],
            key_share_groups: [X25519],
            cert_compression_algorithms: [0],
            psk: false,
            grease: false,
            permute: false,
            sct_ocsp: false,
            supported_versions_ext: [TLS13_ID, TLS12_ID],
        },
        // ──── chrome_149 ────
        // Chrome 149 (2026) TCP/TLS ClientHello, captured 2026-06-27.
        // Run: _ja4_capture_workspace/20260627_120000/
        // Source: Chrome 149.0.7827.201 stable on macOS (--disable-quic).
        // Target JA4: t13d1516h2_8daaf6152771_d8a2da3f94cd
        // 15 ciphers (wire order, GREASE excluded):
        //   0x1301,0x1302,0x1303,0xC02B,0xC02F,0xC02C,0xC030,
        //   0xCCA9,0xCCA8,0xC013,0xC014,0x009C,0x009D,0x002F,0x0035
        // BoringSSL-unachievable gaps:
        //   - ALPS 0x44CD (extension drops 16→15, low impact)
        //   - X25519Kyber768 0x11EC in groups + key_share (medium impact)
        //   - ECH 0xFE0D GREASE extension (low impact, BoringSSL handles GREASE)
        // RSA-kx ciphers (0x009C,0x009D,0x002F,0x0035) ARE achievable —
        //   BoringSSL accepts them via set_cipher_list().
        profile! {
            name: "chrome_149",
            description: "Chrome 149 on macOS (2026) — captured TCP/TLS, 15 ciphers, 8 sigalgs",
            tls_versions: ["TLS 1.3", "TLS 1.2"],
            cipher_suites: [
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                TLS_RSA_WITH_AES_128_GCM_SHA256,
                TLS_RSA_WITH_AES_256_GCM_SHA384,
                TLS_RSA_WITH_AES_128_CBC_SHA,
                TLS_RSA_WITH_AES_256_CBC_SHA,
            ],
            signature_algorithms: [
                ECDSA_SECP256R1_SHA256,
                RSA_PSS_RSAE_SHA256,
                RSA_PKCS1_SHA256,
                ECDSA_SECP384R1_SHA384,
                RSA_PSS_RSAE_SHA384,
                RSA_PKCS1_SHA384,
                RSA_PSS_RSAE_SHA512,
                RSA_PKCS1_SHA512,
            ],
            supported_groups: [X25519, SECP256R1, SECP384R1],
            alpn_protocols: ["h2", "http/1.1"],
            key_share_groups: [X25519],
            cert_compression_algorithms: [2],  // Brotli (IANA id 2) — Chrome 149
            psk: false,
            grease: true,
            permute: true,
            sct_ocsp: true,
            supported_versions_ext: [TLS13_ID, TLS12_ID],
        },
        // ──── chrome_149_stable ────
        // Chrome 149 without extension permutation (GREASE stays — REQUIRED).
        // Same 15-cipher list, 8 sigalgs, curves, Brotli+SCT+OCSP as chrome_149
        // but produces a STABLE, repeatable JA4 fingerprint across connections.
        // Use this profile when you need consistent bot-detection scores.
        profile! {
            name: "chrome_149_stable",
            description: "Chrome 149 stable — 15 ciphers, consistent JA4 fingerprint",
            tls_versions: ["TLS 1.3", "TLS 1.2"],
            cipher_suites: [
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                TLS_RSA_WITH_AES_128_GCM_SHA256,
                TLS_RSA_WITH_AES_256_GCM_SHA384,
                TLS_RSA_WITH_AES_128_CBC_SHA,
                TLS_RSA_WITH_AES_256_CBC_SHA,
            ],
            signature_algorithms: [
                ECDSA_SECP256R1_SHA256,
                RSA_PSS_RSAE_SHA256,
                RSA_PKCS1_SHA256,
                ECDSA_SECP384R1_SHA384,
                RSA_PSS_RSAE_SHA384,
                RSA_PKCS1_SHA384,
                RSA_PSS_RSAE_SHA512,
                RSA_PKCS1_SHA512,
            ],
            supported_groups: [X25519, SECP256R1, SECP384R1],
            alpn_protocols: ["h2", "http/1.1"],
            key_share_groups: [X25519],
            cert_compression_algorithms: [2],  // Brotli (IANA id 2)
            psk: false,
            grease: true,        // ← REQUIRED by Cloudflare — rejects without GREASE
            permute: false,       // ← NO permute = consistent JA4
            sct_ocsp: true,       // ← REQUIRED — Cloudflare rejects without SCT+OCSP!
            supported_versions_ext: [TLS13_ID, TLS12_ID],
        },
        // ──── firefox_current ────
        // Firefox current (2026) matching real captured fingerprint from macOS.
        // Includes ECDHE-ECDSA CBC, SHA1 legacy sigalgs, X448, ECH-ready.
        // JA4 reference: t13d1617h2_86a278354501_3cbfd9057e0d
        profile! {
            name: "firefox_current",
            description: "Firefox current on macOS (2026) — captured fingerprint",
            tls_versions: ["TLS 1.3", "TLS 1.2"],
            cipher_suites: [
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            ],
            signature_algorithms: [
                ECDSA_SECP256R1_SHA256,
                ECDSA_SECP384R1_SHA384,
                ECDSA_SECP521R1_SHA512,
                RSA_PSS_RSAE_SHA256,
                RSA_PSS_RSAE_SHA384,
                RSA_PSS_RSAE_SHA512,
                RSA_PKCS1_SHA256,
                RSA_PKCS1_SHA384,
                RSA_PKCS1_SHA512,
                ECDSA_SHA1,
                RSA_PKCS1_SHA1,
            ],
            supported_groups: [X25519, SECP256R1, SECP384R1],
            alpn_protocols: ["h2", "http/1.1"],
            key_share_groups: [X25519],
            cert_compression_algorithms: [0],
            psk: false,
            grease: true,
            permute: true,
            sct_ocsp: true,
            supported_versions_ext: [TLS13_ID, TLS12_ID],
        },
    ]
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_are_loadable_by_name() {
        for profile in all_profiles() {
            let found = by_name(&profile.name);
            assert!(
                found.is_some(),
                "Profile '{}' not found by name",
                profile.name
            );
            let found = found.unwrap();
            assert_eq!(found.name, profile.name);
        }
    }

    #[test]
    fn all_profiles_have_ciphers() {
        for profile in all_profiles() {
            assert!(
                !profile.cipher_suites.is_empty(),
                "Profile '{}' has no cipher suites",
                profile.name
            );
        }
    }

    #[test]
    fn all_profiles_have_alpn() {
        for profile in all_profiles() {
            assert!(
                !profile.alpn_protocols.is_empty(),
                "Profile '{}' has no ALPN protocols",
                profile.name
            );
            // Every profile should support HTTP/1.1
            assert!(
                profile.alpn_protocols.iter().any(|a| a == "http/1.1"),
                "Profile '{}' is missing http/1.1 ALPN",
                profile.name
            );
        }
    }

    #[test]
    fn profile_count() {
        assert_eq!(all_profiles().len(), 15, "Expected 15 built-in profiles");
    }

    #[test]
    fn all_profiles_have_supported_groups() {
        for profile in all_profiles() {
            assert!(
                !profile.supported_groups.is_empty(),
                "Profile '{}' has no supported groups",
                profile.name
            );
        }
    }

    #[test]
    fn profiles_have_correct_description() {
        let chrome = by_name("chrome_120").unwrap();
        assert!(chrome.description.contains("Chrome 120"));

        let firefox = by_name("firefox_130").unwrap();
        assert!(firefox.description.contains("Firefox 130"));

        let safari = by_name("safari_17").unwrap();
        assert!(safari.description.contains("Safari 17"));

        let rustls = by_name("rustls_default").unwrap();
        assert!(rustls.description.contains("rustls"));
    }

    #[test]
    fn profile_names_are_unique() {
        let mut names: Vec<&str> = all_profiles().iter().map(|p| p.name.as_str()).collect();
        let len_before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), len_before, "Profile names are not unique");
    }

    #[test]
    fn by_name_case_insensitive() {
        assert!(by_name("CHROME_120").is_some());
        assert!(by_name("ChRoMe_120").is_some());
        assert!(by_name("nonexistent").is_none());
    }

    #[test]
    fn profile_names_vec_matches_all() {
        let names = profile_names();
        assert_eq!(names.len(), all_profiles().len());
        for profile in all_profiles() {
            assert!(names.contains(&profile.name));
        }
    }
}
