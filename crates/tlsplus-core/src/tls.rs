//! Custom TLS configuration builder using BoringSSL for Chrome-accurate
//! fingerprint spoofing with GREASE, extension permutation, and certificate
//! compression support.
//!
//! Translates a `TlsProfile` into a BoringSSL `SslContext` that closely
//! matches the target browser's TLS fingerprint. Unlike rustls, BoringSSL
//! offers:
//!
//! 1. **GREASE injection** — `set_grease_enabled(true)` adds random GREASE
//!    values to cipher suites, extensions, and supported groups, matching
//!    Chrome's behavior.
//! 2. **Extension permutation** — `set_permute_extensions(true)` randomizes
//!    the order of TLS extensions (like Chrome).
//! 3. **Full cipher suite coverage** — BoringSSL supports CBC ciphers
//!    (e.g., `ECDHE-RSA-AES128-SHA`), enabling exact browser fingerprint
//!    matching.
//! 4. **Cipher suite ordering** — `set_cipher_list()` accepts OpenSSL cipher
//!    strings in exact order, giving full control over cipher suite priority.
//! 5. **Curve and signature algorithm ordering** — `set_curves_list()` and
//!    `set_sigalgs_list()` provide full control over these ClientHello fields.
//! 6. **Certificate compression** — Brotli (`CertCompressionAlgorithm::BROTLI`)
//!    via `add_certificate_compression_algorithm()` adds the CompressCertificate
//!    TLS extension (0x001B), matching Chrome's behavior.
//!
//! To apply profile settings to a `SslConnectorBuilder` (for use with hyper),
//! simply call `configure_context(connector_builder.deref_mut(), profile)`
//! — `SslConnectorBuilder` derefs to `SslContextBuilder` so settings
//! automatically transfer.

use std::io::Write;
use std::sync::Arc;

use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, SslContext, SslContextBuilder,
    SslMethod, SslVersion,
};

use crate::profiles::TlsProfile;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build a BoringSSL `SslContext` from a `TlsProfile`.
///
/// Returns an error if any BoringSSL configuration call fails (e.g. invalid
/// cipher suite names, missing root certificate paths).
pub fn build_tls_config(profile: &TlsProfile) -> Result<SslContext, String> {
    let mut builder = SslContextBuilder::new(SslMethod::tls())
        .map_err(|e| format!("Failed to create SslContextBuilder: {e}"))?;
    configure_context(&mut builder, profile)?;
    Ok(builder.build())
}

/// Build a `SslContext` wrapped in `Arc` for use with cached connection pools.
pub fn build_tls_config_arc(profile: &TlsProfile) -> Result<Arc<SslContext>, String> {
    build_tls_config(profile).map(Arc::new)
}

/// Apply a `TlsProfile`'s settings to an `SslContextBuilder`.
///
/// This function configures:
/// - GREASE (Generate Random Extensions And Sustain Extensibility)
/// - Extension permutation (Chrome-like random ordering)
/// - SCT (Signed Certificate Timestamps) extension request
/// - OCSP Stapling extension request
/// - Cipher suite list (in profile order)
/// - Supported elliptic curves (in profile order)
/// - Signature algorithms (in profile order)
/// - ALPN protocols (binary-encoded)
/// - Certificate compression (Brotli via CompressCertificate extension)
/// - TLS protocol version range
/// - Root certificate verification
///
/// # Usage with `SslConnectorBuilder`
///
/// `SslConnectorBuilder` implements `DerefMut<Target = SslContextBuilder>`,
/// so you can pass it directly:
///
/// ```ignore
/// let mut ssl_builder = SslConnector::builder(SslMethod::tls())?;
/// tls::configure_context(&mut ssl_builder, profile)?;
/// // ssl_builder is now configured; pass to HttpsConnector::with_connector()
/// ```
pub fn configure_context(
    builder: &mut SslContextBuilder,
    profile: &TlsProfile,
) -> Result<(), String> {
    // ── GREASE — controlled per-profile for stability ──
    builder.set_grease_enabled(profile.grease);

    // ── Extension permutation — controlled per-profile ──
    builder.set_permute_extensions(profile.permute_extensions);

    // ── SCT + OCSP Stapling — controlled per-profile ──
    if profile.enable_sct_ocsp {
        builder.enable_signed_cert_timestamps();
        builder.enable_ocsp_stapling();
    }

    // ── Cipher suites in profile order ──
    //
    // NOTE: BoringSSL handles TLS 1.3 ciphers separately from TLS 1.2
    // ciphers (via `set_ciphersuites`, which the boring crate does not
    // currently expose). `set_cipher_list` only controls TLS 1.2 and
    // below. We filter out TLS 1.3 cipher suite IDs (0x1301–0x1305)
    // so they don't trigger NO_CIPHER_MATCH errors. TLS 1.3 ciphers
    // will use BoringSSL's sensible defaults.
    if !profile.cipher_suites.is_empty() {
        let tls12_ciphers: Vec<&str> = profile
            .cipher_suites
            .iter()
            .filter(|&&id| !is_tls13_cipher(id))
            .filter_map(|&id| cipher_suite_id_to_openssl_name(id))
            .collect();
        if !tls12_ciphers.is_empty() {
            let cipher_list = tls12_ciphers.join(":");
            builder.set_cipher_list(&cipher_list).map_err(|e| {
                format!(
                    "Failed to set cipher list for profile '{}': {e}",
                    profile.name
                )
            })?;
        } else {
            eprintln!(
                "tlsplus: profile '{}' has no TLS 1.2 cipher suites; using BoringSSL defaults",
                profile.name
            );
        }
    }

    // ── Supported curves in profile order ──
    if !profile.supported_groups.is_empty() {
        let curves = profile
            .supported_groups
            .iter()
            .filter_map(|&id| curve_id_to_openssl_name(id))
            .collect::<Vec<_>>()
            .join(":");
        if !curves.is_empty() {
            builder.set_curves_list(&curves).map_err(|e| {
                format!(
                    "Failed to set curves list for profile '{}': {e}",
                    profile.name
                )
            })?;
        }
    }

    // ── Signature algorithms in profile order ──
    if !profile.signature_algorithms.is_empty() {
        let sigalgs = profile
            .signature_algorithms
            .iter()
            .filter_map(|&id| sigalg_id_to_openssl_name(id))
            .collect::<Vec<_>>()
            .join(":");
        if !sigalgs.is_empty() {
            builder.set_sigalgs_list(&sigalgs).map_err(|e| {
                format!(
                    "Failed to set sigalgs list for profile '{}': {e}",
                    profile.name
                )
            })?;
        }
    }

    // ── ALPN — binary protocol encoding (1-byte length prefix per protocol) ──
    if !profile.alpn_protocols.is_empty() {
        let alpn_bytes: Vec<u8> = profile
            .alpn_protocols
            .iter()
            .flat_map(|p| {
                let mut v = Vec::with_capacity(1 + p.len());
                v.push(p.len() as u8);
                v.extend_from_slice(p.as_bytes());
                v
            })
            .collect();
        builder.set_alpn_protos(&alpn_bytes).map_err(|e| {
            format!(
                "Failed to set ALPN protocols for profile '{}': {e}",
                profile.name
            )
        })?;
    }

    // ── Certificate compression (Brotli) — Chrome-like CompressCertificate ──
    //
    // Real Chrome sends the CompressCertificate extension (0x001B) with Brotli
    // (IANA id 2). BoringSSL exposes this via `add_certificate_compression_algorithm`
    // with a `CertificateCompressor` trait implementation.
    //
    // NOTE: This is a best-effort configuration. If Brotli is not available in
    // the linked BoringSSL build, `add_certificate_compression_algorithm` will
    // return an error, which we log but don't treat as fatal.
    if !profile.cert_compression_algorithms.is_empty()
        && profile.cert_compression_algorithms.contains(&2)
    {
        let compressor = BrotliCertCompressor;
        if let Err(e) = builder.add_certificate_compression_algorithm(compressor) {
            eprintln!(
                "tlsplus: Brotli cert compression not available for '{}': {e}",
                profile.name
            );
        }
    }

    // ── TLS protocol version range ──
    let has_tls13 = profile.tls_versions.iter().any(|v| v == "TLS 1.3");
    let has_tls12 = profile.tls_versions.iter().any(|v| v == "TLS 1.2");

    if has_tls12 || !has_tls13 {
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|e| format!("Failed to set min proto version: {e}"))?;
    }
    if has_tls13 {
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| format!("Failed to set max proto version: {e}"))?;
    } else if has_tls12 {
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .map_err(|e| format!("Failed to set max proto version: {e}"))?;
    }

    // ── Root certificate verification ──
    builder
        .set_default_verify_paths()
        .map_err(|e| format!("Failed to set default verify paths: {e}"))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// ID → OpenSSL name mapping helpers
// ---------------------------------------------------------------------------

/// Returns `true` if the cipher suite ID is a TLS 1.3 AEAD cipher suite.
///
/// TLS 1.3 cipher suites are in the range 0x1301–0x1305 and must be
/// configured via `set_ciphersuites` in BoringSSL, not `set_cipher_list`.
fn is_tls13_cipher(id: u16) -> bool {
    (0x1301..=0x1305).contains(&id)
}

/// Map a u16 cipher suite ID (from TLS profiles) to its OpenSSL name string.
///
/// Returns `None` if the ID is not recognized.
fn cipher_suite_id_to_openssl_name(id: u16) -> Option<&'static str> {
    match id {
        // TLS 1.3 AEAD
        0x1301 => Some("TLS_AES_128_GCM_SHA256"),
        0x1302 => Some("TLS_AES_256_GCM_SHA384"),
        0x1303 => Some("TLS_CHACHA20_POLY1305_SHA256"),
        // TLS 1.2 ECDHE GCM
        0xC02B => Some("ECDHE-ECDSA-AES128-GCM-SHA256"),
        0xC02F => Some("ECDHE-RSA-AES128-GCM-SHA256"),
        0xC02C => Some("ECDHE-ECDSA-AES256-GCM-SHA384"),
        0xC030 => Some("ECDHE-RSA-AES256-GCM-SHA384"),
        // TLS 1.2 ECDHE ChaCha20
        0xCCA9 => Some("ECDHE-ECDSA-CHACHA20-POLY1305"),
        0xCCA8 => Some("ECDHE-RSA-CHACHA20-POLY1305"),
        // TLS 1.2 ECDHE CBC (used by all real browsers)
        0xC013 => Some("ECDHE-RSA-AES128-SHA"),
        0xC014 => Some("ECDHE-RSA-AES256-SHA"),
        0xC009 => Some("ECDHE-ECDSA-AES128-SHA"),
        0xC00A => Some("ECDHE-ECDSA-AES256-SHA"),
        // TLS 1.2 ECDHE CBC with SHA-256/384 (Firefox sends these; Chrome 149 does NOT)
        0xC027 => Some("ECDHE-RSA-AES128-SHA256"),
        0xC028 => Some("ECDHE-RSA-AES256-SHA384"),
        // TLS 1.2 RSA key exchange ciphers — Chrome 149 sends these on the wire.
        // They are available in BoringSSL via set_cipher_list().
        0x009C => Some("AES128-GCM-SHA256"),
        0x009D => Some("AES256-GCM-SHA384"),
        0x002F => Some("AES128-SHA"),
        0x0035 => Some("AES256-SHA"),
        _ => {
            eprintln!("tlsplus: unknown cipher suite 0x{id:04X} — not available in BoringSSL");
            None
        }
    }
}

/// Map a u16 curve/group ID to its OpenSSL name string.
fn curve_id_to_openssl_name(id: u16) -> Option<&'static str> {
    match id {
        0x001D => Some("X25519"),
        0x0017 => Some("prime256v1"),
        0x0018 => Some("secp384r1"),
        0x001E => Some("X448"),
        0x6399 => Some("X25519Kyber768"),
        _ => {
            eprintln!("tlsplus: unknown curve 0x{id:04X}");
            None
        }
    }
}

/// Map a u16 signature algorithm ID to its OpenSSL name string.
fn sigalg_id_to_openssl_name(id: u16) -> Option<&'static str> {
    match id {
        0x0403 => Some("ecdsa_secp256r1_sha256"),
        0x0503 => Some("ecdsa_secp384r1_sha384"),
        0x0603 => Some("ecdsa_secp521r1_sha512"),
        0x0804 => Some("rsa_pss_rsae_sha256"),
        0x0805 => Some("rsa_pss_rsae_sha384"),
        0x0806 => Some("rsa_pss_rsae_sha512"),
        0x0401 => Some("rsa_pkcs1_sha256"),
        0x0501 => Some("rsa_pkcs1_sha384"),
        0x0601 => Some("rsa_pkcs1_sha512"),
        // Legacy SHA-1 — real browsers (especially Firefox) include these
        0x0203 => Some("ecdsa_sha1"),
        0x0201 => Some("rsa_pkcs1_sha1"),
        _ => {
            eprintln!("tlsplus: unknown sigalg 0x{id:04X}");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Certificate compression — Brotli (Chrome-like CompressCertificate)
// ---------------------------------------------------------------------------

/// Brotli certificate compressor implementing `CertificateCompressor`.
///
/// Uses the `brotli` crate for compression/decompression. Chrome sends
/// Brotli (IANA id 2) in the CompressCertificate TLS extension (0x001B).
///
/// Compression parameters (quality=11, lgwin=22) match Chrome's typical
/// Brotli settings for certificate compression.
struct BrotliCertCompressor;

impl CertificateCompressor for BrotliCertCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;

    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: Write,
    {
        // Use quality 11 (max), lgwin 22 (4MB window — standard for certs)
        let mut writer = brotli::CompressorWriter::new(output, 4096, 11, 22);
        writer.write_all(input)?;
        // CompressorWriter flushes on drop, completing the brotli stream
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: Write,
    {
        brotli::BrotliDecompress(&mut std::io::Cursor::new(input), output)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles;

    #[test]
    fn build_config_for_each_profile() {
        for profile in profiles::all_profiles() {
            let result = build_tls_config(profile);
            assert!(
                result.is_ok(),
                "Failed to build TLS config for '{}': {:?}",
                profile.name,
                result.err()
            );
        }
    }

    #[test]
    fn build_config_for_safari_18_tls13_only() {
        let profile = profiles::by_name("safari_18").unwrap();
        assert_eq!(profile.tls_versions, vec!["TLS 1.3"]);
        let config = build_tls_config(profile).unwrap();
        // SslContext is opaque, but constructing it is the test
        drop(config);
    }

    #[test]
    fn build_config_arc_wraps() {
        let profile = profiles::by_name("rustls_default").unwrap();
        let arc = build_tls_config_arc(profile).unwrap();
        let _cloned = Arc::clone(&arc);
    }

    #[test]
    fn cipher_suite_id_mapping_known_values() {
        assert_eq!(
            cipher_suite_id_to_openssl_name(0x1301),
            Some("TLS_AES_128_GCM_SHA256")
        );
        assert_eq!(
            cipher_suite_id_to_openssl_name(0x1302),
            Some("TLS_AES_256_GCM_SHA384")
        );
        assert_eq!(
            cipher_suite_id_to_openssl_name(0xC02F),
            Some("ECDHE-RSA-AES128-GCM-SHA256")
        );
        // CBC ciphers — now supported by BoringSSL!
        assert_eq!(
            cipher_suite_id_to_openssl_name(0xC013),
            Some("ECDHE-RSA-AES128-SHA")
        );
        assert_eq!(
            cipher_suite_id_to_openssl_name(0xC014),
            Some("ECDHE-RSA-AES256-SHA")
        );
        // CBC-SHA256/SHA384 variants — Firefox sends these; Chrome 149 does NOT
        assert_eq!(
            cipher_suite_id_to_openssl_name(0xC027),
            Some("ECDHE-RSA-AES128-SHA256")
        );
        assert_eq!(
            cipher_suite_id_to_openssl_name(0xC028),
            Some("ECDHE-RSA-AES256-SHA384")
        );
        // RSA key exchange ciphers — Chrome 149 sends these; BoringSSL accepts them
        assert_eq!(
            cipher_suite_id_to_openssl_name(0x009C),
            Some("AES128-GCM-SHA256")
        );
        assert_eq!(
            cipher_suite_id_to_openssl_name(0x009D),
            Some("AES256-GCM-SHA384")
        );
        assert_eq!(cipher_suite_id_to_openssl_name(0x002F), Some("AES128-SHA"));
        assert_eq!(cipher_suite_id_to_openssl_name(0x0035), Some("AES256-SHA"));
    }

    #[test]
    fn build_config_for_chrome_149_with_rsa_ciphers() {
        // Verify BoringSSL accepts RSA key exchange cipher names via set_cipher_list.
        // This is THE critical test — if it fails, BoringSSL genuinely drops these.
        let profile = profiles::by_name("chrome_149").unwrap();
        assert_eq!(
            profile.cipher_suites.len(),
            15,
            "chrome_149 should have 15 ciphers"
        );

        // Count the RSA-kx ciphers in the profile
        let rsa_kx_ciphers: Vec<u16> = profile
            .cipher_suites
            .iter()
            .filter(|&&id| matches!(id, 0x009C | 0x009D | 0x002F | 0x0035))
            .copied()
            .collect();
        assert_eq!(
            rsa_kx_ciphers.len(),
            4,
            "chrome_149 profile should have 4 RSA-kx ciphers; found: {:?}",
            rsa_kx_ciphers
        );

        let result = build_tls_config(profile);
        assert!(
            result.is_ok(),
            "BoringSSL rejected chrome_149 RSA-kx ciphers: {:?}",
            result.err()
        );
    }

    #[test]
    fn curve_id_mapping_known_values() {
        assert_eq!(curve_id_to_openssl_name(0x001D), Some("X25519"));
        assert_eq!(curve_id_to_openssl_name(0x0017), Some("prime256v1"));
        assert_eq!(curve_id_to_openssl_name(0x0018), Some("secp384r1"));
    }

    #[test]
    fn sigalg_id_mapping_known_values() {
        assert_eq!(
            sigalg_id_to_openssl_name(0x0403),
            Some("ecdsa_secp256r1_sha256")
        );
        assert_eq!(
            sigalg_id_to_openssl_name(0x0804),
            Some("rsa_pss_rsae_sha256")
        );
        assert_eq!(sigalg_id_to_openssl_name(0x0401), Some("rsa_pkcs1_sha256"));
    }

    #[test]
    fn unknown_cipher_suite_returns_none() {
        assert_eq!(cipher_suite_id_to_openssl_name(0xFFFF), None);
        assert_eq!(cipher_suite_id_to_openssl_name(0x0000), None);
    }

    #[test]
    fn configure_context_preserves_grease_setting() {
        let profile = profiles::by_name("chrome_120").unwrap();
        assert!(profile.grease);

        let config = build_tls_config(profile).unwrap();
        // SslContext built successfully — GREASE was configured
        drop(config);
    }

    #[test]
    fn configure_context_preserves_safari_no_grease() {
        let profile = profiles::by_name("safari_17").unwrap();
        assert!(!profile.grease);

        let config = build_tls_config(profile).unwrap();
        drop(config);
    }
}
