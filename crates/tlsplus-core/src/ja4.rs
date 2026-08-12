//! JA4 and JA3 computation wrappers around `huginn-net-tls`.

use huginn_net_tls::{TlsVersion, parse_tls_client_hello};

use crate::{Ja3Result, Ja4Result};

// ---------------------------------------------------------------------------
// Convenience error constructors (Template Method pattern)
// ---------------------------------------------------------------------------

impl Ja4Result {
    /// Build an error result with all optional fingerprint fields set to `None`.
    fn error(reason: String) -> Self {
        Ja4Result {
            ok: false,
            error: Some(reason),
            source: "huginn-net-tls".to_owned(),
            ja4: None,
            ja4_r: None,
            ja4_o: None,
            ja4_or: None,
            ja4_s1: None,
            ja4_s1r: None,
            sni: None,
            alpn: None,
            tls_version: None,
        }
    }
}

impl Ja3Result {
    /// Build an error result.
    fn error(reason: String) -> Self {
        Ja3Result {
            ok: false,
            error: Some(reason),
            ja3: None,
            ja3_hash: None,
        }
    }
}

/// Compute all JA4 fingerprint variants from raw TLS ClientHello bytes.
///
/// Returns a `Ja4Result` with every available variant populated:
/// - `ja4` / `ja4_r` — sorted cipher/extension order
/// - `ja4_o` / `ja4_or` — original (unsorted) order
/// - `ja4_s1` / `ja4_s1r` — stable (ephemeral extensions excluded)
pub fn compute_ja4_from_client_hello(packet: &[u8]) -> Ja4Result {
    let sig = match parse_tls_client_hello(packet) {
        Ok(sig) => sig,
        Err(e) => {
            return Ja4Result::error(format!("Failed to parse ClientHello: {e}"));
        }
    };

    // Compute all three JA4 variants
    let sorted = sig.generate_ja4();
    let original = sig.generate_ja4_original();
    let stable = sig.generate_ja4_stable_v1();

    // Map TLS version to human-readable string
    let version_str = match sig.version {
        TlsVersion::V1_3 => "TLS 1.3",
        TlsVersion::V1_2 => "TLS 1.2",
        TlsVersion::V1_1 => "TLS 1.1",
        TlsVersion::V1_0 => "TLS 1.0",
        TlsVersion::Ssl3_0 => "SSL 3.0",
        TlsVersion::Ssl2_0 => "SSL 2.0",
        TlsVersion::Unknown(v) => {
            let mut result = Ja4Result::error(format!("Unknown TLS version: {v:#06x}"));
            result.sni = sig.sni;
            result.alpn = sig.alpn;
            return result;
        }
    };

    Ja4Result {
        ok: true,
        ja4: Some(sorted.full.value().to_owned()),
        ja4_r: Some(sorted.raw.value().to_owned()),
        ja4_o: Some(original.full.value().to_owned()),
        ja4_or: Some(original.raw.value().to_owned()),
        ja4_s1: Some(stable.full.value().to_owned()),
        ja4_s1r: Some(stable.raw.value().to_owned()),
        sni: sig.sni,
        alpn: sig.alpn,
        tls_version: Some(version_str.to_owned()),
        error: None,
        source: "huginn-net-tls".to_owned(),
    }
}

/// Compute JA3 fingerprint from raw TLS ClientHello bytes.
///
/// JA3 = MD5(TLSVersion,Ciphers,Extensions,SupportedGroups,ECPointFormats)
///
/// Each component is a hyphen-separated list of decimal integers, and the
/// whole string before hashing is comma-separated.
pub fn compute_ja3_from_client_hello(packet: &[u8]) -> Ja3Result {
    let sig = match parse_tls_client_hello(packet) {
        Ok(sig) => sig,
        Err(e) => {
            return Ja3Result::error(format!("Failed to parse ClientHello for JA3: {e}"));
        }
    };

    // TLS version as decimal integer
    let tls_version_id: u16 = match sig.version {
        TlsVersion::V1_3 => 771,
        TlsVersion::V1_2 => 770,
        TlsVersion::V1_1 => 769,
        TlsVersion::V1_0 => 768,
        TlsVersion::Ssl3_0 => 768,
        TlsVersion::Ssl2_0 => 767,
        TlsVersion::Unknown(v) => v,
    };

    // Cipher suites as comma-separated decimal IDs
    let ciphers_str = sig
        .cipher_suites
        .iter()
        .map(|cs| cs.to_string())
        .collect::<Vec<_>>()
        .join("-");

    // Extensions as comma-separated decimal IDs
    let extensions_str = sig
        .extensions
        .iter()
        .map(|ext| ext.to_string())
        .collect::<Vec<_>>()
        .join("-");

    // Supported groups / elliptic curves as comma-separated decimal IDs
    let curves_str = sig
        .elliptic_curves
        .iter()
        .map(|ec| ec.to_string())
        .collect::<Vec<_>>()
        .join("-");

    // EC point formats as comma-separated decimal IDs
    let point_formats_str = sig
        .elliptic_curve_point_formats
        .iter()
        .map(|pf| pf.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let ja3_string =
        format!("{tls_version_id},{ciphers_str},{extensions_str},{curves_str},{point_formats_str}");

    let ja3_hash = format!("{:x}", md5::compute(ja3_string.as_bytes()));

    Ja3Result {
        ok: true,
        ja3: Some(ja3_string),
        ja3_hash: Some(ja3_hash),
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_error() {
        let result = compute_ja4_from_client_hello(&[]);
        assert!(!result.ok);
        assert!(result.error.is_some());
        assert!(result.ja4.is_none());
    }

    #[test]
    fn garbage_input_returns_error() {
        let result = compute_ja4_from_client_hello(&[0xff; 100]);
        assert!(!result.ok);
        assert!(result.error.is_some());
    }

    /// A minimal valid TLS 1.2 ClientHello handshake record.
    /// This is a hand-crafted ClientHello sufficient to exercise the parser.
    fn minimal_client_hello() -> Vec<u8> {
        let mut buf = Vec::new();
        // TLS record header: ContentType::Handshake(22), TLS 1.2(0x0303), length placeholder
        buf.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x00]);
        // Handshake payload starts here
        let payload_start = buf.len();
        // Handshake: ClientHello(1), length placeholder (3 bytes)
        buf.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        // ClientHello body:
        // - client_version: TLS 1.2 (0x0303)
        buf.extend_from_slice(&[0x03, 0x03]);
        // - random: 32 zero bytes
        buf.extend_from_slice(&[0u8; 32]);
        // - session_id length: 0
        buf.push(0x00);
        // - cipher_suites length: 2 (one suite)
        buf.extend_from_slice(&[0x00, 0x02]);
        // - cipher_suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
        buf.extend_from_slice(&[0xC0, 0x2F]);
        // - compression_methods length: 1, method: null(0)
        buf.extend_from_slice(&[0x01, 0x00]);
        // - extensions length: 0
        buf.extend_from_slice(&[0x00, 0x00]);

        // Patch the record length (at bytes 3..5) and handshake length (at bytes 6..9)
        let payload_len = buf.len() - payload_start;
        // Record length = handshake payload length (2 bytes at offset 3)
        buf[3] = ((payload_len >> 8) & 0xff) as u8;
        buf[4] = (payload_len & 0xff) as u8;
        // Handshake length = payload_len - handshake header (4 bytes)
        let hs_len = payload_len.saturating_sub(4);
        buf[6] = ((hs_len >> 16) & 0xff) as u8;
        buf[7] = ((hs_len >> 8) & 0xff) as u8;
        buf[8] = (hs_len & 0xff) as u8;

        buf
    }

    #[test]
    fn parses_minimal_client_hello() {
        let packet = minimal_client_hello();
        let result = compute_ja4_from_client_hello(&packet);
        assert!(result.ok, "Error: {:?}", result.error);
        assert!(result.ja4.is_some());
        assert_eq!(result.tls_version.as_deref(), Some("TLS 1.2"));
        // The fingerprint should start with "t12" (TLS 1.2, no SNI → "i")
        assert!(result.ja4.as_ref().unwrap().starts_with("t12i"));
    }

    #[test]
    fn ja3_empty_input_returns_error() {
        let result = compute_ja3_from_client_hello(&[]);
        assert!(!result.ok);
        assert!(result.error.is_some());
        assert!(result.ja3.is_none());
    }

    #[test]
    fn ja3_parses_minimal_client_hello() {
        let packet = minimal_client_hello();
        let result = compute_ja3_from_client_hello(&packet);
        assert!(result.ok, "JA3 Error: {:?}", result.error);
        assert!(result.ja3.is_some());
        assert!(result.ja3_hash.is_some());
        // Hash should be 32 hex chars (MD5)
        assert_eq!(result.ja3_hash.as_ref().unwrap().len(), 32);
    }

    #[test]
    fn ja3_hash_is_valid_hex() {
        let packet = minimal_client_hello();
        let result = compute_ja3_from_client_hello(&packet);
        assert!(result.ok);
        let hash = result.ja3_hash.unwrap();
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
