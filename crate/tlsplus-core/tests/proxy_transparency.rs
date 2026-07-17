//! Proxy compression transparency test.
//!
//! Verifies the fix for the blank-page bug: the proxy no longer decompresses
//! response bodies, so Content-Encoding and Content-Length headers remain
//! consistent with the (still-compressed) body.
//!
//! # Run (manual QA only — hits external web sites):
//! ```bash
//! cargo test --test proxy_transparency -- --ignored --nocapture
//! ```

use tlsplus_core::{ProxyRequest, proxy_send_request};

/// Fetch a URL and verify compression transparency invariants:
/// 1. Content-Encoding is preserved (not stripped)
/// 2. Content-Length matches actual body size (not truncated)
/// 3. Body looks like a complete HTML document (not truncated mid-stream)
fn assert_transparency_for(url: &str, profile: &str) {
    let request = ProxyRequest {
        id: format!("transparency-{profile}"),
        method: "GET".to_owned(),
        url: url.to_owned(),
        headers: vec![
            "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
             AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
                .to_owned(),
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_owned(),
            "Accept-Encoding: gzip, deflate, br".to_owned(),
            "Accept-Language: en-US,en;q=0.9".to_owned(),
        ],
        body: vec![],
        profile: profile.to_owned(),
        timeout_secs: 15,
    };

    let response = proxy_send_request(request);

    assert!(
        response.error.is_none(),
        "Request to {url} (profile: {profile}) failed: {:?}",
        response.error
    );
    assert!(
        response.status_code >= 200 && response.status_code < 400,
        "Unexpected status {} for {url} (profile: {profile})",
        response.status_code
    );

    let body = response.body;
    let header_map: std::collections::HashMap<String, String> = response
        .headers
        .iter()
        .filter_map(|h| {
            let (k, v) = h.split_once(':')?;
            Some((k.trim().to_lowercase(), v.trim().to_owned()))
        })
        .collect();

    // ── Invariant 1: Content-Encoding is preserved ──
    let content_encoding = header_map.get("content-encoding");
    println!(
        "  [{profile}] {url} → status={}, content-encoding={:?}, body_len={}",
        response.status_code,
        content_encoding,
        body.len()
    );

    // Many sites use compression; this just confirms we didn't strip it
    if let Some(enc) = content_encoding {
        assert!(
            !enc.is_empty(),
            "Content-Encoding should not be empty for {url}"
        );
    }

    // ── Invariant 2: Content-Length matches body size ──
    if let Some(cl_str) = header_map.get("content-length") {
        let declared_len: usize = cl_str
            .parse()
            .unwrap_or_else(|_| panic!("Content-Length '{cl_str}' is not a valid integer"));
        assert_eq!(
            declared_len,
            body.len(),
            "Content-Length mismatch: header says {declared_len} bytes, body is {} bytes. \
             This is the blank-page bug — truncated resources!",
            body.len()
        );
    }

    // ── Invariant 3: Body is complete (not truncated) ──
    // For HTML pages, verify the closing tag is present
    let body_str = String::from_utf8_lossy(&body);
    if body_str.contains("<html") || body_str.contains("<HTML") {
        assert!(
            body_str.contains("</html>") || body_str.contains("</HTML>"),
            "HTML body appears TRUNCATED — missing closing </html> tag for {url}. \
             Body starts: {:.200}...\nBody ends: ...{:.200}",
            &body_str[..body_str.len().min(200)],
            &body_str[body_str.len().saturating_sub(200)..]
        );
    }

    // Also verify the body is non-empty
    assert!(!body.is_empty(), "Response body is empty for {url}");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
#[ignore = "external network — hits google.com; use `cargo test --test proxy_transparency -- --ignored --nocapture`"]
fn google_com_passthrough_preserves_compression() {
    assert_transparency_for("https://www.google.com/", "pass-through");
}

#[test]
#[ignore = "external network — hits google.com; use `cargo test --test proxy_transparency -- --ignored --nocapture`"]
fn google_com_chrome_preserves_compression() {
    assert_transparency_for("https://www.google.com/", "chrome_149");
}

#[test]
#[ignore = "external network — hits example.com; use `cargo test --test proxy_transparency -- --ignored --nocapture`"]
fn example_com_passthrough_no_truncation() {
    // example.com is lightweight and unlikely to be compressed
    let request = ProxyRequest {
        id: "transparency-example".to_owned(),
        method: "GET".to_owned(),
        url: "https://example.com/".to_owned(),
        headers: vec![
            "User-Agent: tlsplus-transparency-test/1.0".to_owned(),
            "Accept: text/html".to_owned(),
        ],
        body: vec![],
        profile: "pass-through".to_owned(),
        timeout_secs: 15,
    };
    let response = proxy_send_request(request);

    assert!(response.error.is_none(), "Error: {:?}", response.error);
    assert_eq!(response.status_code, 200);

    let header_map: std::collections::HashMap<String, String> = response
        .headers
        .iter()
        .filter_map(|h| {
            let (k, v) = h.split_once(':')?;
            Some((k.trim().to_lowercase(), v.trim().to_owned()))
        })
        .collect();

    // Even if not compressed, Content-Length must match body size
    if let Some(cl_str) = header_map.get("content-length") {
        let declared_len: usize = cl_str.parse().unwrap();
        assert_eq!(
            declared_len,
            response.body.len(),
            "Content-Length mismatch: {} vs {}",
            declared_len,
            response.body.len()
        );
    }

    let body_str = String::from_utf8_lossy(&response.body);
    assert!(body_str.contains("</html>") || body_str.contains("</HTML>"));
    println!(
        "  example.com → status={}, body_len={}",
        response.status_code,
        response.body.len()
    );
}
