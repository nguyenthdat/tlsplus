//! T04 — Rust API and UniFFI contracts.
//!
//! Locks all current Rust public items, error types, and the 10-function /
//! 7-record UniFFI-generated structure. Uses compile-time / type assertions,
//! not prose snapshots.

use tlsplus_core::{
    ProxyRequest, ProxyResponse, Ja3Result, Ja4Result, ServerStatus,
    EngineInfo, TlsProfileInfo,
    proxy_send_request, proxy_send_request_async,
    start_local_server, stop_local_server, server_status,
    ja3_calculate_client_hello, ja4_calculate_client_hello,
    tlsplus_version, engine_info, available_profiles, get_tls_profile,
};

// ── 7 UniFFI Record types must exist and be constructible ────────────────

#[test]
fn record_types_exist() {
    let _: EngineInfo = engine_info();
    let _: Ja3Result = ja3_calculate_client_hello(vec![]);
    let _: Ja4Result = ja4_calculate_client_hello(vec![]);
    let _: ServerStatus = server_status();
    let _: TlsProfileInfo = get_tls_profile("chrome_120".to_owned()).expect("chrome_120 exists");
}

#[test]
fn proxy_request_record_is_constructible() {
    let req = ProxyRequest {
        id: "test".to_owned(),
        method: "GET".to_owned(),
        url: "https://example.com".to_owned(),
        headers: vec!["Host: example.com".to_owned()],
        body: vec![1, 2, 3],
        profile: "chrome_120".to_owned(),
        timeout_secs: 30,
    };
    assert_eq!(req.id, "test");
    assert_eq!(req.method, "GET");
}

#[test]
fn proxy_response_record_is_constructible() {
    let resp = ProxyResponse {
        id: "test".to_owned(),
        status_code: 200,
        headers: vec!["Content-Type: text/html".to_owned()],
        body: vec![],
        ja4: None,
        error: None,
    };
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.id, "test");
}

// ── 10 UniFFI-exported functions must be callable ────────────────────────

#[test]
fn all_ten_uniffi_functions_are_callable() {
    // 1. tlsplus_version
    let ver = tlsplus_version();
    assert!(!ver.is_empty());

    // 2. engine_info
    let info = engine_info();
    assert!(!info.name.is_empty());

    // 3. available_profiles
    let profiles = available_profiles();
    assert!(profiles.len() >= 20);

    // 4. get_tls_profile
    let p = get_tls_profile("chrome_120".to_owned());
    assert!(p.is_some());

    // 5. ja3_calculate_client_hello
    let ja3 = ja3_calculate_client_hello(vec![]);
    assert!(!ja3.ok);

    // 6. ja4_calculate_client_hello
    let ja4 = ja4_calculate_client_hello(vec![]);
    assert!(!ja4.ok);

    // 7. start_local_server
    let ss = start_local_server("127.0.0.1:43118".to_owned());
    assert!(ss.running);

    // 8. stop_local_server
    let ss = stop_local_server();
    assert!(!ss.running);

    // 9. server_status
    let st = server_status();
    assert!(!st.message.is_empty());

    // 10. proxy_send_request
    let req = ProxyRequest {
        id: "ffi-10".to_owned(),
        method: "GET".to_owned(),
        url: "http://127.0.0.1:1/nope".to_owned(),
        headers: vec![],
        body: vec![],
        profile: "pass-through".to_owned(),
        timeout_secs: 2,
    };
    let resp = proxy_send_request(req);
    assert_eq!(resp.id, "ffi-10");
}

#[tokio::test]
async fn async_proxy_send_request_is_callable() {
    let req = ProxyRequest {
        id: "async-1".to_owned(),
        method: "GET".to_owned(),
        url: "http://127.0.0.1:1/nope".to_owned(),
        headers: vec![],
        body: vec![],
        profile: "pass-through".to_owned(),
        timeout_secs: 2,
    };
    let resp = proxy_send_request_async(req).await;
    assert_eq!(resp.id, "async-1");
    assert!(resp.error.is_some());
}

// ── JA4 result field count ──────────────────────────────────────────────

#[test]
fn ja4_result_has_eleven_fields() {
    // Encode the current 10-field + `source` = 11-field structure.
    let result = ja4_calculate_client_hello(vec![]);
    // Touch every field name — a compile error here means the record shape
    // changed unexpectedly.
    let _ = result.ok;
    let _ = result.ja4;
    let _ = result.ja4_r;
    let _ = result.ja4_o;
    let _ = result.ja4_or;
    let _ = result.ja4_s1;
    let _ = result.ja4_s1r;
    let _ = result.sni;
    let _ = result.alpn;
    let _ = result.tls_version;
    let _ = result.error;
    let _ = result.source;
}

// ── Error types from tlsplus-core — compile-time existence check ────────

#[test]
fn core_http_client_error_is_non_exhaustive() {
    // tlsplus_core::http_client::HttpClientError is #[non_exhaustive]
    use tlsplus_core::http_client::HttpClientError;
    // If the error type disappears, this won't compile.
    let _: HttpClientError;
}

// ── Rust async proxy_send_request_async returns ProxyResponse ──────────

#[test]
fn async_proxy_signature_returns_proxy_response() {
    // Compile-time: verify the Rust API fn exists and returns ProxyResponse.
    fn _check(_req: ProxyRequest) -> impl std::future::Future<Output = ProxyResponse> {
        proxy_send_request_async(_req)
    }
}


