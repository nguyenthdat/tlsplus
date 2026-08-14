use super::*;

#[test]
fn classifies_idempotent_methods() {
    for method in [
        Method::GET,
        Method::HEAD,
        Method::OPTIONS,
        Method::PUT,
        Method::DELETE,
    ] {
        assert!(is_idempotent(&method));
    }
    assert!(!is_idempotent(&Method::POST));
    assert!(!is_idempotent(&Method::PATCH));
}

#[test]
fn preserves_repeated_header_values() {
    let headers = vec!["X-Value: one".to_owned(), "X-Value: two".to_owned()];
    let map = build_forward_headers(&headers);
    let values: Vec<_> = map
        .get_all("x-value")
        .iter()
        .map(|value| value.to_str().expect("test header is UTF-8"))
        .collect();
    assert_eq!(values, ["one", "two"]);
}

#[test]
fn extracts_ja4_from_the_tls_diagnostic_response() {
    let uri = "https://tls.peet.ws/api/all"
        .parse::<wreq::Uri>()
        .expect("parse diagnostic URI");
    let body = br#"{"tls":{"ja4":"t13d1516h2_8daaf6152771_02713d6af862"}}"#;

    assert_eq!(
        diagnostic_ja4(&uri, hyper::StatusCode::OK, body),
        Some("t13d1516h2_8daaf6152771_02713d6af862".to_owned())
    );
}

#[test]
fn ignores_ja4_from_an_untrusted_response() {
    let uri = "https://example.com/api/all"
        .parse::<wreq::Uri>()
        .expect("parse arbitrary URI");
    let body = br#"{"tls":{"ja4":"spoofed"}}"#;

    assert_eq!(diagnostic_ja4(&uri, hyper::StatusCode::OK, body), None);
}

#[test]
fn accepts_the_canonical_diagnostic_uri_only() {
    let body = br#"{"tls":{"ja4":"t13d1516h2_8daaf6152771_02713d6af862"}}"#;
    let accepted = [
        "https://tls.peet.ws/api/all",
        "https://TLS.PEET.WS:443/api/all",
    ];
    let rejected = [
        "http://tls.peet.ws/api/all",
        "https://tls.peet.ws:444/api/all",
        "https://tls.peet.ws/api/all?source=spoof",
        "https://tls.peet.ws/api/other",
        "https://tls.peet.ws.evil.example/api/all",
    ];

    for uri in accepted {
        assert!(diagnostic_ja4(
            &uri.parse().expect("parse accepted URI"),
            hyper::StatusCode::OK,
            body
        )
        .is_some());
    }
    for uri in rejected {
        assert_eq!(
            diagnostic_ja4(
                &uri.parse().expect("parse rejected URI"),
                hyper::StatusCode::OK,
                body
            ),
            None
        );
    }
}

#[test]
fn rejects_invalid_diagnostic_ja4_values() {
    let uri = "https://tls.peet.ws/api/all"
        .parse::<wreq::Uri>()
        .expect("parse diagnostic URI");
    let rejected = [
        br#"{"tls":{"ja4":""}}"#.as_slice(),
        br#"{"tls":{"ja4":"line\nbreak"}}"#.as_slice(),
        br#"{"tls":{"ja4":"not a fingerprint"}}"#.as_slice(),
        br#"{"tls":{}}"#.as_slice(),
        br#"not-json"#.as_slice(),
    ];

    for body in rejected {
        assert_eq!(diagnostic_ja4(&uri, hyper::StatusCode::OK, body), None);
    }
}

#[test]
fn rejects_ja4_from_a_non_success_response() {
    let uri = "https://tls.peet.ws/api/all"
        .parse::<wreq::Uri>()
        .expect("parse diagnostic URI");
    let body = br#"{"tls":{"ja4":"t13d1516h2_8daaf6152771_02713d6af862"}}"#;

    assert_eq!(
        diagnostic_ja4(&uri, hyper::StatusCode::SERVICE_UNAVAILABLE, body),
        None
    );
}
