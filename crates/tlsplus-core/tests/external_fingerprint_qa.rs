use tlsplus_core::{ProxyRequest, proxy_send_request};

const CHROME_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36";

struct FingerprintTarget {
    name: &'static str,
    url: &'static str,
    expected_markers: &'static [&'static str],
}

const BROWSERSCAN: FingerprintTarget = FingerprintTarget {
    name: "BrowserScan",
    url: "https://tls.browserscan.net/api/tls",
    expected_markers: &["\"ja3_hash\"", "\"ja4\"", "\"tls\""],
};

const BROWSERLEAKS: FingerprintTarget = FingerprintTarget {
    name: "BrowserLeaks",
    url: "https://tls.browserleaks.com/tls?minify=1",
    expected_markers: &["\"ja3_hash\"", "\"ja4\"", "\"tls\""],
};

#[test]
#[ignore = "external TLS fingerprint QA; use `cargo test -p tlsplus-core --test external_fingerprint_qa -- --ignored --nocapture`"]
fn chrome_149_browserscan_fingerprint_qa() {
    run_fingerprint_qa(&BROWSERSCAN);
}

#[test]
#[ignore = "external TLS fingerprint QA; use `cargo test -p tlsplus-core --test external_fingerprint_qa -- --ignored --nocapture`"]
fn chrome_149_browserleaks_fingerprint_qa() {
    run_fingerprint_qa(&BROWSERLEAKS);
}

fn run_fingerprint_qa(target: &FingerprintTarget) {
    let response = proxy_send_request(ProxyRequest {
        id: format!("chrome149-{}", target.name.to_ascii_lowercase()),
        method: "GET".to_owned(),
        url: target.url.to_owned(),
        headers: vec![
            format!("User-Agent: {CHROME_UA}"),
            "Accept: application/json".to_owned(),
            "Accept-Language: en-US,en;q=0.9".to_owned(),
        ],
        body: vec![],
        profile: "chrome_149".to_owned(),
        timeout_secs: 30,
    });

    assert!(
        response.error.is_none(),
        "{} request failed: {}",
        target.name,
        response.error.as_deref().unwrap_or("unknown error")
    );
    assert_eq!(
        response.status_code, 200,
        "{} returned HTTP {}",
        target.name, response.status_code
    );

    let body = String::from_utf8_lossy(&response.body);
    for marker in target.expected_markers {
        assert!(
            body.contains(marker),
            "{} response did not include expected marker {marker}",
            target.name
        );
    }

    eprintln!(
        "{}: HTTP {} | required JA3/JA4/TLS fields present",
        target.name, response.status_code
    );
}
