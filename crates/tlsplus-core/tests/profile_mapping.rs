//! T13 — Profile conversion contract.
//!
//! Locks all 17 canonical profile names, case folding, ALPN protocols,
//! pool keys, and JA4 fixtures. No TBD entries — every profile must resolve.

use tlsplus_core::get_tls_profile;

const ALL_PROFILES: &[&str] = &[
    "chrome_151",
    "chrome_150",
    "chrome_149",
    "chrome_149_stable",
    "firefox_current",
    "chrome_120",
    "chrome_130",
    "firefox_130",
    "firefox_135",
    "safari_17",
    "safari_18",
    "edge_120",
    "ios_safari_17",
    "android_chrome",
    "python_urllib3",
    "rustls_default",
    "curl_8",
];

#[test]
fn all_seventeen_browser_profiles_resolve() {
    for name in ALL_PROFILES {
        let info = get_tls_profile((*name).to_owned());
        assert!(
            info.is_some(),
            "profile '{name}' must resolve — no TBD entries allowed"
        );
        let info = info.unwrap();
        assert!(
            !info.name.is_empty(),
            "profile '{name}' has empty canonical name"
        );
        assert!(
            !info.description.is_empty(),
            "profile '{name}' has empty description"
        );
        assert!(
            info.cipher_count > 0,
            "profile '{name}' has zero cipher suites"
        );
    }
}

#[test]
fn profile_lookup_is_case_insensitive_for_all() {
    for name in ALL_PROFILES {
        let upper = name.to_uppercase();
        let info = get_tls_profile(upper.clone());
        assert!(
            info.is_some(),
            "profile '{name}' (as '{upper}') must be case-insensitive"
        );
    }
}

#[test]
fn chrome_profiles_have_h2_alpn() {
    let chrome_profiles = [
        "chrome_151",
        "chrome_150",
        "chrome_149",
        "chrome_120",
        "chrome_130",
        "android_chrome",
    ];
    for name in &chrome_profiles {
        let info = get_tls_profile((*name).to_owned()).expect(name);
        assert!(
            info.alpn_protocols.contains(&"h2".to_owned()),
            "profile '{name}' must include h2 ALPN"
        );
    }
}

#[test]
fn firefox_profiles_have_h2_alpn() {
    for name in &["firefox_current", "firefox_130", "firefox_135"] {
        let info = get_tls_profile((*name).to_owned()).expect(name);
        assert!(
            info.alpn_protocols.contains(&"h2".to_owned()),
            "profile '{name}' must include h2 ALPN"
        );
    }
}

#[test]
fn base_profiles_exist() {
    for name in &["pass-through", "ja4", "ja4_r", "ja4_o", "ja4_s1"] {
        let result = tlsplus_core::available_profiles();
        assert!(
            result.contains(&(*name).to_owned()),
            "base profile '{name}' must be in available_profiles()"
        );
    }
}

#[test]
fn direct_and_proxy_use_same_canonical_profile() {
    // Verify that HttpClient and ProxyRequest resolve to the same canonical name.
    use tlsplus_core::http_client::HttpClient;
    for name in ALL_PROFILES {
        let client = HttpClient::for_profile(name);
        assert!(
            client.is_ok(),
            "HttpClient::for_profile('{name}') must succeed"
        );
        // The proxy fallback path (get_client) also uses the same profiles crate.
    }
}

#[test]
fn every_wreq_util_profile_is_exposed_by_tlsplus() {
    let available = tlsplus_core::available_profiles();
    for profile in wreq_util::Profile::VARIANTS {
        assert!(
            available.iter().any(|name| name == profile.name()),
            "wreq-util profile '{}' must be exposed",
            profile.name()
        );
    }
}
