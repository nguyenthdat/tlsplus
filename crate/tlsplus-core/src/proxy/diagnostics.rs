// ---------------------------------------------------------------------------
// JA4 diagnostic: measure outbound TLS fingerprints for each profile
// ---------------------------------------------------------------------------

#[cfg(test)]
mod ja4_diagnostic_tests {
    use std::io::Read;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::{Method, Request, Uri};
    use hyper_boring::HttpsConnector;
    use hyper_util::client::legacy::Client;
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::rt::TokioExecutor;

    /// Diagnostic test: measure the actual outbound JA4 fingerprint produced by
    /// each profile's TLS configuration (BoringSSL).
    ///
    /// ## How it works
    ///
    /// 1. Bind a raw `std::net::TcpListener` on an ephemeral port.
    /// 2. Spawn a thread that accepts one connection and reads raw bytes.
    /// 3. Build a profile-configured hyper client and connect via HTTPS.
    /// 4. The TLS client immediately sends its `ClientHello` on connect.
    /// 5. The server thread reads the `ClientHello` bytes.
    /// 6. Parse those bytes with `huginn_net_tls::parse_tls_client_hello`
    ///    and compute the JA4 hash.
    ///
    /// The HTTPS connection will *fail* (the raw TCP listener does not
    /// complete the TLS handshake), but that is expected — the JA4 is
    /// derived from the ClientHello alone, which is sent *before* any
    /// server response.
    #[test]
    #[ignore = "diagnostic: opens local TCP listeners for every profile; slow and unsuitable for CI — run manually with `cargo test -p tlsplus-core diagnostic_outbound_ja4_hashes -- --ignored --nocapture`"]
    fn diagnostic_outbound_ja4_hashes() {
        let profiles = crate::profiles::all_profiles();
        let mut results: Vec<(String, String)> = Vec::new();

        for profile in profiles {
            let profile_name = profile.name.clone();

            // 1. Bind a raw TCP listener on an ephemeral port
            let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("  SKIP '{profile_name}': bind failed: {e}");
                    continue;
                }
            };
            let port = listener.local_addr().unwrap().port();

            // 2. Shared buffer for captured ClientHello bytes
            let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
            let captured_clone = Arc::clone(&captured);

            // 3. Spawn server thread — accept one connection and read raw bytes
            let server_handle = std::thread::spawn(move || {
                let (mut stream, _) = match listener.accept() {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("  [server] accept failed: {e}");
                        return;
                    }
                };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let mut buf = [0u8; 16384];
                match stream.read(&mut buf) {
                    Ok(n) if n >= 5 => {
                        *captured_clone.lock().unwrap() = buf[..n].to_vec();
                    }
                    Ok(n) => {
                        eprintln!("  [server] read only {n} bytes (too short for TLS record)");
                    }
                    Err(e) => {
                        eprintln!("  [server] read error: {e}");
                    }
                }
            });

            // Give the server thread a moment to reach accept()
            std::thread::sleep(Duration::from_millis(50));

            // 4. Build SSL connector with profile settings
            let ssl_builder = match boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())
            {
                Ok(mut b) => {
                    if let Err(e) = crate::tls::configure_context(&mut b, profile) {
                        eprintln!("  SKIP '{profile_name}': TLS config failed: {e}");
                        let _ = server_handle.join();
                        continue;
                    }
                    // Disable certificate verification for localhost diagnostic
                    b.set_verify(boring::ssl::SslVerifyMode::NONE);
                    b
                }
                Err(e) => {
                    eprintln!("  SKIP '{profile_name}': SslConnector builder failed: {e}");
                    let _ = server_handle.join();
                    continue;
                }
            };

            // 5. Build a hyper client with this profile's TLS config
            let mut http = HttpConnector::new();
            http.set_connect_timeout(Some(Duration::from_secs(3)));
            http.set_nodelay(true);

            let https = match HttpsConnector::with_connector(http, ssl_builder) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("  SKIP '{profile_name}': HTTPS connector failed: {e}");
                    let _ = server_handle.join();
                    continue;
                }
            };

            use crate::proxy::client::ProxyBody;

            let client: Client<HttpsConnector<HttpConnector>, ProxyBody> =
                Client::builder(TokioExecutor::new()).build(https);

            // 6. Attempt HTTPS connection — ClientHello is sent immediately
            let target_url = format!("https://127.0.0.1:{port}/");
            crate::proxy::RUNTIME.block_on(async {
                if let Ok(uri) = target_url.parse::<Uri>() {
                    let body = Full::new(Bytes::new())
                        .map_err(|never: std::convert::Infallible| match never {})
                        .boxed();
                    let req = Request::builder()
                        .method(Method::GET)
                        .uri(uri)
                        .body(body)
                        .expect("build request");
                    let _ = client.request(req).await;
                }
            });

            // 7. Wait for server thread to finish reading
            let _ = server_handle.join();

            // 8. Parse and report
            let bytes = captured.lock().unwrap();
            if bytes.len() >= 5 {
                let result = crate::ja4::compute_ja4_from_client_hello(&bytes);
                if result.ok {
                    let ja4 = result.ja4.as_deref().unwrap_or("N/A");
                    println!("  {profile_name:25} JA4: {ja4}");
                    results.push((profile_name.clone(), ja4.to_owned()));
                } else {
                    eprintln!("  {profile_name:25} parse FAILED: {:?}", result.error);
                    eprintln!(
                        "    raw bytes ({}B): {:02X?}",
                        bytes.len(),
                        &bytes[..std::cmp::min(bytes.len(), 64)]
                    );
                }
            } else {
                eprintln!(
                    "  {profile_name:25} NO ClientHello captured ({}) bytes",
                    bytes.len()
                );
            }
        }

        // ── Summary ──
        println!();
        println!(
            "=== JA4 Diagnostic Results ({}/{}) ===",
            results.len(),
            crate::profiles::all_profiles().len()
        );
        for (name, ja4) in &results {
            println!("  {name:25} {ja4}");
        }

        // Sanity: at least one profile should produce a valid JA4
        assert!(
            !results.is_empty(),
            "No profiles produced valid JA4 hashes — diagnostic test failed"
        );
    }
}
