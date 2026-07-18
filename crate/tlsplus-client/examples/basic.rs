//! Basic TLS+ HTTP client example.
//!
//! Demonstrates the ergonomic `tlsplus_client::Client` builder and the direct
//! Rust HTTP path through `tlsplus_core`'s fingerprint-aware BoringSSL pools.
//!
//! # Usage
//!
//! ```sh
//! cargo run -p tlsplus-client --example basic -- [URL] [PROFILE]
//! ```
//!
//! Defaults: `https://example.com/` and `chrome_149`.

use std::{env, time::Duration};

use tlsplus_client::Client;

const DEFAULT_URL: &str = "https://example.com/";
const DEFAULT_PROFILE: &str = "chrome_149";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const BODY_DISPLAY_LIMIT: usize = 512;

#[tokio::main]
async fn main() -> Result<(), tlsplus_client::Error> {
    let mut args = env::args().skip(1);
    let url = args.next().unwrap_or_else(|| DEFAULT_URL.to_owned());
    let profile = args.next().unwrap_or_else(|| DEFAULT_PROFILE.to_owned());

    let client = Client::builder()
        .profile(&profile)
        .timeout(REQUEST_TIMEOUT)
        .default_header("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .default_header("accept-language", "en-US,en;q=0.9")
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
        )
        .build()?;

    let response = client.get(&url).send().await?.error_for_status()?;

    println!("status : {}", response.status());
    println!("url    : {}", response.url());
    println!("profile: {}", response.profile());

    let body = response.text().await?;
    if body.len() <= BODY_DISPLAY_LIMIT {
        println!("body   : {body}");
    } else {
        let end = floor_char_boundary(&body, BODY_DISPLAY_LIMIT);
        println!("body   : {}…", &body[..end]);
        println!("        ({} bytes total, truncated)", body.len());
    }

    Ok(())
}

/// Returns the greatest byte index `<= limit` that sits on a UTF-8 character
/// boundary in `text`.
fn floor_char_boundary(text: &str, limit: usize) -> usize {
    let limit = limit.min(text.len());
    if text.is_char_boundary(limit) {
        limit
    } else {
        // Back up to the previous character boundary.
        (0..limit)
            .rev()
            .find(|&i| text.is_char_boundary(i))
            .unwrap_or(0)
    }
}
