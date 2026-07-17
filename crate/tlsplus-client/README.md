# tlsplus-client

`tlsplus-client` is the ergonomic Rust HTTP API for TLS+. It wraps the
fingerprint-aware Hyper/BoringSSL engine in `tlsplus-core` so callers do not
need to construct Hyper connectors, bodies, or requests directly. Calls run on
Tokio; direct request and response bodies are currently buffered in memory.

```rust
use std::time::Duration;
use tlsplus_client::Client;

# async fn example() -> Result<(), tlsplus_client::Error> {
let client = Client::builder()
    .profile("chrome_149")
    .timeout(Duration::from_secs(15))
    .default_header("user-agent", "Mozilla/5.0 ...")
    .build()?;

let response = client
    .get("https://example.com/api")
    .query(&[("page", 1)])
    .send()
    .await?
    .error_for_status()?;

println!("{}", response.text().await?);
# Ok(())
# }
```

For one-off requests:

```rust
# async fn example() -> Result<(), tlsplus_client::Error> {
let body = tlsplus_client::get("https://example.com")
    .profile("firefox_current")
    .send()
    .await?
    .text()
    .await?;
# Ok(())
# }
```

The initial API supports reusable clients, per-client and per-request TLS
profiles/timeouts, default and request headers, query serialization, raw or
JSON request bodies, buffered bytes/text/JSON responses, and
`error_for_status`.
