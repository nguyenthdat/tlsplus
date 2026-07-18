# tlsplus-client

`tlsplus-client` is the ergonomic Rust HTTP API for TLS+. Its builders create
Hyper requests and send them directly through the fingerprint-aware
Hyper/BoringSSL connection pools in `tlsplus-core`. It does not start or route
through the embedded local proxy, and it does not convert requests through the
UniFFI `ProxyRequest`/`ProxyResponse` records. Calls run on Tokio; request and
response bodies are currently buffered in memory.

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

## Runnable example

A self-contained example ships in `examples/basic.rs`. It fetches a URL
through a reusable client, calls `error_for_status`, and prints the status,
final URL, TLS profile, and (optionally truncated) text body.

```sh
# Use the default URL and profile:
cargo run -p tlsplus-client --example basic

# Customize both:
cargo run -p tlsplus-client --example basic -- https://httpbin.org/ip chrome_149

# Use a different profile:
cargo run -p tlsplus-client --example basic -- https://example.com firefox_current
```

Positional arguments: `[URL] [PROFILE]`. Defaults are `https://example.com/`
and `chrome_149`.
