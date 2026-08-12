# TLS+

TLS+ is a Burp Suite Montoya extension that routes Burp traffic through a native Rust TLS core so outbound requests can use configurable TLS/JA3/JA4 fingerprint profiles.

It is built as a Kotlin/JVM Burp extension with a Rust `cdylib` packaged inside the Burp-loadable jar through UniFFI and JNA.

## Current Capabilities

- Burp Montoya extension shell written in Kotlin.
- Native Rust core exposed to Kotlin through UniFFI-generated bindings.
- Direct Rust HTTP API backed by the shared profile-aware wreq client pool.
- Embedded local HTTP forward proxy with Hyper ingress and wreq outbound transport.
- Automatic proxy startup on extension load, defaulting to `127.0.0.1:43117`.
- Burp HTTP handler that redirects outgoing Burp traffic through the local TLS+ proxy when active mode is enabled.
- Burp Proxy handler that observes request header order for fingerprint diagnostics.
- Suite tab named `TLS+` with proxy controls, profile selection, JA3/JA4 helpers, profile details, and a proxy test panel.
- Native Burp Settings panel backed by Montoya `Preferences` for shared persistent settings.
- Raw ClientHello JA4 variants: `JA4`, `JA4_r`, `JA4_o`, `JA4_or`, `JA4_s1`, and `JA4_s1r`.
- Legacy JA3 calculation with MD5 hash.
- Browser TLS/HTTP profile presets backed by the in-repository wreq-util fork.

## Architecture

```text
Burp Suite
  -> Kotlin Montoya extension
       -> TlsPlusHttpHandler redirects requests to local proxy
       -> TlsPlusTab and TlsPlusSettingsPanel read/write shared Preferences
       -> UniFFI/JNA calls into native Rust library
  -> Rust tlsplus-core
       -> JA3/JA4 ClientHello parsing and fingerprint calculation
       -> Embedded Hyper forward proxy
       -> Per-profile wreq clients and connection pooling
       -> Streaming request/response forwarding

Rust applications
  -> tlsplus-core::http_client::HttpClient
       -> Buffered Hyper request input and streaming wreq response
       -> Direct use of the shared profile pool without the local proxy
```

Key files:

- `src/main/kotlin/com/tlsplus/burp/TlsPlusExtension.kt` registers the Burp tab, settings panel, HTTP handler, proxy handler, and proxy autostart.
- `src/main/kotlin/com/tlsplus/burp/settings/ExtensionSettings.kt` stores persistent extension settings in Burp preferences.
- `src/main/kotlin/com/tlsplus/burp/ui/TlsPlusTab.kt` implements the main Burp UI.
- `src/main/kotlin/com/tlsplus/burp/ui/TlsPlusSettingsPanel.kt` implements the native Burp Settings panel.
- `crates/tlsplus-core/src/lib.rs` exposes the UniFFI API.
- `crates/tlsplus-core/src/proxy/` contains the embedded forwarding proxy.
- `crates/tlsplus-core/src/profiles.rs` maps stable TLS+ labels to wreq-util emulation profiles.
- `crates/tlsplus-core/src/ja4.rs` computes JA3/JA4 fingerprints from raw ClientHello bytes.
- `crates/wreq/` and `crates/wreq-util/` are the editable in-repository transport forks.

## Requirements

- Java 21.
- Rust toolchain with Cargo.
- Gradle available as `gradle` on `PATH`.
- Burp Suite with a Montoya API runtime compatible with `2026.4`.
- A platform supported by the native library packaging task: macOS, Linux, or Windows.

There is no Gradle wrapper checked in, so use the locally installed `gradle` command.

CI uses `gradle/actions/setup-gradle` to provision Gradle explicitly.

## Build

Build the Burp-loadable fat jar:

```bash
gradle burpJar
```

The jar is written to:

```text
build/libs/tlsplus-extension.jar
```

`gradle build` also builds the jar because `assemble` depends on `burpJar`.

To include prebuilt native libraries for multiple platforms in one jar, pass a bundle directory containing `native/<platform>/<library>` entries:

```bash
gradle burpJar -Ptlsplus.nativeBundleDir=build/prebuilt-native
```

The Gradle build performs these steps:

1. Builds `crates/tlsplus-core` as a release Rust `cdylib`.
2. Generates Kotlin bindings with UniFFI.
3. Compiles the Kotlin Montoya extension.
4. Copies the current-platform native library into `native/<os>-<arch>/` resources.
5. Packages Kotlin classes, generated UniFFI bindings, JNA, runtime dependencies, and the native library into `tlsplus-extension.jar`.

Useful Rust-only commands:

```bash
cargo check -p tlsplus-core
cargo test -p tlsplus-core
cargo clippy -p tlsplus-core
cargo test -p wreq-util
```

## Rust HTTP Client

Use `tlsplus_core::http_client::HttpClient` to send Rust requests directly
through a profile-aware shared connection pool:

```rust
let client = tlsplus_core::http_client::HttpClient::for_profile("chrome_149")?;
let request = hyper::Request::builder()
    .uri("https://example.com")
    .header("accept", "text/html")
    .body(http_body_util::Full::new(bytes::Bytes::new()))?;
let response = client.request(request).await?.error_for_status()?;

println!("{}", response.text().await?);
```

Reuse an `HttpClient` for multiple requests. Clones share the same wreq
connection pool. The async client must run on a Tokio runtime.

## Load In Burp

1. Build `build/libs/tlsplus-extension.jar`.
2. Open Burp Suite.
3. Go to `Extensions` -> `Installed` -> `Add`.
4. Choose extension type `Java`.
5. Select `build/libs/tlsplus-extension.jar`.
6. Open the `TLS+` suite tab.

On load, TLS+ attempts to start the embedded proxy on `127.0.0.1:43117`. If the port is busy, it retries `43118` through `43122` and persists the selected fallback address.

## Runtime Settings

Settings are shared between the `TLS+` tab, the native Burp Settings panel, handlers, and the background proxy through Burp `Preferences`.

- `Pass-through only`: when enabled, Burp traffic uses Burp's normal TLS stack and TLS+ does not spoof TLS profiles.
- `Preserve header order`: logs observed request header order from Burp Proxy traffic for diagnostics.
- `Profile`: active TLS fingerprint profile used by the Rust forwarding proxy.
- `Listen address`: local embedded proxy bind address, default `127.0.0.1:43117`.

Default active profile: `chrome_149`.

## Profiles

The core exposes base labels, every profile declared by the in-repository
`wreq-util` fork, and a small compatibility alias set.

Base entries:

- `pass-through`
- `ja4`
- `ja4_r`
- `ja4_o`
- `ja4_s1`

Use `pass-through` or one of the built-in TLS profiles below for traffic forwarding. The `ja4*` labels are exposed for compatibility with the JA4 helper surface and are not browser spoofing profiles.

`wreq_util::Profile::VARIANTS` is the source of truth, so new fork profiles
automatically appear in `available_profiles()` without another core change.
Compatibility aliases include `chrome_149_stable`, `firefox_current`,
`firefox_130`, `safari_17`, `edge_120`, `ios_safari_17`, `android_chrome`,
`python_urllib3`, `rustls_default`, and `curl_8`.

Rust callers can build emulation settings directly with
`wreq_util::profile!(Chrome149)` or
`wreq_util::profile!(Chrome149, Android)`. Profile names round-trip through
`Profile::name()` and case-insensitive `Profile::from_name()`.

## How Traffic Flows

When active mode is enabled, `TlsPlusHttpHandler` rewrites outgoing Burp requests to the local TLS+ proxy service and adds internal forwarding headers:

- `X-Tlsplus-Target`: original destination URL.
- `X-Tlsplus-Profile`: selected TLS profile.
- `X-Tlsplus-Timeout`: per-request timeout in seconds.

The Rust proxy strips TLS+ internal headers and hop-by-hop headers, forwards the request to the original target with the selected TLS client profile, and streams the response back to Burp.

Requests to `127.0.0.1` and `localhost` are not redirected to avoid proxy loops.

## JA3/JA4 Helpers

The `TLS+` tab can compute JA3 and JA4 values from raw TLS ClientHello hex. For TCP TLS input, include the 5-byte TLS record header.

The Rust core returns:

- TLS version.
- SNI.
- ALPN.
- `JA4`, `JA4_r`, `JA4_o`, `JA4_or`, `JA4_s1`, `JA4_s1r`.
- Legacy `JA3` and `JA3 MD5`.

## Verification

Recommended local checks:

```bash
cargo test -p tlsplus-core
gradle build
```

Cloudflare connectivity QA is available in the Rust test suite:

```bash
cargo test -p tlsplus-core --test cloudflare_qa -- --nocapture
```

Targeted `chrome_149` human-score QA:

```bash
cargo test -p tlsplus-core --test cloudflare_qa chrome_149_human_score -- --nocapture
```

These tests contact external services and may fail because of network conditions or target-side bot-detection changes.

- https://www.browserscan.net/
- https://browserleaks.com/

## Known Limits

- TLS profile matching is best-effort and constrained by the available wreq-util profiles and Burp Montoya APIs.
- Burp HTTP handlers do not expose raw browser ClientHello bytes, so JA3/JA4 helper input must be supplied separately.
- Full MITM certificate generation is not implemented in the Rust core.
- A plain local `gradle burpJar` packages the native library for the platform where it is run. The GitHub Actions release workflow packages a single all-platform jar containing native libraries for macOS aarch64, Windows amd64/aarch64, and Linux amd64/aarch64.
- This is an internal research/testing extension. Use it only in environments where you are authorized to test traffic and TLS fingerprint behavior.
