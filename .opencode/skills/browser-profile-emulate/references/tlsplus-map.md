# TLS+ Browser Profile Extension Map

## Canonical flow

```text
wreq_util::Profile::ChromeNNN
  -> Profile::match_emulation()
  -> chrome::vNNN::emulation()
  -> build_emulation()
  -> build_standard_emulation()
  -> wreq::Emulation

Profile::VARIANTS
  -> tlsplus-core TlsProfile::from_wreq()
  -> available_profiles()
  -> HttpClient and proxy shared profile pool
```

## File responsibilities

| Path | Responsibility | Normal new Chrome profile action |
|---|---|---|
| `crates/wreq-util/src/emulate.rs` | Profile enum, canonical name, dispatch, variants | Add `ChromeNNN` mapping |
| `crates/wreq-util/src/emulate/profile/chrome.rs` | Version modules and platform headers | Add one `vNNN` `mod_generator!` block |
| `crates/wreq-util/src/emulate/profile/chrome/tls.rs` | Reusable Chrome TLS presets | Reuse; extend only from measured mismatch |
| `crates/wreq-util/src/emulate/profile/chrome/http2.rs` | Reusable HTTP/2 presets | Reuse; extend only from measured mismatch |
| `crates/wreq-util/src/emulate/profile/chrome/header.rs` | Header initializers | Select from measured headers |
| `crates/wreq-util/src/emulate/macros.rs` | Enum/module/header macros | Normally no change |
| `crates/wreq-util/tests/emulate_chrome.rs` | Live profile fingerprints | Add only measured fixture |
| `crates/tlsplus-core/src/profiles.rs` | Automatic TLS+ catalog mapping and aliases | No canonical-profile edit normally |
| `crates/tlsplus-core/tests/profile_mapping.rs` | Curated compatibility arrays plus automatic canonical catalog assertion | Rely on `Profile::VARIANTS`; update curated arrays/comments only by policy |
| `README.md` | User-facing documentation | Update only for a deliberate catalog/default claim |

## Evidence mapping

| Captured evidence | Implementation area |
|---|---|
| User-Agent, `sec-ch-ua`, platform hints | `chrome.rs` platform rows |
| Cipher/extension/group/signature/ALPN order | existing or new `tls_options!` preset |
| HTTP/2 settings/order/flow control/priority | existing or new `http2_options!` preset |
| Request headers and observed priority/zstd behavior | header initializer selection |
| Measured JA4 and Akamai hash | `tests/emulate_chrome.rs` fixture |

Do not derive browser identity from a ClientHello or expected fixtures from a version string.

## Platform and connection caveats

- `Platform` defaults to macOS.
- `platform_headers!` falls back to the first row for every unlisted platform. Require evidence for each exposed row or change the implementation to reject unsupported platforms.
- TLS+ direct and proxy surfaces share cached clients. For fresh-handshake QA, launch a short-lived process that constructs one new `wreq::Client` from the canonical wreq-util profile, performs one request, and exits.
