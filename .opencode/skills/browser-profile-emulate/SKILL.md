---
name: browser-profile-emulate
description: "Implements or refreshes an evidence-backed Chrome/Firefox profile in this TLS+ repository from a completed browser capture manifest. Use when adding a canonical profile such as chrome_151 to wreq-util, updating profile fixtures, or translating measured TLS/HTTP2/header behavior into Rust. Do not use without verified capture artifacts, for general Rust refactors, or for anti-bot/WAF bypass."
compatibility: opencode
metadata:
  domain: tlsplus
  phase: emulate
---

# Browser Profile Emulation

Translate captured behavior into the smallest correct TLS+/wreq profile change. The capture manifest is the source of facts; the nearest existing Chrome profile is only an implementation candidate.

## Preconditions

1. Load the available `programming` skill before editing Rust, plus any project Rust-testing guidance that resolves successfully.
2. Read `.opencode/skills/browser-profile-lab/references/artifact-contract.md` and this skill's `references/tlsplus-map.md`.
3. Require measured `traffic_origin_verified: true` with a named selected flow, plus measured browser full/major version.
4. Require the requested canonical name to match the observed major version.
5. Require measured `tls_client_hello` evidence whose client/server 5-tuple, SNI, and TCP stream match the manifest's selected flow.

If these gates fail, produce an implementation gap report and stop. Do not make a scaffold variant that claims to emulate an unobserved browser.

## Workflow

### 1. Build an evidence matrix

Before editing, map each intended setting to:

```text
Dimension | Proposed value | Provenance | Artifact | Existing preset match | Action
```

Cover:

- User-Agent and Client Hints for every platform the profile will expose.
- Header initializer and observed request headers.
- TLS cipher, extension, curve/group, signature algorithm, ALPN, GREASE/ECH, and permutation behavior.
- HTTP/2 SETTINGS order/values, pseudo-header order, flow control, priority, and push/concurrency behavior.
- Expected JA4 and Akamai fixture values, when measured.

An unobserved dimension stays unknown. Reuse an existing preset only when its relevant measured behavior matches; record the comparison in `emulate/implementation.md`. The current platform macro silently falls back to the first row, so a platform without measured headers cannot merely be omitted.

### 2. Edit the minimal production surface

For a normal Chrome desktop version:

1. Add `ChromeNNN => ("chrome_NNN", vNNN::emulation)` to the profile enum in `crates/wreq-util/src/emulate.rs`.
2. Add one `mod_generator!` block named `vNNN` in `crates/wreq-util/src/emulate/profile/chrome.rs`.
3. Reuse existing private helpers in `chrome/{tls,http2,header}.rs` when evidence matches.

Do not create per-version files or flat prefixed modules. Do not migrate the existing Chrome module layout during an isolated profile addition.

Only add a new TLS or HTTP/2 preset when measured behavior cannot be represented by an existing one. Keep implementation modules private and expose the stable profile through the existing enum/macro path. Require measured platform rows for every exposed platform. If evidence exists for only one platform, block the normal canonical addition until either the remaining platforms are captured or the implementation can reject unsupported platform selection rather than falling back.

### 3. Update contracts and fixtures

- Add a live `test_emulation!` case in `crates/wreq-util/tests/emulate_chrome.rs` only when expected JA4/Akamai values are measured independently. Never commit placeholders.
- Treat the explicit arrays in `crates/tlsplus-core/tests/profile_mapping.rs` as a curated compatibility contract. The automatic `Profile::VARIANTS` assertion already covers new canonical profiles; update curated arrays and their count/name comments only when the new profile intentionally joins that compatibility set.
- Do not edit `crates/tlsplus-core/src/profiles.rs` for a normal canonical profile; it already exposes `Profile::VARIANTS` automatically.
- Add a TLS+ compatibility alias, weighted-random entry, README claim, or new default only when explicitly requested as a separate policy decision.

### 4. Verify

Run the smallest checks first, then package checks:

```bash
cargo check -p wreq-util
cargo test -p tlsplus-core --test profile_mapping
cargo test -p wreq-util --test emulate_chrome
cargo test -p wreq-util
cargo test -p tlsplus-core
cargo clippy -p wreq-util --all-targets
cargo clippy -p tlsplus-core --all-targets
```

The Chrome emulation integration test contacts a third-party service. Run it only when network access and endpoint use are authorized; otherwise mark it not run and use an owned fixture for manual QA.

After each Rust edit, run diagnostics on every changed Rust file. Review the diff to ensure unrelated profiles and policies did not change.

### 5. Manually QA the profile

Use a dedicated short-lived process that builds a fresh `wreq::Client` from the canonical `wreq_util::Profile` and exits after one request to the authorized fixture. Do not use TLS+ `HttpClient::for_profile` or the proxy to prove a fresh handshake because both use shared profile pools. Confirm a matching target ClientHello exists in the new pcap before handing it to `browser-profile-verify`.

## Output

Write `emulate/implementation.md` containing:

```text
Observed browser:
Canonical profile:
Changed files:
Reused presets and measured match:
New settings and supporting artifacts:
Unknown/unimplemented dimensions:
Tests and results:
Manual QA result:
Policy changes intentionally omitted:
```

## Reference

- `references/tlsplus-map.md` lists the current profile registration flow and file responsibilities.
