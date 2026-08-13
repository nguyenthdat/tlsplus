---
name: browser-profile-verify
description: "Differentially verifies a captured real browser against its TLS+ emulation using packet, TLS, HTTP/2, and request evidence from the same authorized fixture. Use to validate, compare, rerun, regress, or audit a new profile such as chrome_151 after implementation. Do not use for visual QA, generic tests, anti-bot scoring, WAF bypass, CAPTCHA evasion, or claims that automation is human."
compatibility: opencode
metadata:
  domain: browser-compatibility
  phase: verify
---

# Browser Profile Verification

Compare real and emulated clients under equivalent conditions and report protocol fidelity without overclaiming.

## Preconditions

1. Read `.opencode/skills/browser-profile-lab/references/artifact-contract.md`.
2. Require the real capture manifest, implementation report, and a resolvable TLS+ profile.
3. Use the same authorized endpoint, protocol capability, network path, and fresh-connection policy for both sides.
4. Do not compare a guest browser run with a host Playwright browser unless the manifest explicitly identifies them as the same target process.

## Workflow

### 1. Define the comparison plan

Classify each dimension as `exact`, `normalized`, `set`, `informational`, or `unavailable` before looking at the emulated result.

Required dimensions when measured on the real side:

- Browser identity and intended platform headers.
- TLS cipher-suite order.
- TLS extension order after normalizing dynamic GREASE values.
- Supported groups, signature algorithms, key-share behavior, ALPN, ECH/GREASE behavior.
- JA3/JA4 variants computed with the same implementation.
- HTTP/2 SETTINGS values and order, connection/stream windows, pseudo-header order, and priority behavior.
- Request header values, casing, order, and compression advertisement where observable.

An unavailable real-side dimension cannot pass by matching an inferred value.

### 2. Capture the emulated side

Run the canonical wreq-util profile against the same fixture in a dedicated short-lived process and collect `emulate/` artifacts with the capture skill's scripts. Build one new `wreq::Client`, perform one request, then exit. Do not use TLS+ direct/proxy shared pools for fresh-handshake evidence. Require the new pcap to contain the selected target ClientHello before comparison.

Exercise:

- Happy path: one successful navigation/request to the fixture.
- Controlled failure: use the direct `tlsplus_core::http_client::HttpClient::for_profile("does-not-exist")` validation path and require `UnknownProfile`. Do not use the proxy for this check because its current transport path falls back to `rustls_default`.

Repeat fresh connections when needed to distinguish stable ordering from dynamic GREASE/session fields.

### 3. Normalize only dynamic fields

Allowed normalization includes documented GREASE values, random/session identifiers, timestamps, ephemeral ports, and connection-specific key material.

Do not normalize away:

- Stable list ordering.
- Missing/extra extensions.
- Different ALPN.
- Different HTTP/2 settings or order.
- User-Agent or Client Hint differences.
- Header presence/order differences that the evidence contract marks exact.

Record every normalization rule in the report.

### 4. Compare and diagnose

For each mismatch, identify the likely implementation owner:

| Mismatch | Inspect |
|---|---|
| TLS cipher/extensions/groups/signatures/ALPN | `chrome/tls.rs` and selected TLS preset |
| HTTP/2 settings/order/windows/priority | `chrome/http2.rs` and selected H2 preset |
| User-Agent/Client Hints | `chrome.rs` platform row |
| Default headers/zstd/priority | `chrome/header.rs` initializer |
| Profile cannot resolve | `emulate.rs` enum/name dispatch and catalog tests |

Fix through `browser-profile-emulate`, then rerun only affected comparisons plus the full profile gate.

### 5. Write the report

Copy `assets/comparison-report.template.md` to `compare/report.md`. Attach evidence paths for every row.

Verdict rules:

- `PASS`: all required measured dimensions match.
- `PARTIAL`: all observed dimensions match, but required evidence is unavailable.
- `FAIL`: a stable required dimension mismatches.
- `BLOCKED`: identity, origin, fixture equivalence, or basic captures are invalid.

Never translate a passing protocol comparison into "human", "undetectable", "Cloudflare bypass", or equivalent language.

## Verification surface

The final manual QA has two parts: the dedicated-process wreq client supplies fresh-handshake evidence, then the actual TLS+ direct client or proxy proves the profile works through the product surface. The product-surface request may reuse a pool and is not accepted as fresh-handshake evidence. Inspect the pcap and report after both. Unit tests alone do not satisfy this gate.

## Output

Return the report path, verdict, exact mismatches, unavailable dimensions, normalization rules, commands run, and residual risks.
