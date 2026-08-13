---
name: browser-profile-lab
description: "Coordinates the complete authorized browser-profile workflow: capture a real installed browser build in Parallels, translate measured TLS/HTTP behavior into tlsplus/wreq, and compare real versus emulated output. Use when asked to add, refresh, rerun, or audit a browser profile such as Chrome 151. Do not use for ordinary Playwright browsing, visual QA, bot/WAF bypass, CAPTCHA evasion, or identity rotation."
compatibility: opencode
metadata:
  domain: browser-compatibility
  workflow: capture-emulate-verify
---

# Browser Profile Lab

Coordinate an evidence-first pipeline for adding browser profiles to TLS+. A version in a request, such as "Chrome 151", is a target, not an observed fact.

## Safety and scope

Proceed only for environments and endpoints the user owns or is authorized to test. Keep the workflow focused on interoperability, regression testing, and faithful protocol reproduction.

Do not optimize for anti-bot scores or advise on WAF bypass, CAPTCHA evasion, account farming, rotating identities, residential proxies, or concealing automation. A profile comparison can report protocol similarity; it cannot certify that automation is "human" or undetectable.

## Artifact contract

Read `references/artifact-contract.md` before dispatching any phase. Copy `assets/capture-manifest.template.json` into the run directory and fill it from evidence.

Every material value has one provenance state:

- `measured`: directly present in a named artifact.
- `inferred`: derived from measured facts, with the rule and confidence recorded.
- `unknown`: not established by the current evidence.

Never silently promote an inferred or unknown value to measured.

## Workflow

### Phase 0: Resolve the run

1. Record the requested browser family/version, channel, guest OS, VM identifier, authorized test endpoint, and desired TLS+ profile name.
2. Use `prlctl list --all --json` and `prlctl status <VM>` to discover VM state. Do not guess a VM name, interface, browser path, guest shell, or remote-debugging endpoint.
3. Check for an existing run directory:
   - Same installed browser build and a partial rerun: preserve it and create a new capture/attempt directory for the repeated phase.
   - New browser build or platform: create a new run; do not overwrite old evidence.
4. If the exact browser binary cannot report its version, stop before implementation. A requested `chrome_151` label is invalid evidence by itself.

### Phase 1: Capture the real browser

Load `browser-profile-capture` and produce a complete real-browser evidence bundle.

Gate to continue:

- The installed binary reports the expected family and exact version.
- Browser location is proven to be the intended Parallels guest or the manifest clearly says otherwise.
- The packet capture contains a fresh, selected client-to-fixture flow with a matching SNI ClientHello.
- Missing HTTP/2, header-order, or TLS facts remain `unknown` rather than guessed.

### Phase 2: Implement the emulation

Load `browser-profile-emulate`. Give it the capture manifest and artifact directory, not a prose-only summary.

Gate to continue:

- The canonical name is derived only after it matches the observed major version.
- Every platform exposed by the profile has platform-specific measured evidence; otherwise implementation is blocked until the code can reject unsupported platforms instead of falling back.
- Rust changes cite which artifact supports each changed TLS, HTTP/2, and header value.
- New live fixtures contain measured expected values; no placeholder JA4 or Akamai hashes exist.
- Targeted compile and tests pass.

### Phase 3: Differential verification

Load `browser-profile-verify`. Run real and emulated clients against the same authorized fixture under equivalent network conditions.

Gate to finish:

- The comparison report distinguishes exact matches, acceptable dynamic differences, mismatches, and unavailable evidence.
- At least one dedicated-process fresh-connection happy path and a direct-client invalid-profile failure path were exercised.
- The verdict is `PASS`, `PARTIAL`, `FAIL`, or `BLOCKED`; it is not an anti-detection claim.

### Phase 4: Handoff

Return:

```text
Profile:
Observed browser build:
Guest platform:
Run directory:
Implementation files:
Verification verdict:
Measured gaps:
Residual risks:
Commands executed:
```

## Error policy

- Retry a transient capture or test once in a new capture/attempt directory.
- On a second failure, preserve artifacts and mark the phase `BLOCKED` or `PARTIAL`.
- Never fill a gap from the nearest Chrome profile without recording it as an inference and validating it.
- VM power changes, snapshot creation/switch/deletion, VM deletion, network reconfiguration, credential embedding, and deleting captures require explicit user authorization.

## Test scenarios

### Happy path

The user has equivalent authorized captures for every platform the profile will expose, including a Windows VM with Chrome 151 and an owned diagnostic endpoint. Each capture proves version `151.x`, a selected fresh ClientHello flow, request headers, and HTTP/2 settings; implementation adds `chrome_151`; a dedicated-process differential run passes with only GREASE/session randomness normalized.

### Error path

The request says Chrome 151, but the guest binary reports Chrome 150 or Playwright is attached to host Chrome. Stop before implementation, retain the evidence, and report the identity/location mismatch.

## References

- `references/artifact-contract.md` defines directories, required fields, and provenance.
- `assets/capture-manifest.template.json` is the canonical run manifest template.
