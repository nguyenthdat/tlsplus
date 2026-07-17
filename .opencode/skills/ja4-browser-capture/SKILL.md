---
name: ja4-browser-capture
description: JA4 browser capture workflow for tlsplus using Wireshark/tshark, Chrome DevTools MCP, Firefox DevTools MCP, Playwright MCP, Cloakbrowser profiles, Cloudflare Manfredi, and bot/fingerprint QA pages. Use when capturing browser ClientHello/JA4 profiles or validating TLS fingerprints against bot checks.
---

# JA4 Browser Capture

Use this skill to capture real browser TLS ClientHello data, derive JA4/JA3/profile candidates, and score the same browser profile against controlled bot-detection pages.

## Principles

- Capture evidence first, then change tlsplus. Do not guess browser TLS profiles from docs alone.
- Prefer real packet capture over browser-reported network data for JA4.
- Use every user-defined browser/profile in scope, including Cloakbrowser profiles. Do not impose a single Chrome-only matrix.
- Keep artifacts local in `_ja4_capture_workspace/`; do not paste raw packet dumps, cookies, or private browsing data into chat.
- Treat external bot-check sites as unstable. Record screenshots/text and continue when a target changes or fails.

## Preflight

Record this into `_ja4_capture_workspace/{run}/00_preflight.md`:

```sh
tshark -v
dumpcap -D
tshark -G fields | rg -i 'ja4|ja3|tls.handshake|handshake.extensions|supported_groups|alpn'
```

If `tshark` or `dumpcap` is unavailable, fall back to browser/MCP network logs and document that packet-level JA4 extraction is unavailable.

## Profile Matrix

Build `_ja4_capture_workspace/{run}/01_profile_matrix.json` with entries like:

```json
[
  {
    "id": "chrome-devtools-current",
    "driver": "chrome.devtools",
    "browser": "chrome",
    "executable_path": null,
    "user_data_dir": null,
    "notes": "Existing Chrome DevTools MCP session"
  },
  {
    "id": "firefox-devtools-current",
    "driver": "firefox.devtools",
    "browser": "firefox",
    "executable_path": null,
    "user_data_dir": null,
    "notes": "Existing Firefox DevTools MCP session"
  },
  {
    "id": "cloakbrowser-profile-name",
    "driver": "playwright-custom-executable",
    "browser": "chromium-compatible",
    "executable_path": "/path/to/CloakBrowser",
    "user_data_dir": "/path/to/profile",
    "notes": "User-defined Cloakbrowser profile"
  }
]
```

Accept profile definitions from explicit prompt data, `TLSPLUS_BROWSER_PROFILES_JSON`, `CLOAKBROWSER_EXECUTABLE`, `CLOAKBROWSER_PROFILE_DIR`, Playwright env vars, and available MCP browsers.

## Capture Pattern

For each profile:

1. Create `captures/`, `browser/{profile}/`, `scores/`, and `extracted/` under the run directory.
2. Start targeted capture with `tshark` or `dumpcap` on the selected interface. Prefer capture filters like `tcp port 443` plus host restrictions when practical.
3. Navigate the primary target and secondary targets with the matching driver.
4. Save screenshot, page text/snapshot, console logs, and network logs.
5. Stop capture and extract ClientHello fields.

Example extraction commands to adapt after field preflight:

```sh
tshark -r captures/profile.pcapng -Y 'tls.handshake.type == 1' -T fields \
  -e frame.number \
  -e ip.src \
  -e ip.dst \
  -e tcp.dstport \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.ja3 \
  -e tls.handshake.ja4
```

If `tls.handshake.ja4` is not available, export JSON or PDML for ClientHello and compute/compare using tlsplus parser code:

```sh
tshark -r captures/profile.pcapng -Y 'tls.handshake.type == 1' -T json > extracted/profile.clienthello.json
```

## Bot QA Targets

Primary target:

- `https://cloudflare.manfredi.io/test/`

Parse and record the exact visible result. Aim for `You are not a verified bot and you are 98% human` or a higher human percentage. Store result in `scores/{profile}.bot-score.json`.

Secondary targets:

- `https://bot.sannysoft.com/`
- `https://abrahamjuliot.github.io/creepjs/`
- `https://pixelscan.net/`
- `https://iphey.com/`
- `https://www.browserscan.net/bot-detection`
- `https://browserleaks.com/client-hints`
- `https://browserleaks.com/webrtc`
- `https://fingerprint.com/products/bot-detection/`

Run at least two secondary targets for QA when possible. Save screenshots because page DOM and wording change frequently.

## Playwright And Cloakbrowser

The project MCP config intentionally does not lock Playwright MCP to `--browser chrome`. Use Playwright MCP for normal runs, and use bash-driven Playwright when a custom executable or persistent Cloakbrowser profile is required.

Recommended Playwright options when launching outside MCP:

- Use headed mode unless the user explicitly wants headless, because headless often changes bot-score behavior.
- Use persistent contexts for user-defined browser profiles.
- Pass explicit executable paths for Cloakbrowser or other Chromium-compatible browsers.
- Keep viewport, locale, timezone, UA, and client hints consistent with the actual profile; do not spoof one layer while leaving contradictions elsewhere.

## Report Template

Write `_ja4_capture_workspace/{run}/report.md`:

```markdown
# JA4 Browser Capture Report

## Summary
[PASS/WARN/FAIL, best profile, Cloudflare human percentage]

## Profile Matrix
[Browsers/profiles tested]

## Primary Target
- URL: https://cloudflare.manfredi.io/test/
- Best result: [exact text]
- Human percentage: [number]

## Secondary Bot Checks
[Table of target, result, screenshot path]

## JA4 Extraction
[JA4/JA3 per profile, field availability, pcap path]

## tlsplus Candidate
[Path to tlsplus_profile_candidates.json and mapping notes]

## Regressions Or Risks
[Known issues, inconsistent browser signals, missing capture evidence]
```

## QA Decision

- `PASS`: Cloudflare Manfredi says not verified bot and no material baseline regression; target human percentage is at least `98%` when achievable.
- `WARN`: site unavailable, partial capture, or score below target but secondary checks remain usable.
- `FAIL`: verified bot/bot-like result, large regression, or no packet capture for a TLS-profile change.
