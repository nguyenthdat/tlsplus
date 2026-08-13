# Browser Profile Artifact Contract

## Run layout

Use a new immutable run directory for each browser build and guest platform. Every retry gets a new attempt directory:

```text
artifacts/browser-profiles/<family>-<full-version>/<guest-os>/<capture-id>/
|-- manifest.json
|-- real/
|   |-- browser-version.txt
|   |-- vm.json
|   |-- vm.png
|   |-- attempts/<attempt-id>/capture.pcapng
|   |-- attempts/<attempt-id>/capture-summary.json
|   |-- attempts/<attempt-id>/client-hello.tsv
|   |-- attempts/<attempt-id>/http2-settings.tsv
|   |-- playwright-requests.md
|   `-- notes.md
|-- emulate/
|   |-- implementation.md
|   |-- attempts/<attempt-id>/capture.pcapng
|   |-- attempts/<attempt-id>/capture-summary.json
|   |-- attempts/<attempt-id>/client-hello.tsv
|   `-- attempts/<attempt-id>/http2-settings.tsv
`-- compare/
    `-- report.md
```

Only `manifest.json`, `browser-version.txt`, and the packet-level artifacts needed for the current comparison are required. Other files are required when that evidence source is used. Never overwrite or reuse an attempt directory.

Do not commit credentials, cookies, authorization headers, TLS key logs, private browsing data, or captures unrelated to the authorized fixture. Store sensitive transient artifacts outside the repository and reference them without copying secrets into the manifest.

## Identity gate

The requested version is never evidence. Before naming a profile `chrome_NNN`, capture the version emitted by the exact browser binary that generated the network traffic.

Record separately:

- Browser family.
- Full version.
- Major version.
- Channel, or `unknown`.
- Binary path or application identity.
- Guest OS and architecture.
- Whether Playwright was attached to this exact process, with provenance.

If browser version and traffic origin cannot be linked, the run is `BLOCKED` for profile implementation.

## Provenance record

Each observation uses this shape:

```json
{
  "status": "measured",
  "value": "151.0.0.0",
  "evidence": "real/browser-version.txt",
  "method": "exact browser binary version command",
  "confidence": "high",
  "notes": null
}
```

Allowed `status` values are `measured`, `inferred`, and `unknown`. Use `value: null` for unknowns. Every inference names its rule and supporting measured inputs. Identity, traffic-origin, Playwright-attachment, and fresh-connection gates use the same record shape; bare booleans are not evidence. Traffic-origin evidence also names the selected client IP/port, fixture IP/port/SNI, TCP stream, and timestamp window.

## Evidence boundaries

### Packet capture can establish

- ClientHello cipher suites, extensions, supported groups, signature algorithms, ALPN, and observed ordering.
- Computed JA3/JA4 values when the parser has the complete ClientHello.
- TCP behavior and negotiated TLS facts visible in the trace.
- QUIC presence and visible long-header metadata.
- HTTP/2 frames only when decryption or an equivalent controlled endpoint trace makes them observable.
- Client-versus-server direction only when the selected flow and endpoint roles are recorded; server SETTINGS and SETTINGS ACKs are not client-profile evidence.

### Playwright MCP can establish

- The page/session's observed requests, response data, console output, screenshots, and JavaScript-visible browser facts.
- It does not prove packet completeness, TLS ordering, HTTP/2 SETTINGS, guest placement, or which binary was launched unless those are independently verified.

### Do not infer from TLS alone

- Chrome version, browser family, channel, guest OS, or architecture.
- User-Agent and Client Hints.
- HTTP/2 settings or request-header order hidden by TLS.
- Stability across OSes, channels, feature flags, experiments, or connection reuse.

## Comparison classes

- `exact`: stable value/order must match.
- `normalized`: compare semantics after replacing dynamic GREASE/session values with placeholders.
- `set`: order is not part of the known contract.
- `informational`: record but do not gate.
- `unavailable`: evidence was not captured; never count as a match.

## Completion states

- `PASS`: all required measured dimensions match.
- `PARTIAL`: observed dimensions match, but named required dimensions are unavailable.
- `FAIL`: at least one stable required dimension mismatches.
- `BLOCKED`: browser identity, traffic origin, authorization, or basic evidence cannot be established.

## Platform gate

The current Chrome `mod_generator!`/`platform_headers!` path falls back to its first platform row for any unlisted platform. Therefore a canonical profile may expose only platforms with measured platform headers unless the implementation first changes the API to reject unsupported platforms. A Windows-only capture is not sufficient for a profile that silently serves Windows headers to macOS, Linux, Android, or iOS callers.
