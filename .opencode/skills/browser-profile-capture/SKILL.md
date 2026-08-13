---
name: browser-profile-capture
description: "Captures a real installed browser profile for authorized compatibility testing using Parallels Desktop, Playwright MCP, dumpcap, and tshark. Use to capture, recapture, refresh, or inspect a Chrome/Firefox build before adding it to TLS+. Do not use for ordinary browsing, screenshots alone, WAF bypass, CAPTCHA evasion, or fabricating an uninstalled version such as Chrome 151."
compatibility: opencode
metadata:
  domain: browser-compatibility
  phase: capture
---

# Browser Profile Capture

Produce a provenance-rich evidence bundle from the exact browser binary that generated the traffic.

## Preconditions

1. Read `.opencode/skills/browser-profile-lab/references/artifact-contract.md`.
2. Confirm the endpoint is owned or authorized for testing.
3. Require a Parallels VM identifier, guest platform, target browser family/version, and an exact guest-side version command verified for that guest OS.
4. Do not put guest passwords on a command line or in artifacts.

If Playwright MCP cannot be proven to control the browser process inside the intended guest, record the attachment observation as `unknown` or `measured: false` with evidence. Use manual guest interaction or separately verified guest automation; never pretend the MCP browser is the guest browser.

## Workflow

### 1. Inventory the environment

Use the verified host commands in `references/tool-recipes.md`:

- List VMs and record the selected VM as JSON.
- Record VM status and IP information when available.
- List capture interfaces with `dumpcap -D`; choose from output, not memory.
- Record `tshark --version`, `dumpcap --version`, and `prlctl --help` version output in notes.

Do not change Parallels networking to make capture easier. Starting/stopping a VM, creating or switching snapshots, and reset/delete/network operations all mutate state and require explicit authorization.

### 2. Verify browser identity

Run the exact browser binary's version command in the guest using a guest command already validated for that OS. Save raw output to `real/browser-version.txt`.

Also record:

- Binary/application identity.
- Full version and major version.
- Channel if directly available, otherwise `unknown`.
- Guest OS and architecture.

If the observed major differs from the requested profile name, stop with `BLOCKED`. Do not generate future-version headers or rename a nearest profile.

### 3. Establish traffic origin

Before the measured run:

1. Use a clean browser state appropriate for the test, without reusing an unrelated user's profile.
2. Ensure the destination is the authorized fixture and the connection will be fresh.
3. Correlate browser navigation time, guest IP, fixture IP/SNI, pcap timestamps, and one selected TCP stream.
4. Capture a VM screenshot with `prlctl capture <VM> --file <path>` when it helps prove the selected guest/browser. This is a screenshot, not packet capture.

Mark traffic origin `measured: true` only when the exact browser identity and selected client-to-fixture flow are linked by named evidence. The provenance record must include client IP, fixture IP/SNI, TCP stream, timestamp window, method, and confidence.

### 4. Capture packets

Prefer the bundled helper:

```bash
.opencode/skills/browser-profile-capture/scripts/capture-host.sh \
  <interface> <duration-seconds> <output.pcapng> <capture-filter>
```

Start capture before navigation. Drive exactly one controlled navigation and wait for the fixture to complete. Avoid background tabs and unrelated traffic. Preserve the raw pcapng. A narrow guest-to-fixture libpcap filter is mandatory; if the host cannot isolate that flow, capture inside the authorized guest with separately verified tools or stop.

Capture filters use libpcap syntax. Analysis filters use Wireshark display-filter syntax; they are not interchangeable.

### 5. Drive and observe the browser

Only when Playwright is proven attached to the target process:

1. `browser_navigate` to the authorized fixture.
2. `browser_snapshot` to capture rendered state.
3. `browser_network_requests` and `browser_network_request` to record request/response evidence.
4. `browser_console_messages` for errors.
5. `browser_take_screenshot` for a visual record.

Prefer structured MCP tools. Do not use `browser_run_code_unsafe` merely to launch, attach, or extract data.

Playwright request data is application-level evidence. It does not prove ClientHello ordering, HTTP/2 SETTINGS, complete packet capture, or header wire order.

### 6. Extract protocol evidence

Run:

```bash
.opencode/skills/browser-profile-capture/scripts/analyze-pcap.sh \
  <capture.pcapng> <attempt-output-directory> \
  <client-ip> <client-port> <server-ip> <server-port> \
  <server-name> <tcp-stream> [tls-keylog]
```

The helper rejects a flow with no matching ClientHello, includes timestamps/SNI/5-tuple/stream direction, and extracts only non-ACK client SETTINGS from the selected flow. Inspect the generated files. A header-only HTTP/2 file means client SETTINGS were not observable; mark the field `unknown`. Do not copy HTTP/2 settings from a neighboring Chrome version.

If decryption uses the optional TLS key-log argument, keep the key log outside the repository, restrict access, and do not commit it. Record its use and secure location class, not its contents.

### 7. Complete the manifest

Copy the lab template to `manifest.json`, then fill it. Every observation points to a concrete artifact. List unresolved facts explicitly. Every recapture or analysis retry gets a new capture/attempt directory; never overwrite a previous attempt.

## Completion gate

The capture is complete only when:

- Exact browser version and traffic origin are verified.
- A fresh target connection exists in the pcap.
- A matching selected-flow ClientHello is extracted and recorded as measured evidence. Its absence makes the capture `BLOCKED`.
- Playwright placement is a provenance record proving attachment or recording it as unknown/measured false.
- Encrypted/unobservable dimensions remain unknown.
- Sensitive unrelated traffic and credentials are absent from the deliverable.

## References

- `references/tool-recipes.md` contains syntax verified against local Parallels 26.4.0, Wireshark 4.6.7, and the enabled Playwright MCP surface.
- `scripts/capture-host.sh` performs bounded host packet capture.
- `scripts/analyze-pcap.sh` extracts stable summary tables without guessing browser identity.
