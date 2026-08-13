# Changelog

All notable user-facing changes to TLS+ are documented in this file.

## [0.4.0] - 2026-08-13

### Added

- RFC 8441 WebSocket support using HTTP/2 Extended CONNECT with transparent bidirectional frame transport.
- Protocol-preserving HTTP/2 forwarding across the Burp-to-TLS+ and TLS+-to-backend connections.
- Controlled HTTP/2, Extended CONNECT, downgrade, standard CONNECT classification, and Montoya routing integration tests.

### Changed

- The embedded proxy now accepts HTTP/1.1 and HTTP/2 connections and advertises Extended CONNECT support.
- Burp HTTP/2 requests are rebuilt explicitly with Montoya's HTTP/2 request factory and rejected if the local connection is silently downgraded.
- The two lifecycle/API tests that previously used port `43118` now request OS-assigned loopback ports, so they remain isolated from a running Burp instance.

### Fixed

- Preserved HTTP/1.0 forwarding and avoided misclassifying standard CONNECT requests as RFC 8441 WebSockets.
- Kept existing HTTP/1.1 WebSocket upgrades working alongside multiplexed HTTP/2 tunnels.

## [0.3.0] - 2026-08-12

### Added

- Direct Rust `tlsplus_core::http_client::HttpClient` API for profile-aware requests without routing through the local proxy.
- Opt-in Chrome 149 external TLS fingerprint QA against BrowserScan and BrowserLeaks.
- All-platform Burp extension packaging for macOS ARM64, Windows x64 and ARM64, and Linux x64 and ARM64.

### Changed

- Migrated the native core to the `crates/tlsplus-core` workspace layout.
- Replaced the legacy outbound transport with the in-repository, profile-aware `wreq` and `wreq-util` forks.
- Reworked CI into a read-only validation workflow and an immutable SemVer tag release workflow with pinned actions, locked Cargo resolution, checksum verification, and build provenance.
- Updated the bundled `wreq-util` transport and browser profile implementation.

### Fixed

- Embedded proxy shutdown now waits for the listener to close, reports occupied ports correctly, and supports immediate restart on the same address.
- Release builds now check out transport submodules recursively and support Windows ARM64 cross-compilation.
