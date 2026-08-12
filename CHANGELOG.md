# Changelog

All notable user-facing changes to TLS+ are documented in this file.

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
