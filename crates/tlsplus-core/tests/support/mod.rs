//! Shared test support for tlsplus-core integration tests.
//!
//! This module is re-exported by tests that need common helpers.
//! No public API surface — tests import `mod support;` and use `support::*`.

/// Returns a local address on the loopback interface with an available port.
pub fn ephemeral_listen_addr() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener
        .local_addr()
        .map(|a| a.to_string())
        .expect("local addr")
}
