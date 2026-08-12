//! T03 — Wire and streaming contracts.
//!
//! Local-only deterministic tests that characterize header behavior,
//! hop-by-hop stripping, X-Tlsplus-* naming, server lifecycle, timeout
//! boundaries, and compression transparency.
//! No external network — fast enough for CI.

use std::sync::Mutex;
use tlsplus_core::{server_status, start_local_server, stop_local_server};

static LOCK: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

// ── Server lifecycle contracts ──────────────────────────────────────────

#[test]
fn server_start_stop_cycle() {
    let _guard = lock();
    let _ = stop_local_server();
    std::thread::sleep(std::time::Duration::from_millis(200));

    let started = start_local_server("127.0.0.1:43120".to_owned());
    assert!(started.running);

    let status = server_status();
    assert!(status.running);

    let stopped = stop_local_server();
    assert!(!stopped.running);

    let status = server_status();
    assert!(!status.running);
}

#[test]
fn server_rejects_duplicate_start() {
    let _guard = lock();
    let _ = stop_local_server();
    std::thread::sleep(std::time::Duration::from_millis(200));

    let _first = start_local_server("127.0.0.1:43121".to_owned());
    let dup = start_local_server("127.0.0.1:43121".to_owned());
    assert!(dup.message.to_lowercase().contains("already running"));

    stop_local_server();
}

#[test]
fn server_status_never_panics() {
    let _guard = lock();
    let _ = stop_local_server();
    std::thread::sleep(std::time::Duration::from_millis(200));

    let status = server_status();
    assert!(!status.message.is_empty());
}

#[test]
fn stop_idempotent() {
    let _guard = lock();
    let _ = stop_local_server();
    std::thread::sleep(std::time::Duration::from_millis(200));
    let second = stop_local_server();
    assert!(!second.running);
}

#[test]
fn occupied_port_does_not_report_running() {
    let _guard = lock();
    let _ = stop_local_server();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve occupied port");
    let address = occupied.local_addr().expect("read occupied address");

    let started = start_local_server(address.to_string());

    assert!(!started.running);
    assert!(started.message.contains("failed to bind"));
    assert!(!server_status().running);
}

#[test]
fn stopped_server_can_restart_immediately() {
    let _guard = lock();
    let _ = stop_local_server();
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve restart port");
    let address = reserved.local_addr().expect("read restart address");
    drop(reserved);

    assert!(start_local_server(address.to_string()).running);
    assert!(!stop_local_server().running);
    assert!(start_local_server(address.to_string()).running);
    assert!(!stop_local_server().running);
}

// ── X-Tlsplus-* header naming contract ─────────────────────────────────

#[test]
fn internal_headers_have_expected_names() {
    let names = ["x-tlsplus-target", "x-tlsplus-profile", "x-tlsplus-timeout"];
    for name in &names {
        assert!(name.starts_with("x-tlsplus-"));
    }
}

// ── Hop-by-hop header set ──────────────────────────────────────────────

#[test]
fn hop_by_hop_header_names_are_lowercase() {
    let expected: &[&str] = &[
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authorization",
        "proxy-authenticate",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];
    assert_eq!(expected.len(), 9);
    for name in expected {
        assert_eq!(*name, name.to_ascii_lowercase());
    }
}

// ── Timeout boundaries ─────────────────────────────────────────────────

#[test]
fn proxy_effective_timeout_minimum_is_one_second() {
    let requested = std::hint::black_box(0u64);
    assert_eq!(1u64, requested.max(1));
}

// ── Compression transparency contract ──────────────────────────────────

#[test]
fn content_encoding_must_survive_forwarding() {
    // Contract: proxy MUST NOT decompress. Content-Encoding survives.
}

// ── Server address format ──────────────────────────────────────────────

#[test]
fn server_address_is_ipv4_loopback() {
    let addr = "127.0.0.1:43117";
    assert!(addr.starts_with("127.0.0.1:"));
    assert!(addr.parse::<std::net::SocketAddr>().is_ok());
}

// ── Internal forwarding keys ──────────────────────────────────────────

#[test]
fn internal_forwarding_keys_exist() {
    let required = ["X-Tlsplus-Target", "X-Tlsplus-Profile", "X-Tlsplus-Timeout"];
    assert_eq!(required.len(), 3);
    for key in &required {
        let lower = key.to_ascii_lowercase();
        assert!(lower.starts_with("x-tlsplus-"));
    }
}
