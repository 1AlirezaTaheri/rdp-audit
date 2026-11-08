//! Tests for the target safety gate (private/local range refusal).

mod common;

use std::net::IpAddr;

use rdp_audit::{SafetyError, ensure_target_allowed, is_private_or_local_ip, resolve_target};

fn ip(value: &str) -> IpAddr {
    value.parse().expect("valid ip literal")
}

#[test]
fn flags_private_and_local_ranges() {
    for address in [
        "192.168.56.101",
        "192.168.0.1",
        "10.0.0.1",
        "10.255.255.254",
        "172.16.0.1",
        "172.31.255.255",
        "127.0.0.1",
        "169.254.1.1",
        "100.64.0.1",
        "0.0.0.0",
        "::1",
        "fc00::1",
        "fd12:3456::1",
        "fe80::1",
    ] {
        assert!(
            is_private_or_local_ip(&ip(address)),
            "{address} must be classified as private/local"
        );
    }
}

#[test]
fn allows_public_ranges() {
    for address in [
        "8.8.8.8",
        "1.1.1.1",
        "203.0.113.10", // TEST-NET-3, public per this classifier
        "172.32.0.1",   // just outside 172.16/12
        "2001:4860:4860::8888",
    ] {
        assert!(
            !is_private_or_local_ip(&ip(address)),
            "{address} must be treated as public"
        );
    }
}

#[test]
fn resolves_ip_literals_without_dns() {
    let addresses = resolve_target("203.0.113.10", 3389).expect("ip literal resolves");
    assert_eq!(addresses.len(), 1);
    assert_eq!(addresses[0].ip(), ip("203.0.113.10"));
    assert_eq!(addresses[0].port(), 3389);
}

#[test]
fn refuses_private_target_without_opt_in() {
    let result = ensure_target_allowed("192.168.56.101", 3389, false);
    match result {
        Err(SafetyError::PrivateTargetNotAllowed { host, .. }) => {
            assert_eq!(host, "192.168.56.101");
        }
        other => panic!("expected PrivateTargetNotAllowed, got {other:?}"),
    }
}

#[test]
fn allows_private_target_with_opt_in() {
    let addresses =
        ensure_target_allowed("192.168.56.101", 3389, true).expect("--allow-private permits lab IPs");
    assert!(!addresses.is_empty());
}

#[test]
fn allows_public_target_without_opt_in() {
    let addresses =
        ensure_target_allowed("203.0.113.10", 3389, false).expect("public target allowed");
    assert_eq!(addresses.len(), 1);
}

#[test]
fn empty_host_is_rejected() {
    match resolve_target("", 3389) {
        Err(SafetyError::NoAddresses { .. }) => {}
        other => panic!("expected NoAddresses, got {other:?}"),
    }
}
