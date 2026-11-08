//! Target safety gates: DNS resolution and private/local network refusal.
//!
//! The tool refuses to run against private or local address ranges unless the
//! operator explicitly opts in with `--allow-private`. This keeps accidental runs
//! against production or unexpected networks impossible, while still allowing
//! authorized lab ranges (e.g. `192.168.56.101`) behind an explicit flag.

use std::net::{IpAddr, ToSocketAddrs};
use thiserror::Error;

/// Errors produced while validating that a target may be contacted.
#[derive(Debug, Error)]
pub enum SafetyError {
    /// The target host name could not be resolved to an address.
    #[error("cannot resolve target '{host}': {source}")]
    ResolutionFailed {
        host: String,
        #[source]
        source: std::io::Error,
    },
    /// The host resolved, but to no usable socket address.
    #[error("target '{host}' did not resolve to any usable address")]
    NoAddresses { host: String },
    /// The target is inside a private/local range and `--allow-private` was not set.
    #[error(
        "refusing to target private/local address {addr} ('{host}'). \
         Private networks are only allowed with --allow-private (authorized labs)."
    )]
    PrivateTargetNotAllowed { host: String, addr: std::net::SocketAddr },
}

/// Returns `true` when the IP belongs to a private, local or otherwise non-public range.
///
/// Covered ranges:
///
/// * IPv4: `0.0.0.0/8`, loopback `127.0.0.0/8`, link-local `169.254.0.0/16`,
///   CGNAT `100.64.0.0/10`, RFC1918 (`10/8`, `172.16/12`, `192.168/16`)
/// * IPv6: unspecified/loopback, link-local `fe80::/10`, unique-local `fc00::/7`
/// * IPv4-mapped IPv6 addresses are canonicalized first (e.g. `::ffff:192.168.1.1`)
pub fn is_private_or_local_ip(ip: &IpAddr) -> bool {
    let ip = ip.to_canonical();
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_private()
                || octets[0] == 0 // 0.0.0.0/8
                || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64) // 100.64.0.0/10 CGNAT
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (first & 0xfe00) == 0xfc00 // fc00::/7 unique local
                || (first & 0xffc0) == 0xfe80 // fe80::/10 link local
        }
    }
}

/// Resolves `host` on `port` to every socket address it maps to.
///
/// IP literals resolve locally; host names go through the system resolver.
/// Resolution failures are reported as [`SafetyError::ResolutionFailed`] so the
/// tool never proceeds against a target it could not classify.
pub fn resolve_target(host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>, SafetyError> {
    if host.trim().is_empty() {
        return Err(SafetyError::NoAddresses {
            host: host.to_owned(),
        });
    }
    let addresses: Vec<std::net::SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|source| SafetyError::ResolutionFailed {
            host: host.to_owned(),
            source,
        })?
        .collect();
    if addresses.is_empty() {
        return Err(SafetyError::NoAddresses {
            host: host.to_owned(),
        });
    }
    Ok(addresses)
}

/// The main safety gate: resolves `host` and refuses private/local targets
/// unless `allow_private` is set.
///
/// If **any** resolved address is private/local the target is refused, which
/// also covers host names that resolve to both public and private addresses.
pub fn ensure_target_allowed(
    host: &str,
    port: u16,
    allow_private: bool,
) -> Result<Vec<std::net::SocketAddr>, SafetyError> {
    let addresses = resolve_target(host, port)?;
    if allow_private {
        return Ok(addresses);
    }
    for addr in &addresses {
        if is_private_or_local_ip(&addr.ip()) {
            return Err(SafetyError::PrivateTargetNotAllowed {
                host: host.to_owned(),
                addr: *addr,
            });
        }
    }
    Ok(addresses)
}
