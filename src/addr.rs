//! Provider-candidate address resolution — the ONE place a DHT [`CandidateAddr`] becomes a dialable
//! [`SocketAddr`], and the ONE place a candidate is rendered as text.
//!
//! # Why this module exists
//!
//! A candidate's `host` is an IP **literal** (v4, v6, or v4-mapped-v6). Composing `"{host}:{port}"`
//! and parsing that back as a [`SocketAddr`] is WRONG for every IPv6 literal — the socket-address
//! grammar requires brackets (`[2001:db8::1]:9444`), so an unbracketed v6 host fails with
//! `invalid socket address syntax` before a socket is ever opened. That format-then-reparse round
//! trip killed the whole #836 read leg on an AWS host advertising `::ffff:172.31.79.22`.
//!
//! So: **parse the host as an [`IpAddr`] and CONSTRUCT the [`SocketAddr`]** — no string grammar in
//! the middle. Rendering is the inverse and goes through [`display`], which brackets v6 correctly.
//!
//! # Candidate order (§5.2 IPv6-first, IPv4-fallback)
//!
//! [`dial_candidates`] orders a provider's dialable addresses IPv6 first, then IPv4, then anything
//! unresolvable — so a dialer walks the whole list and only reports failure once EVERY candidate
//! has been tried. One unusable v6 candidate must never mask a working v4 one.

use dig_dht::{CandidateAddr, ProviderRecord};
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;

/// Upper bound on dial candidates tried per provider, so a record padded with many addresses cannot
/// turn one holder into an unbounded connect storm.
pub const MAX_DIAL_CANDIDATES: usize = 4;

/// Why a candidate address could not be turned into a dialable [`SocketAddr`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AddrError {
    /// The host is neither an IPv4 nor an IPv6 literal. DHT candidates are always literals (they are
    /// *observed* socket addresses), so this means a malformed or hostname-bearing record — this
    /// crate does not resolve DNS on the dial path.
    #[error("candidate host {host:?} is not an IPv4/IPv6 literal")]
    NotAnIpLiteral {
        /// The offending host text, quoted in the message so a bad record is greppable in logs.
        host: String,
    },
}

/// Resolve one candidate to a dialable [`SocketAddr`].
///
/// Correct for IPv4, IPv6, and v4-mapped-IPv6 hosts alike, because the port is attached to a parsed
/// [`IpAddr`] rather than to a formatted string (see the module docs).
pub fn candidate_socket(addr: &CandidateAddr) -> Result<SocketAddr, AddrError> {
    let ip: IpAddr = addr.host.parse().map_err(|_| AddrError::NotAnIpLiteral {
        host: addr.host.clone(),
    })?;
    Ok(SocketAddr::new(ip, addr.port))
}

/// Render a candidate as `host:port`, bracketing an IPv6 literal so the text round-trips through
/// [`str::parse::<SocketAddr>`] and reads unambiguously in logs.
pub fn display(addr: &CandidateAddr) -> String {
    match candidate_socket(addr) {
        Ok(socket) => socket.to_string(),
        // Not a literal: there is nothing to bracket, so show it verbatim rather than inventing syntax.
        Err(_) => format!("{}:{}", addr.host, addr.port),
    }
}

/// The provider's dialable candidates in dial order: **IPv6 first, then IPv4** (§5.2), then any
/// candidate whose host is not a literal — capped at [`MAX_DIAL_CANDIDATES`].
///
/// Unresolvable candidates are kept (last) on purpose: a dialer that walks them reports a concrete
/// per-candidate reason instead of silently pretending the provider had no address at all.
pub fn dial_candidates(provider: &ProviderRecord) -> Vec<&CandidateAddr> {
    let mut candidates: Vec<&CandidateAddr> = provider
        .addresses
        .iter()
        .filter(|a| a.kind.is_dialable())
        .collect();
    candidates.sort_by_key(|a| match candidate_socket(a) {
        Ok(SocketAddr::V6(_)) => 0,
        Ok(SocketAddr::V4(_)) => 1,
        Err(_) => 2,
    });
    candidates.truncate(MAX_DIAL_CANDIDATES);
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_dht::{AddressKind, Key};
    use dig_nat::PeerId;

    fn record(addresses: Vec<CandidateAddr>) -> ProviderRecord {
        ProviderRecord::new(
            &Key::from_bytes([0xAB; 32]),
            &PeerId::from_bytes([1; 32]),
            addresses,
            u64::MAX,
        )
    }

    #[test]
    fn resolves_v4_v6_and_v4_mapped_hosts() {
        for host in ["10.0.0.1", "2001:db8::1", "::ffff:10.0.0.1"] {
            let addr = CandidateAddr::direct(host, 9444);
            let socket = candidate_socket(&addr).expect("literal host must resolve");
            assert_eq!(socket.ip(), host.parse::<IpAddr>().unwrap());
            assert_eq!(socket.port(), 9444);
        }
    }

    #[test]
    fn rejects_a_non_literal_host_with_a_named_reason() {
        let err = candidate_socket(&CandidateAddr::direct("peer.example", 9444)).unwrap_err();
        assert_eq!(
            err,
            AddrError::NotAnIpLiteral {
                host: "peer.example".into()
            }
        );
    }

    #[test]
    fn display_brackets_v6_and_leaves_v4_bare() {
        assert_eq!(
            display(&CandidateAddr::direct("10.0.0.1", 9444)),
            "10.0.0.1:9444"
        );
        assert_eq!(
            display(&CandidateAddr::direct("::ffff:10.0.0.1", 9444)),
            "[::ffff:10.0.0.1]:9444"
        );
        // A rendered candidate must always parse back as a socket address.
        assert!(display(&CandidateAddr::direct("2001:db8::1", 9444))
            .parse::<SocketAddr>()
            .is_ok());
    }

    #[test]
    fn dial_order_is_v6_then_v4_then_unresolvable() {
        let p = record(vec![
            CandidateAddr::direct("10.0.0.1", 1),
            CandidateAddr::direct("peer.example", 2),
            CandidateAddr::direct("2001:db8::1", 3),
        ]);
        let hosts: Vec<&str> = dial_candidates(&p)
            .iter()
            .map(|a| a.host.as_str())
            .collect();
        assert_eq!(hosts, vec!["2001:db8::1", "10.0.0.1", "peer.example"]);
    }

    #[test]
    fn dial_candidates_skip_relay_markers_and_stay_bounded() {
        let mut addresses = vec![CandidateAddr::relay_marker()];
        addresses.extend((0..10).map(|i| CandidateAddr::direct(format!("10.0.0.{i}"), 9444)));
        let p = record(addresses);
        let candidates = dial_candidates(&p);
        assert_eq!(candidates.len(), MAX_DIAL_CANDIDATES);
        assert!(candidates.iter().all(|a| a.kind == AddressKind::Direct));
    }
}
