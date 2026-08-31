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
//! # Candidate ORDER is NOT owned here (§5.2 IPv6-first, IPv4-fallback)
//!
//! Ranking a provider's candidates belongs to [`dig_dht::dial_candidates`], which is "the ONE place
//! the DHT expresses it, so every consumer inherits it instead of re-deriving a ranking of its own."
//! This module deliberately owns only the two things it can own without duplicating that policy:
//! constructing the [`SocketAddr`] and rendering the text.
//!
//! A local ranking used to live here and it disagreed with the canonical one **in the direction that
//! matters**: it classified an IPv4-mapped IPv6 literal as PREFERRED, which is the very
//! `::ffff:172.31.79.22` shape blamed above for killing the #836 read leg, and it capped with a bare
//! truncation that could evict every IPv4 candidate. Order comes from dig-dht; nothing re-derives it.

use dig_dht::CandidateAddr;
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;

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

#[cfg(test)]
mod tests {
    use super::*;
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
}
