//! Dial-candidate ranking is dig-dht's, not this crate's (dig-download#32).
//!
//! `dig-download` used to carry its own ranking, and the copy disagreed with the canonical one in
//! the direction that matters: it classified an IPv4-mapped IPv6 literal as PREFERRED — the
//! `::ffff:172.31.79.22` shape `src/addr.rs` blames for killing the #836 read leg — deduped nothing,
//! and capped with a bare truncation that could evict every IPv4 candidate.
//!
//! These tests exercise the surface this crate EXPORTS and the method `source.rs` actually calls, so
//! they fail if a local ranking is ever reintroduced behind either.

use dig_download::{dial_candidates, MAX_DIAL_CANDIDATES};
use dig_dht::{CandidateAddr, Key, ProviderRecord};
use dig_nat::PeerId;

/// A record whose `addresses` are assigned AFTER construction.
///
/// `ProviderRecord::new` canonicalizes the list it is given, which would satisfy an ordering
/// assertion without the function under test doing anything — the fixture would pin the constructor
/// and read as green under a wrong ranking. Writing the field directly is what makes the ordering
/// assertions load-bearing.
fn record_with_unsorted(addresses: Vec<CandidateAddr>) -> ProviderRecord {
    let mut record = ProviderRecord::new(
        &Key::from_bytes([0xAB; 32]),
        &PeerId::from_bytes([1; 32]),
        Vec::new(),
        u64::MAX,
    );
    record.addresses = addresses;
    record
}

fn hosts(candidates: &[&CandidateAddr]) -> Vec<String> {
    candidates.iter().map(|a| a.host.clone()).collect()
}

/// An IPv4-mapped IPv6 literal is IPv4 REACHABILITY, so it belongs in the fallback tier behind a
/// native IPv6 — the local copy put it in front, on `matches!(SocketAddr::V6(_))`.
///
/// The mapped address is listed FIRST so a rank-by-syntax implementation would leave it first; only
/// a rank-by-reachability implementation moves it.
#[test]
fn a_mapped_v6_literal_ranks_behind_a_native_v6() {
    let addresses = vec![
        CandidateAddr::direct("::ffff:10.0.0.1", 9444),
        CandidateAddr::direct("2001:db8::1", 9444),
    ];
    assert_eq!(
        hosts(&dial_candidates(&addresses)),
        vec!["2001:db8::1", "::ffff:10.0.0.1"],
    );
}

/// `::ffff:10.0.0.1` and `10.0.0.1` name ONE endpoint, so they must occupy ONE dial slot. Without
/// the dedup a record padded with re-spellings of a single address fills the whole cap with it.
#[test]
fn spellings_of_one_endpoint_collapse_to_one_slot() {
    let addresses = vec![
        CandidateAddr::direct("::ffff:10.0.0.1", 9444),
        CandidateAddr::direct("10.0.0.1", 9444),
        CandidateAddr::direct("2001:db8::1", 9444),
    ];
    let ranked = hosts(&dial_candidates(&addresses));
    assert_eq!(ranked.len(), 2, "expected one v6 + one collapsed v4; got {ranked:?}");
    assert_eq!(ranked[0], "2001:db8::1");
}

/// A dual-stack holder legitimately advertises several IPv6 candidates. Under a bare `truncate(4)`
/// five of them evict the only IPv4 address, so a dialer that faithfully walks every candidate it is
/// GIVEN still never reaches the working one — #836, one layer down.
///
/// The assertion is on the PRESENCE of the fallback tier, not on the returned length: a length check
/// is satisfied identically by the truncation this test exists to reject.
#[test]
fn the_cap_never_evicts_the_last_fallback_candidate() {
    let mut addresses: Vec<CandidateAddr> = (1..=5)
        .map(|i| CandidateAddr::direct(format!("2001:db8::{i}"), 9444))
        .collect();
    addresses.push(CandidateAddr::direct("10.0.0.1", 9444));

    let ranked = hosts(&dial_candidates(&addresses));
    assert_eq!(ranked.len(), MAX_DIAL_CANDIDATES);
    assert!(
        ranked.contains(&"10.0.0.1".to_string()),
        "the only IPv4 candidate must survive the cap; got {ranked:?}"
    );
    assert_eq!(ranked[0], "2001:db8::1", "IPv6 still leads the list");
}

/// The ranking must reach the DIAL PATH, not merely the crate root: `source.rs` walks
/// `ProviderRecord::dial_candidates()`, so that method is asserted to carry the same order. A
/// re-derived local ranking reintroduced behind it would pass the free-function tests above.
#[test]
fn the_provider_method_source_dials_through_carries_the_same_order() {
    let addresses = vec![
        CandidateAddr::relay_marker(),
        CandidateAddr::direct("::ffff:10.0.0.1", 9444),
        CandidateAddr::direct("2001:db8::1", 9444),
    ];
    let record = record_with_unsorted(addresses.clone());
    assert_eq!(
        hosts(&record.dial_candidates()),
        hosts(&dial_candidates(&addresses)),
    );
    // A relay marker is not directly dialable and must not appear on the dial path at all.
    assert_eq!(hosts(&record.dial_candidates()), vec!["2001:db8::1", "::ffff:10.0.0.1"]);
}
