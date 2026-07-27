//! Dependency-tree invariants asserted against the resolved `Cargo.lock` itself.
//!
//! # Why a test reads the lock file
//!
//! A caret dep can look right in `Cargo.toml` while the RESOLVED tree still carries an old major
//! reachable through an intermediate consumer — and the compiler will not complain, because two majors
//! of the same crate are perfectly legal Rust. That silence is the problem: when the duplicated crate
//! defines a WIRE TYPE, the two majors sit either side of a trust boundary and disagree about the shape
//! of the bytes, which presents as content that "arrives" but never verifies.
//!
//! That exact defect cost the read leg six blind diagnosis rounds (#836: a `serde_bytes`-vs-base64 skew
//! on the range frame), and #1576 hit its sibling: dig-download consumed dig-rpc-protocol **0.5** — the
//! major carrying the whole-module wire — while pulling dig-peer's **0.3.1** through the peer client, so
//! the tree held TWO `ModuleInfo` types on the field that drives the entire pull plan.
//!
//! So the invariant is asserted where it is actually decided: the lock.

/// The resolved lock of THIS crate, read at compile time so the assertion cannot drift from the tree
/// the tests actually built against.
const LOCK: &str = include_str!("../Cargo.lock");

/// Every `version = "…"` recorded for `crate_name` in the lock, in file order.
fn locked_versions(crate_name: &str) -> Vec<&str> {
    let needle = format!("name = \"{crate_name}\"");
    LOCK.split("[[package]]")
        .filter(|block| block.lines().any(|l| l.trim() == needle))
        .filter_map(|block| {
            block
                .lines()
                .find_map(|l| l.trim().strip_prefix("version = "))
                .map(|v| v.trim_matches('"'))
        })
        .collect()
}

/// **Proves:** the resolved tree carries EXACTLY ONE `dig-rpc-protocol`, and it is the 0.6 line that
/// defines the whole-module wire (`ModuleInfo`, `GetModuleInfoParams`, `FetchModuleRangeParams`).
/// **Catches:** a consumer (today dig-peer) reintroducing an older dig-rpc-protocol major, which would
/// silently place two `ModuleInfo` shapes either side of the module pull's trust boundary — a defect the
/// compiler accepts and only a wire test or a real network run would otherwise reveal (#1576/#836).
#[test]
fn the_tree_carries_exactly_one_dig_rpc_protocol_and_it_is_the_module_wire_major() {
    let versions = locked_versions("dig-rpc-protocol");
    assert_eq!(
        versions.len(),
        1,
        "expected exactly one dig-rpc-protocol in the resolved tree, found {versions:?} — two majors \
         means two `ModuleInfo` shapes across a trust boundary"
    );
    assert!(
        versions[0].starts_with("0.6."),
        "the module wire ships in dig-rpc-protocol 0.6; the tree resolved {}",
        versions[0]
    );
}

/// **Proves:** the peer client itself is on the same 0.6 line — the transitive entry, not just the
/// direct caret dep, since a consumer's own lock is what actually decides which patch is compiled.
#[test]
fn the_peer_client_is_on_the_module_wire_major() {
    let versions = locked_versions("dig-peer");
    assert_eq!(versions.len(), 1, "one dig-peer only, found {versions:?}");
    assert!(
        versions[0].starts_with("0.6."),
        "dig-peer must be on the 0.6 line (dig-rpc-protocol 0.6 + the module client methods); \
         the tree resolved {}",
        versions[0]
    );
}

/// **Proves:** exactly one `dig-nat` and one `dig-tls`, the pre-existing invariant the dig-peer bump
/// must not disturb — two majors of either would make `NodeCert`/`PeerTarget` type-incompatible between
/// this crate's transport and its caller's.
#[test]
fn the_transport_stack_is_not_duplicated() {
    for crate_name in ["dig-nat", "dig-tls"] {
        let versions = locked_versions(crate_name);
        assert_eq!(
            versions.len(),
            1,
            "expected exactly one {crate_name}, found {versions:?}"
        );
    }
}

/// **Proves:** the resolved `dig-nat` is on the 0.13 line — the release where `RangeFrame::encode`
/// became FALLIBLE and started refusing a body over `MAX_FRAMED_BODY`.
///
/// **Catches:** a lock that silently resolves dig-nat 0.11.x/0.12.x, which is not a version nit: on
/// those lines the framed ENCODE side was UNCAPPED while the DECODE side already capped at 64 KiB, so a
/// holder happily emitted frames every conforming reader was required to reject, and every DIG read or
/// reshare above ~48 KiB failed to decode (#1640). `the_transport_stack_is_not_duplicated` proves there
/// is only ONE dig-nat; only this test proves that one is the FIXED one. A caret bump in `Cargo.toml`
/// does not settle it — an intermediate consumer pinning `^0.11` re-introduces the broken line in the
/// lock while the manifest still reads `"0.13"`.
#[test]
fn the_transport_is_on_the_capped_encode_line() {
    let versions = locked_versions("dig-nat");
    assert_eq!(versions.len(), 1, "one dig-nat only, found {versions:?}");
    assert!(
        versions[0].starts_with("0.13."),
        "dig-nat must be on the 0.13 line (framed ENCODE capped at MAX_FRAMED_BODY, #1640); the tree \
         resolved {} — reads above ~48 KiB cannot decode on that line",
        versions[0]
    );
}

/// **Proves:** exactly one `dig-dht`, on the 0.7 line that itself carries dig-nat 0.13.
///
/// **Catches:** the published-but-unresolvable class this cascade exists to fix — `dig-dht = "0.5.1"`
/// means `>=0.5.1, <0.6`, which can NEVER reach 0.7.0, so the locate leg would keep resolving a dig-dht
/// that drags the uncapped dig-nat line in transitively while the direct dep looked correct. Two dig-dht
/// entries would also make `dig_dht::ProviderRecord` two distinct types across the locate boundary.
#[test]
fn the_locator_is_on_the_cascaded_dht_line() {
    let versions = locked_versions("dig-dht");
    assert_eq!(versions.len(), 1, "one dig-dht only, found {versions:?}");
    assert!(
        versions[0].starts_with("0.7."),
        "dig-dht must be on the 0.7 line (the release carrying dig-nat 0.13); the tree resolved {}",
        versions[0]
    );
}
