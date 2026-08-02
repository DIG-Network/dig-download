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

/// **Proves:** the peer client itself is on the dig-rpc-protocol 0.6 line — the transitive entry, not
/// just the direct caret dep, since a consumer's own lock is what actually decides which patch is
/// compiled.
#[test]
fn the_peer_client_is_on_the_module_wire_major() {
    let versions = locked_versions("dig-peer");
    assert_eq!(versions.len(), 1, "one dig-peer only, found {versions:?}");
    assert!(
        versions[0].starts_with("0.9."),
        "dig-peer must be on the 0.9 line (dig-rpc-protocol 0.6 + the module client methods, re-exporting          dig-nat 0.18, whose `SafeText` crosses dig-peer's own error surface); the tree resolved {}",
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

/// **Proves:** the resolved `dig-nat` is on the 0.14 line.
///
/// **Catches:** a lock that silently resolves dig-nat 0.11.x. On that line `RangeFrame::encode`
/// returned a bare `Vec<u8>` with NO ceiling on the payload while the DECODE side already capped the
/// body at 64 KiB, so a holder emitted frames every conforming reader was required to reject and every
/// DIG read or reshare above ~48 KiB failed to decode (#1640).
///
/// Three things worth stating exactly, because a version this test names wrongly is a wrong rule the
/// suite would then vouch for. First, the encode ceiling landed in **0.12.0** — not in this line at all;
/// 0.13.0 added the `#[non_exhaustive]` wire types with public constructors and the `chunk_index` setter
/// separate from `with_inclusion_proof`, and **0.14.0** adds the paged-prologue reassembly primitives
/// (`ChunkLensAssembler`, `MAX_RESOURCE_CHUNK_COUNT`, `split_chunk_lens_pages`). Second,
/// `the_transport_stack_is_not_duplicated` proves there is only ONE dig-nat; only this test proves that
/// one is a fixed one — and a caret bump in `Cargo.toml` does not settle it, because an intermediate
/// consumer pinning an older caret reintroduces the old line in the lock while the manifest reads
/// correctly. **0.15.0** then adds `SafeText` — the type that makes peer-supplied text unrepresentable
/// in a rendered error — and that type crosses dig-dht's and dig-peer's public error surfaces, so a
/// second dig-nat in the tree is now an outright `E0308` on those seams rather than merely two mTLS
/// stacks.
///
/// Third, and this is why this assertion is load-bearing rather than ceremonial: a **0.x MINOR is
/// semver-incompatible**, so `dig-nat = "0.14"` here is unresolvable on its own while ANY intermediate
/// consumer still requires `^0.14`. dig-dht and dig-peer both did, and bumping only dig-nat produced a
/// lock with TWO dig-nat entries and four `E0308`s on the `DigPeer::fetch_range` seam. All three deps
/// therefore move together, and this tracked lock is the one place in the cascade where a test can
/// demonstrate the whole graph collapsing to a single dig-nat — the sibling crates' own locks are
/// untracked, so their assertions only ever covered their own trees.
#[test]
fn the_transport_is_on_the_capped_encode_line() {
    let versions = locked_versions("dig-nat");
    assert_eq!(versions.len(), 1, "one dig-nat only, found {versions:?}");
    assert!(
        versions[0].starts_with("0.18."),
        "dig-nat must be on the 0.18 line (capped framed ENCODE since 0.12 for #1640, the per-frame          chunk_index setter and public constructors from 0.13, the paged-prologue reassembly primitives          from 0.14, `SafeText` in 0.15, the RLY-009 DHT-record messages in 0.17, and the          non_exhaustive RelayMessage in 0.18 that stops a wire addition forcing this cascade again);          the tree resolved {}",
        versions[0]
    );
}

/// **Proves:** exactly one `dig-dht`, on the 0.11 line that itself carries dig-nat 0.18.
///
/// **Catches:** the published-but-unresolvable class this cascade exists to fix — a caret like
/// `dig-dht = "0.8"` means `>=0.8.0, <0.9`, which can NEVER reach 0.9.0, so the locate leg would keep
/// resolving a dig-dht that drags an older dig-nat in transitively while the direct dep looked correct.
/// Two dig-dht entries would also make `dig_dht::ProviderRecord` two distinct types across the locate
/// boundary.
#[test]
fn the_locator_is_on_the_cascaded_dht_line() {
    let versions = locked_versions("dig-dht");
    assert_eq!(versions.len(), 1, "one dig-dht only, found {versions:?}");
    assert!(
        versions[0].starts_with("0.11."),
        "dig-dht must be on the 0.11 line (the release carrying dig-nat 0.18 + the bounded          ProviderStore::snapshot the relay's /dht view is built from); the tree resolved {}",
        versions[0]
    );
}
