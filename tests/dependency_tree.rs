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

/// **Proves:** the resolved tree carries EXACTLY ONE `dig-rpc-protocol`, and it is the 0.10 line that
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
        versions[0].starts_with("0.10."),
        "the module wire ships in dig-rpc-protocol 0.10; the tree resolved {}",
        versions[0]
    );
}

/// **Proves:** the peer client itself is on the dig-rpc-protocol 0.10 line — the transitive entry, not
/// just the direct caret dep, since a consumer's own lock is what actually decides which patch is
/// compiled.
#[test]
fn the_peer_client_is_on_the_module_wire_major() {
    let versions = locked_versions("dig-peer");
    assert_eq!(versions.len(), 1, "one dig-peer only, found {versions:?}");
    assert!(
        versions[0].starts_with("0.12."),
        "dig-peer must be on the 0.12 line (dig-rpc-protocol 0.10 + the module client methods, re-exporting          dig-nat 0.20 and dig-tls 0.4 on the chia-0.36 line, whose `SafeText` crosses dig-peer's own          error surface); the tree resolved {}",
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

/// **Proves:** the resolved `dig-nat` is on the 0.20 line.
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
        versions[0].starts_with("0.20."),
        "dig-nat must be on the 0.20 line (capped framed ENCODE since 0.12 for #1640, the per-frame          chunk_index setter and public constructors from 0.13, the paged-prologue reassembly primitives          from 0.14, `SafeText` in 0.15, the RLY-009 DHT-record messages in 0.17, the          non_exhaustive RelayMessage in 0.18, and in 0.20 the dig-tls 0.4 re-export that puts          `NodeCert`'s BLS identity on the chia-0.36 line); the tree resolved {}",
        versions[0]
    );
}

/// **Proves:** the §5.3 endpoint literals this crate re-exports come from the dig-constants line the
/// manifest names, and that the tree carries exactly the two copies the manifest graph accounts for.
///
/// **Catches:** two distinct regressions, neither of which the compiler can see.
///
/// First, a stale endpoint SSOT. `RPC_DIG_NET_URL`, `DIG_LOCAL_HOST` and `DIG_NODE_PORT` are
/// `pub use`d straight out of `read_ladder`, so an older dig-constants would republish stale
/// endpoints under THIS crate's own name — the drift dig-constants exists to end (#1283). Unlike the
/// type-identity invariants above, that is invisible to `cargo build`: the re-exports are a `&str`
/// and a `u16`, so every version of them type-checks identically.
///
/// Second, an unaccounted-for spread of dig-constants copies. One is not a number copied back out of
/// a lock file; it is what the manifest graph requires. Exactly two EDGES reach dig-constants — this
/// crate's direct `^0.10` and dig-nat 0.20's own `^0.10` — and because they agree, they resolve to a
/// single COPY. Nothing else in the tree depends on it (dig-dht → dig-ip + dig-nat; dig-peer →
/// dig-message, dig-nat, dig-rpc-protocol, dig-tls; dig-tls, dig-ip and dig-identity carry no dig
/// deps at all).
///
/// The `>=0.4, <0.6` pin that used to force a second copy is GONE: dig-nat 0.20 requires
/// `dig-constants = "0.10"`. This assertion has therefore been tightened from two copies to one —
/// which is exactly the handover its previous form was written to make.
///
/// Collapsing the copies collapsed the chia stacks behind them, because dig-constants 0.5.1 carried
/// `chia-consensus`/`chia-protocol` 0.26 while 0.10 carries 0.36.1. So a second dig-constants here
/// would resurrect a split chia line underneath a crate that names no chia type at all. Whether
/// anything actually CROSSES such a split is the separate, stronger question
/// `the_chia_stack_reachable_from_dig_crates_is_unified` answers; this test only keeps the edge
/// count honest.
#[test]
fn the_endpoint_ssot_resolves_the_named_constants_line() {
    let versions = locked_versions("dig-constants");

    assert_eq!(
        versions.len(),
        1,
        "expected exactly one dig-constants — this crate's direct `^0.10` and dig-nat 0.20's own \
         `^0.10` select the same release — found {versions:?}. A second copy means an edge \
         reintroduced an older pin, and with it a second chia stack"
    );
    assert!(
        versions[0].starts_with("0.10."),
        "the read ladder re-exports its endpoint literals from dig-constants, so the edge must \
         resolve the 0.10 line the manifest names; the tree resolved {versions:?}"
    );
}

/// **Proves:** exactly one `dig-dht`, on the 0.12 line that itself carries dig-nat 0.20.
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
        versions[0].starts_with("0.12."),
        "dig-dht must be on the 0.12 line (the release carrying dig-nat 0.20 + the bounded          ProviderStore::snapshot the relay's /dht view is built from); the tree resolved {}",
        versions[0]
    );
}
/// Every package in the resolved lock whose name begins with `chia`, paired with the set of packages
/// that depend on it, keyed as `"name version"`.
///
/// Built by reverse-walking the lock's dependency lists rather than by reading `Cargo.toml`, because
/// the question this answers is about the RESOLVED graph: a manifest can name one chia line while an
/// intermediate consumer drags in another.
fn chia_reverse_dependencies() -> std::collections::BTreeMap<String, std::collections::BTreeSet<String>> {
    let mut rev: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
        std::collections::BTreeMap::new();

    for block in LOCK.split("[[package]]") {
        let field = |key: &str| {
            block.lines().find_map(|l| {
                l.trim()
                    .strip_prefix(&format!("{key} = "))
                    .map(|v| v.trim_matches('"').to_owned())
            })
        };
        let (Some(name), Some(version)) = (field("name"), field("version")) else {
            continue;
        };
        let dependant = format!("{name} {version}");

        // A dependency line is `` "name",`` or `` "name version",`` — the version is present only
        // where the lock had to disambiguate duplicates, which is precisely the case of interest.
        for dep in block
            .lines()
            .map(|l| l.trim().trim_end_matches(','))
            .filter(|l| l.starts_with('"') && l.ends_with('"'))
            .map(|l| l.trim_matches('"'))
        {
            if dep.starts_with("chia") {
                rev.entry(dep.to_owned())
                    .or_default()
                    .insert(dependant.clone());
            }
        }
    }
    rev
}

/// **Proves:** every chia crate a DIG crate can reach is on the 0.36 line — stated as a property of
/// the graph, not as a count, and not against an enumerated list of chia crate names.
///
/// **Catches:** the exact defect that shipped twice in this cascade. dig-gossip 0.29.0 and the
/// published dig-nat 0.19.0 both went out internally SPLIT — part of their tree on chia 0.26, part on
/// 0.36 — because the pre-merge check was a hand-written list of chia crates to look at, and
/// `chia-bls` was not on it. `chia-bls` is the one that matters most here: `NodeCert`, the mTLS
/// identity every dig-download consumer must mint to dial a provider, is generated from a
/// `chia_bls::SecretKey` re-exported through `dig_tls::bls`. Two `chia-bls` lines in a consumer's tree
/// is an `E0308` at that call, and dig-download names no chia type anywhere in `src/`, so no grep of
/// THIS crate could ever have seen it coming.
///
/// **Why the assertion is shaped as an allow-list of ROOTS rather than a duplicate count:**
/// `cargo tree -d` is not the gate here and a count would be a false red. The 0.36 chia stack
/// legitimately vendors `clvmr` 0.16.4, whose own internals pin `chia-bls` 0.28.2 and `chia-sha2`
/// 0.34.0 — an implementation detail of the CLVM virtual machine that no DIG type crosses. So the
/// off-line copies are permitted, but only where every path to them begins at `clvmr`. A DIG crate
/// appearing as a dependant of an off-line chia crate reddens this test by name, which is the
/// property a count cannot express.
#[test]
fn the_chia_stack_reachable_from_dig_crates_is_unified() {
    /// The only root permitted to reach a chia crate off the 0.36 line.
    const PERMITTED_OFF_LINE_ROOT: &str = "clvmr";

    let rev = chia_reverse_dependencies();
    assert!(
        !rev.is_empty(),
        "no chia packages found in the lock at all — the parser, not the tree, has drifted"
    );

    let off_line: Vec<&String> = rev
        .keys()
        .filter(|k| {
            k.split(' ')
                .nth(1)
                .is_some_and(|v| !v.starts_with("0.36."))
        })
        .collect();

    for pkg in off_line {
        for dependant in &rev[pkg] {
            let dependant_name = dependant.split(' ').next().unwrap_or(dependant);
            let permitted = dependant_name == PERMITTED_OFF_LINE_ROOT
                // A chia crate off the line may of course depend on its own line-mates; the root of
                // every such chain is still checked, because the root itself appears here too.
                || (dependant_name.starts_with("chia")
                    && rev.contains_key(dependant.as_str()));
            assert!(
                permitted,
                "`{dependant}` depends on `{pkg}`, which is not on the chia-0.36 line. Only \
                 `{PERMITTED_OFF_LINE_ROOT}` may reach an off-line chia crate (its CLVM VM internals \
                 pin chia-bls 0.28.2 / chia-sha2 0.34.0 and no DIG type crosses them). A DIG crate \
                 here is the split that shipped in dig-gossip 0.29.0 and dig-nat 0.19.0"
            );
        }
    }

    // The chia crates the DIG stack actually names must be present AND singular, so the check above
    // cannot pass vacuously on a tree that resolved no 0.36 line at all.
    for named in ["chia-protocol", "chia-consensus"] {
        let versions = locked_versions(named);
        assert_eq!(
            versions.len(),
            1,
            "expected exactly one {named}, found {versions:?}"
        );
        assert!(
            versions[0].starts_with("0.36."),
            "{named} must be on the 0.36 line, found {}",
            versions[0]
        );
    }
}
