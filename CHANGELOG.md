# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.12.0] - 2026-07-27

### Features
- **security:** Re-check EVERY range frame against the identity its first frame declared
  (`root` / `total_length` / `chunk_count`, plus a non-rewinding `chunk_index`), and reject a later frame
  that re-covers `chunk_lens` entries an earlier page already filled or restates the inclusion proof. A
  conforming NEXT page is recognised as paging and reported as a reader limitation, never as a peer
  violation — the field that distinguishes the two is `chunk_lens_offset`, where absent means 0. The reader
  previously read frame 1 and discarded every later frame's declarations, and nothing beneath it performs
  this check (#1668).
- **security:** Refuse a holder that streams without progressing. A non-final frame that does not extend the
  assembled prefix — an empty payload, or a re-send of an already-written offset — previously looped forever
  while holding the staging claim that makes a staging path both GC-exempt and un-downloadable.
- **security:** Bound the metadata probe by `range_timeout`. It runs before the scheduler exists and does not
  poll the control channel, so an unbounded probe could be pinned indefinitely by one holder.
- **security:** Refuse a holder that OMITS the generation `root`. The guard fired only when both the
  request's root and the holder's were present, so silence skipped it entirely and cost a whole wasted fetch.
- **security:** Sanitize the peer-supplied root in the root-mismatch diagnostic through
  `hex64_or_sentinel`. That reason is logged as a raw `String` rather than through `DownloadError`'s
  `Display`, so a holder could otherwise inject newlines, ANSI or bidi overrides into debug output (#1603).
- Replace the generic all-holders-failed `NotFound` with named errors: `MetadataProbeFailed`, carrying the
  per-holder reason that previously went to a `tracing::debug!` and was dropped, and
  `PagedPrologueUnsupported`. A reassembly error is ATTRIBUTED to its provider rather than wrapped in a
  fresh `Transport`, which had flattened every typed variant and made the recoverability distinction
  unobservable.
- **testkit:** `Behavior::ShortLayout` takes an `AvailabilityClaim` (`Honest` / `OwnShortShape` / `Silent`)
  in place of a bool, so a holder that declares NOTHING is expressible.
- **tests:** A mechanical `doc_vocabulary` guard fails the build if a comment describes one of the rejected
  ordering designs without marking it as history. It asserts REACH as well as absence — file-size floors,
  required anchors, and a positive find — because a grep guard that visits nothing passes identically to one
  that finds nothing wrong.

### Not shipped, deliberately — #1670 remains OPEN
- **A first-position holder can still deny a read** by declaring a short but self-consistent layout under
  the correct root. A whole-resource refutation is terminal and attributes to nobody.
- An attributability + exclusion + retry mechanism for it was built and REMOVED. Every version had to vote
  over `dig.getAvailability`'s `total_length` / `chunk_count`, which are OPTIONAL wire fields: an attacker
  forges one for the price of a keypair and an announce, and an honest holder legitimately omits them — a
  conforming node populates them only at resource granularity, so at capsule granularity the honest
  population is silent. Each version produced a cheaper denial than the one it fixed, plus an egress
  amplifier (up to one whole transfer per retry attempt, pulled from honest holders, triggered by one
  anonymous record — measured as 5 range fetches becoming 15 and 19 on two fixtures) and a terminal error naming honest peers as culprits. Not shipping it is strictly
  not-worse-than-baseline.
- **Integrity was never at risk** in any of those cases: the chain-anchored leaf check refuses every
  truncated or forged assembly, and nothing unverified is promoted. #1670 is re-scoped onto per-chunk
  attribution, the only evidence that can name a bad holder. `SPEC.md` §4 states this normatively, including
  that the vote is forbidden and why.

### Breaking
- `dig-nat` 0.13 -> **0.14**, `dig-dht` 0.7 -> **0.8**, `dig-peer` 0.6 -> **0.7**. All three move together:
  a 0.x MINOR is semver-incompatible, so any one left behind reintroduces a `^0.13` requirement and splits
  the tree into two dig-nat instances, which does not merely warn — it fails to compile on the
  `DigPeer::fetch_range` seam. `tests/dependency_tree.rs` asserts the singularity from the tracked lock.
- `RangeMeta` gains `chunk_count` and becomes `#[non_exhaustive]`; build one with `RangeMeta::from_frame`
  or `Default` plus the `declaring_*` setters.
- `ResourceCommitment` and `DownloadConfig` become `#[non_exhaustive]`.
- `DownloadError` gains two variants.
- **testkit:** `Behavior::ShortLayout`'s `also_in_availability: bool` becomes
  `availability: AvailabilityClaim`.

### Documentation
- `DEFAULT_MAX_RESOURCE_SIZE` now states that it bounds HOST MEMORY, not layout capability. Value unchanged
  at 512 MiB: it is the `pub const` default of a public config field, so lowering it would break deployments
  that read fine today.
- `SPEC.md` §2.2 / §3 / §4 / §6 / §11 / §12 state the per-frame identity and paging rules, the
  provisional-commitment framing, the terminal-refutation requirement with the forbidden vote and the open
  residual, discovery-order adoption, probe bounding, and the error catalogue.
- The three rejected ordering/attribution designs are recorded in `orchestrator.rs` beside the code that
  replaced them, so #1670 does not rediscover them.

## [0.11.0] - 2026-07-27

### Chores
- **deps:** Adopt dig-nat 0.13 / dig-dht 0.7 / dig-peer 0.6 / dig-rpc-protocol 0.6 (#1656 level 3) (#19)

## [0.10.0] - 2026-07-26

### Features
- **dig-download:** Bind resumed reads to the chain root + promote only verified bytes (#18)

## [0.8.1] - 2026-07-26

### Chores
- **deps:** Bump dig-peer 0.4.1 -> 0.5.0 to collapse a ModuleInfo shape skew (#1576) (#17)

## [0.8.0] - 2026-07-26

### Features
- **dig-download:** ModuleDownloader — fail-closed whole-.dig peer pull (#1576) (#13)

## [0.7.4] - 2026-07-26

### Bug Fixes
- **source:** Clip an over-long range frame instead of erroring (#836) (#16)

## [0.7.3] - 2026-07-26

### Bug Fixes
- **source:** Parse provider host as IpAddr + try all candidates v6->v4 (#836) (#15)

## [0.7.2] - 2026-07-25

### Bug Fixes
- **orchestrator:** Name the failing step in NotFound + trace locate/probe (#1586) (#14)

## [0.7.1] - 2026-07-23

### Chores
- **deps:** Bump dig-nat 0.11 + dig-dht 0.5.1 + dig-peer 0.4.1 (#12)

## [0.7.0] - 2026-07-22

### Features
- **dig-download:** Adopt DigPeer transport + §5.3 read-ladder (#1283) (#11)

## [0.6.0] - 2026-07-22

### Chores
- **deps:** Adopt dig-nat 0.10 + dig-dht 0.5 (cascade #1494) — release 0.6.0 (#10)

## [0.5.1] - 2026-07-22

### CI
- **lockfile:** Gate Cargo.lock own-version + --locked in ci (#9)

## [0.5.0] - 2026-07-21

### Features
- **dig-download:** Active download optimizer + selector-agnostic seam (#1435 #1440) (#8)

## [0.4.0] - 2026-07-21

### Features
- **dig-download:** Dig-dht 0.4 + full NAT dial ladder on content fetch (§5.3 fall-through) (#7)

## [0.3.0] - 2026-07-21

### Chores
- **deps:** Adopt dig-nat 0.8 + dig-dht 0.3 (cascade) + release 0.3.0 (#6)

## [0.2.1] - 2026-07-20

### Chores
- **deps:** Bump dig-nat to 0.7 (full NAT ladder unification, #836) (#5)

## [0.2.0] - 2026-07-20

### Features
- **deps:** Adopt dig-nat 0.6.0 (dig-tls CA-signed cert cutover) (#4)

## [0.1.3] - 2026-07-18

### Features
- **dig-download:** Bump to latest dig-nat 0.3 + dig-dht 0.1.3 (#947) (#3)

## [0.1.2] - 2026-07-17

### Bug Fixes
- **deps:** Resolve dig-nat 0.2 from crates.io (#2)

## [0.1.1] - 2026-07-12

### Bug Fixes
- **deps:** Re-resolve DIG git deps to rewritten (co-author/signed) revs

### CI
- Enforce version increment in PRs (package.json / Cargo.toml)- Enforce Conventional Commits with commitlint on PRs- Enforce Conventional Commits with commitlint on PRs- Release automation (git-cliff changelog + tag on merge); publish is manual workflow_dispatch (#230)- Re-arm crates.io auto-publish on version tag (token in org secrets; auto-publish-everything #230)- Add flaky-test management (#489) (#1)

### Chores
- **changelog:** Add git-cliff config for Conventional-Commit changelog


