# dig-download — normative specification

The authoritative contract for the DIG Node multi-source download orchestrator. An independent
reimplementation MUST satisfy every MUST/SHALL below and SHOULD satisfy every SHOULD. This spec is the
repo's own contract; it agrees with the ecosystem `SYSTEM.md` cross-repo map and the docs.dig.net L7
protocol pages, which govern the shared wire formats it consumes (`dig.getAvailability`,
`dig.fetchRange`, provider records, the `ContentId` / DHT key scheme).

`dig-download` locates the peers holding a piece of content, fetches its byte ranges from multiple
peers concurrently, verifies each range and the whole resource against a chain-anchored generation
root, and reassembles the verified bytes into a sink — with pause/resume that never re-fetches a
verified range.

---

## 1. Content identity and granularity

A download targets a `ContentId` (re-exported from `dig-dht`) at one of three granularities:

- **`Store { store_id }`** — a whole store. NOT directly downloadable: `download` MUST fail with
  `DownloadError::NotDownloadable` (a store names many capsules, not one byte stream).
- **`Root { store_id, root }`** — a capsule / generation `store_id:root`. Fetched as a whole capsule
  (`capsule: true`); the capsule self-verifies on install, so it carries no per-resource inclusion
  proof.
- **`Resource { store_id, root, retrieval_key }`** — one resource within a capsule. Fetched with
  `capsule: false`; verified against the whole-resource inclusion proof under `root`.

All three fields are raw 32-byte hashes. On the wire they are lowercase 64-hex. The stable resume key
for a content id is the lowercase hex of its `dig-dht` DHT content key (`ContentId::to_key`).

---

## 2. Wire contracts consumed (dig-nat L7)

`dig-download` does not define these formats; it consumes them and MUST match them byte-for-byte.

### 2.1 `dig.getAvailability`

An `AvailabilityItem { store_id, root?, retrieval_key? }` per queried content id. A holder answers
`AvailabilityAnswer { available, roots?, total_length?, chunk_count?, complete? }`. A provider is a
confirmed holder iff its answer's `available` is `true`.

### 2.2 `dig.fetchRange`

A `RangeRequest { store_id, retrieval_key?, root?, capsule, offset, length }` selects
`[offset, offset+length)` of the resource (capsule) ciphertext. The holder streams `RangeFrame`s in
ascending `offset` order that tile the requested range exactly; the caller reassembles by `offset` and
stops on the frame marked `complete` (or on clean end-of-stream).

The **first frame** of a range additionally carries the whole-resource verification metadata:
`total_length`, `chunk_lens` (per-chunk ciphertext lengths, in order), `chunk_index` (index of the
first chunk in this range), `inclusion_proof` (base64, absent for a capsule), and `root` (64-hex, the
generation the inclusion proof is against).

---

## 3. The download flow (normative order)

An implementation MUST perform, in order:

1. **Guard** — reject a bare `Store` content id (`NotDownloadable`).
2. **Discover** — `ProviderLocator::find_providers(content)` returns candidate holders.
3. **Confirm** — `dig.getAvailability` per candidate; keep only confirmed holders. Zero confirmed
   holders after discovery ⇒ `DownloadError::NotFound`. A `NotFound`'s `content` MUST name the step
   that failed — `no providers located for …` (discovery/confirm found nobody) versus
   `could not read resource metadata for … — the metadata probe failed on all N confirmed holder(s)`
   (§4) — so a probe failure is never reported as a discovery miss.
4. **Establish the commitment** (§4) — unless resumed from persisted state.
5. **Plan** (§5) — partition the resource into chunk-aligned ranges; mark resume-done ranges done.
6. **Schedule** (§6) — fan ranges across holders concurrently, verify (§7) each, retry/rebalance.
7. **Whole-resource backstop** (§8) — bind the reassembled `resource_leaf` to the chain-anchored root.
8. **Finalize** — finalize the sink; clear the resume checkpoint; emit `Completed`.

---

## 4. The resource commitment

The `ResourceCommitment { layout, total_length, root, inclusion_proof }` is the trusted per-resource
metadata every range verifies against. It is established ONCE via a meta-probe (fetch a tiny range,
read its first frame) and is then immutable for the life of the download.

- **From-frame validity** — `chunk_lens` MUST sum to `total_length`; otherwise the peer's frame is
  rejected and the next holder is probed.
- **Root binding to the request (MUST)** — before adopting a peer's first-frame metadata, an
  implementation MUST require the peer-reported `root` to equal the content-id's own generation `root`
  (for `Root` / `Resource` granularities; a bare store carries no root). A peer whose reported root
  differs MUST be skipped, NOT adopted. This binds the plan's ground truth to the caller's request
  rather than to whichever peer answers the meta-probe first. If no holder reports the requested root,
  the commitment cannot be established ⇒ `NotFound`.
- **Consistency of later ranges** — every subsequent range's first-frame `total_length` / `chunk_lens`
  / `root`, when present, MUST equal the commitment's; a mismatch is a `VerifyError::Metadata`
  (recoverable — the source is penalized and the range re-fetched).
- **Persistence** — the commitment (total_length, chunk_lens, root, inclusion_proof) is checkpointed
  so a crash-resume skips the meta-probe and re-plans identically.

---

## 5. Range planning

`ChunkLayout` maps `chunk_lens` to cumulative byte offsets. `plan_ranges(layout, window)` partitions
the resource into contiguous, **chunk-aligned** ranges:

- Chunks are packed greedily into a range while the range stays within `window`.
- A range is ALWAYS ≥ one whole chunk; a chunk larger than `window` becomes its own range.
- The ranges tile the whole resource exactly, in ascending offset order; each range's `length` equals
  the sum of the lengths of the chunks it covers.

A range is the scheduling atom: fetched from one holder at a time, verified, marked done. A done range
is NEVER re-fetched (the resume invariant).

---

## 6. Scheduling, retry, and termination

- **Delegated selection (MUST — no second brain)** — peer CHOICE and ORDER are delegated to an injected
  `SourceSelector` (§15); dig-download itself MUST NOT keep a throughput model / speed ranking /
  cross-transfer learning of its own. On each scheduling pass the scheduler calls `select` with the
  currently-live candidates (already filtered by liveness/backoff — see below) and assigns each pending
  range to the first peer in the returned preference order that is under its `max_inflight_per_source`
  cap (an explicit per-range pin in the plan wins when its peer has capacity). With no selector injected
  a fair round-robin (`NullSelector`) is used, keeping the crate usable standalone.
- **Outcome reporting (MUST)** — every range fetch's measured outcome MUST be reported to the selector
  via `record(RangeOutcome { peer_id, bytes, elapsed, result })` where `result ∈ { Ok, Failed,
  TimedOut }`. This is the selector's only learning signal; dig-download derives no ranking from it.
- **Concurrency** — up to `max_concurrency` range fetches in flight globally, and at most
  `max_inflight_per_source` to any one holder.
- **Source liveness (backoff debounce, NOT ranking)** — a holder that fails, times out, or serves a bad
  range is placed in a capped-exponential backoff window (`base_backoff` doubling per consecutive
  failure, capped at `max_backoff`) during which it is not offered to the selector; a success clears its
  failures + backoff. This is purely a liveness/availability debounce — it is NOT a throughput judgement
  (that is the selector's job). A holder is never permanently banned.
- **Per-range timeout (MUST when configured)** — when `range_timeout` is set, a range fetch exceeding it
  is abandoned with `Timeout { provider }` (recoverable), re-queued elsewhere, the source backed off,
  and the outcome reported to the selector as `TimedOut`. Default 30s; `None` disables it.
- **Rebalance + live upgrade** — a failed / dropped / timed-out / unverifiable range is re-queued (state
  → `Pending`) and re-fetched from another holder. When a still-needed range has no live holder,
  `find_providers` re-runs (up to `max_relocate_attempts`) to discover more. Independently, when
  `refresh_interval` is set (default 15s), `find_providers` re-runs PERIODICALLY during the download and
  merges any newly-discovered holders into the candidate set (without consuming the relocate budget), so
  the selector can rebalance onto a faster/fresher holder that appears mid-download — the "live
  upgrade". No in-flight fetch is preempted; the new candidate is used for subsequent range assignments.
- **Termination (MUST)** — the download MUST terminate. It ends with `NoProviders { needed }` when the
  provider set is exhausted (no live holder for a still-missing range, or the retry budget
  `ranges.len() × max_range_attempts` is exceeded), and with `Cancelled` on `cancel()`.
- **Recoverable vs terminal** — `Transport`, `Verify`, and `Timeout` errors are recoverable per range
  (retry elsewhere). `Sink`, `State`, `NoProviders`, `NotFound`, `NotDownloadable`, `Cancelled`,
  `TaskEnded` are terminal for the download.

---

## 7. Per-range integrity (MUST — fail-closed)

When a range's bytes arrive, an implementation MUST, before accepting them:

1. **Metadata consistency** — first-frame `total_length` / `chunk_lens` / `root` (when present) MUST
   agree with the commitment (§4), else `VerifyError::Metadata`.
2. **Exact length** — the reassembled bytes MUST be EXACTLY the planned range length. `bytes.len() !=
   range.length` ⇒ `VerifyError::Length`. This check is load-bearing: a peer may serve fewer whole
   chunks than requested (a **boundary-aligned short range**) whose bytes still start and end on chunk
   boundaries — structurally aligned yet incomplete. The exact-length comparison is the only thing that
   rejects that short range. An implementation MUST NOT rely on chunk-alignment alone to prove a range
   is complete.
3. **Chunk alignment** — the range MUST start at the offset of its declared first chunk and end on a
   chunk boundary, else `VerifyError::Alignment`.

A range that fails any check is discarded (its source penalized) and re-fetched from another holder. A
range is marked `Done` ONLY after passing all three checks; consequently a short/incomplete range can
never be written to the sink as complete nor counted toward progress.

---

## 8. Whole-resource integrity (MUST — fail-closed)

When `verify_whole_resource` is enabled, the reassembled resource's
`resource_leaf = SHA-256(concatenated chunk ciphertexts)` (untagged, matching the digstore
merkle-proofs read path) MUST be bound to the chain-anchored generation `root` via the injected
`ProofVerifier`.

- **Fail-closed length (MUST)** — the assembled length MUST equal the committed `total_length`. A
  short/incomplete assembly MUST return `VerifyError::Length` and MUST NOT fall through to a successful
  finalize. (An implementation MUST NOT skip the backstop merely because the assembled length differs
  from the total — that is the failure, not a reason to skip.)
- **Root binding (MUST)** — a `resource_leaf` the `ProofVerifier` does not accept under
  `(inclusion_proof, root)` MUST return `VerifyError::Root`.
- **Incremental hashing (SHOULD)** — the `resource_leaf` SHOULD be computed by streaming SHA-256 over
  ranges fed in offset order (buffering only the minimal out-of-order window), NOT by retaining every
  range and concatenating a second full-length copy. This bounds transient memory to O(the out-of-order
  window) instead of O(2 × resource size).
- **Resume exception** — on a crash-resume where earlier ranges were verified in a PRIOR process (their
  bytes live only in the sink, not this run's memory), the in-memory whole-resource backstop is skipped.
  This is safe because every range — resumed or freshly fetched — passed the per-range checks of §7; the
  whole-resource root binding is not silently claimed over bytes not present this run.

### 8.1 Verifier construction posture (MUST)

The chain binding is delegated to an injected `ProofVerifier` (the digstore merkle-proof byte format
lives with the store types). To prevent an accidentally fail-open verifier:

- The production `MerkleVerifier` MUST be constructed with an explicit, chain-bound `ProofVerifier`
  (`with_proof_verifier`). There MUST be no `new()` / `Default` constructor that yields a verifier
  performing no on-chain binding.
- A structural-only verifier (length + alignment + metadata consistency, NO chain binding) is fail-open
  on the root and MUST be reachable only via an explicitly named, hidden opt-in
  (`insecure_structural_only`) for tests / deliberate opt-in — never as a default.

---

## 9. Transport resource bounds (MUST)

The real `RangeTransport` (`NatRangeTransport`) reaches every holder through the shared `dig-peer`
client (`DigPeer`) — the ONE DIG Network peer client — rather than driving `dig-nat` directly, so the
whole ecosystem connects to peers ONE way (#1283). Every connection is established through a
`PeerTarget` carrying the holder's `peer_id`, which `DigPeer::connect_with_runtime` PINS the mTLS
handshake to: a caller meaning to reach holder X MUST NOT be answered by a different CA-valid peer (the
impersonation footgun). Availability + range calls are public-read (merkle-verified content), so they
ride the mTLS channel unsealed (§5.4 exemption); this transport configures no `SealingIdentity`.

The transport MUST NOT let a peer exhaust client memory:

- **Bounded range assembly** — range reassembly is bounded by the expected range length; a frame that
  would overflow the expected length is a transport error.
- **Bounded trailer drain (MUST)** — after the last frame, any trailer read to close the mux stream
  cleanly MUST be bounded (read-and-discard up to a fixed cap through a small fixed scratch buffer). An
  implementation MUST NOT drain the trailer into an unbounded buffer (e.g. `read_to_end` into a `Vec`):
  a peer that keeps the stream open and streams filler after a valid range would otherwise exhaust
  memory.
- **Connection reuse (SHOULD)** — a transport SHOULD pool one mTLS connection per peer and open a fresh
  mux stream per request rather than re-handshaking per range/availability call; a connection that
  errors is evicted so the next request re-dials. Per §5.3 of the ecosystem contract, a node-class
  client connects over mTLS.
- **Full NAT-traversal dial (MUST)** — the fetch transport MUST dial each holder over the FULL
  NAT-traversal ladder (direct → port-mapping → hole-punch → relay), composing exactly the tiers whose
  live handles the node supplied. A fully-NAT'd peer that DISCOVERS a non-Direct-reachable holder MUST
  still be able to FETCH from it (over hole-punch/relay), not just from directly-reachable holders. The
  same ladder that carries DHT discovery carries the byte download.

### 9.1 Candidate address resolution (MUST)

A provider record's candidate `host` is an IP **literal** (IPv4, IPv6, or v4-mapped IPv6).

- A candidate MUST be resolved by parsing `host` as an IP address and CONSTRUCTING the socket address
  with the candidate's port. An implementation MUST NOT compose `"{host}:{port}"` and parse that text
  as a socket address: the socket-address grammar requires an IPv6 literal to be bracketed, so the
  round trip rejects every IPv6 candidate before any socket is opened.
- Rendering a candidate as text (logs, selection DTOs) MUST bracket an IPv6 literal, so the rendered
  form parses back as a socket address.
- A `host` that is not an IP literal is NOT dialable (this crate performs no DNS resolution on the dial
  path); such a candidate MUST be skipped with a named reason, never treated as fatal to the provider.
- **IPv6-first with IPv4 fallback (§5.2).** A dial MUST try EVERY dialable candidate of the provider in
  order — IPv6 candidates first, then IPv4, then relay-only reachability by identity — and MUST report
  the holder unreachable only after every candidate has failed. The number of candidates tried per
  provider is bounded. Each failed attempt MUST be logged with the address that produced it.

---

## 10. Reassembly, staging, and resume

- **Positioned writes** — verified ranges are written to the `Sink` by absolute offset, in arbitrary
  order (concurrent fan-out); a sink MUST place by offset, not assume sequential writes.
- **Atomic finalize** — a file-backed sink stages into `<target>.download.tmp` (opened create-or-reuse,
  NEVER truncating, so a resume reattaches to the partial file) and, on finalize, flushes + syncs +
  atomically renames the staging file onto the final path. A reader MUST never observe a partial final
  file; a crash MUST leave only a `.download.tmp`, never a corrupt final file.
- **Resume** — per-range progress is checkpointed to a `StateStore`. A paused or crashed download
  resumes into the same staging file and re-fetches ONLY the still-missing ranges; a verified range is
  never re-fetched.
- **GC** — a stale `.download.tmp` is reaped by the GC sweep; a live or paused-resumable staging file
  (registered in `ActiveDownloads`) MUST NOT be reaped.

---

## 11. Progress and control

A download exposes a live `DownloadEvent` stream (`Planned`, `RangeCompleted`, `RangeFailed`,
`ProvidersRefreshed`, `Paused`, `Resumed`, `Completed`, `Failed`) and `pause()` / `resume()` /
`cancel()` / `join()`. `pause` issues no new fetches (in-flight fetches finish, progress is
checkpointed); `cancel` ends the download with `Cancelled`.

---

## 12. Error catalogue (stable)

`DownloadError`: `Transport { provider, reason }`, `Timeout { provider }`, `Verify(VerifyError)`,
`NoProviders { needed }`, `NotFound { content }`, `Cancelled`, `State(reason)`, `Sink(reason)`,
`NotDownloadable`, `TaskEnded`. `Transport`, `Timeout`, and `Verify` are recoverable per range; the
rest are terminal.

`VerifyError`: `Length { expected, actual }`, `Metadata(reason)`, `Alignment(reason)`, `Root`,
`MissingMetadata(reason)`. Every `VerifyError` is recoverable at the range level (the source is
penalized and the range re-fetched), except when it surfaces from the whole-resource backstop, which is
terminal for the download.

---

## 13. Download queue (bounded, first-come-first-serve)

Capsule downloads are QUEUED, not all launched at once (a cache-fill flywheel may enqueue many). The
`DownloadQueue` wraps a `Downloader` and admits at most `max_active` downloads concurrently (default 3);
the rest wait.

- **Bound (MUST)** — at most `max_active` downloads run concurrently.
- **FCFS (MUST)** — queued downloads START in submission order; no reordering, no starvation. (A job
  leaves the queue only when a worker is free, and jobs are drained in submission order.)
- **Transparent handle** — `submit` returns a `QueuedHandle` exposing the same live `DownloadEvent`
  stream + terminal result as a direct `Downloader::download`, whether the download ran immediately or
  waited for a slot. If the queue is dropped before a download runs, its `join` yields `TaskEnded`.

---

## 14. Outbound serve throttle (FCFS rate limiter)

`FcfsRateLimiter` is the reusable primitive for the SERVE side (a node serving capsule bytes to
requesting peers), so a node never overwhelms a single peer or its own uplink. A serve handler calls
`acquire(conn_key, bytes)` before writing each chunk.

- **Two caps (MUST)** — a GLOBAL byte-rate cap across all connections AND a PER-CONNECTION cap keyed by
  an opaque connection key; both MUST be satisfied before bytes flow. A cap of `0` means unlimited for
  that dimension.
- **FCFS (MUST)** — admission is strictly arrival-order (a fair FIFO gate): a burst of large requests
  MUST NOT starve a smaller request that arrived earlier.
- **Token bucket** — each cap is a token bucket refilling at its byte-rate, holding at most one second's
  burst. An oversized single request (larger than one second's capacity) is admitted (it cannot be
  split) and its debt is repaid by the following callers' waits — it MUST NOT deadlock the limiter.

---

## 15. Source-selection seam (`SourceSelector`)

The selection seam decouples "which peers, in what order" (a self-optimizing decision, owned by
`dig-peer-selector`) from execution (owned by dig-download). dig-download defines the trait + its own
minimal DTOs and DELEGATES to an injected implementation; it keeps no ranking model (§6).

- **Layering (MUST)** — dig-download and dig-peer-selector are both level-30, so dig-download MUST NOT
  depend on dig-peer-selector (reference-DOWN only). The trait + DTOs are therefore defined IN
  dig-download; dig-peer-selector (or a dig-node adapter) implements it. dig-node's `Provenance` /
  address book MUST NOT enter these types — a candidate carries only an opaque `tag` dig-download
  round-trips but never interprets.
- **Trait** — `SourceSelector { fn select(&SelectRequest) -> SelectPlan; fn record(&RangeOutcome); }`
  (both `&self`, so one selector informs many concurrent downloads via interior mutability).
- **DTOs** — `CandidateRef { peer_id, addrs, tag: Option<u64> }`; `SelectRequest { content_key,
  candidates, ranges_needed, inflight }`; `SelectPlan { ordered: Vec<peer_id>, assignments:
  Vec<(range_index, peer_id)> }` (assignments optional); `RangeOutcome { peer_id, bytes, elapsed,
  result: RangeResult }`; `RangeResult ∈ { Ok, Failed, TimedOut }`.
- **Default** — `NullSelector` is a fair round-robin that learns nothing, so dig-download standalone has
  no hidden ranking brain.
- **Candidate set** — the scheduler offers the selector only LIVE candidates (holders not in a
  liveness/backoff window); the selector reasons about speed/preference, never liveness.

> **Deferred (not in this version):** per-range merkle-proof binding on the wire (#1437, transport
> lane) is not yet shipped; dig-download keeps the existing per-range length/alignment + whole-resource
> root binding (§7/§8). Consuming a per-range proof is a separate additive increment once #1437 lands.

---

## 16. Client→node read-ladder (`read_ladder`, §5.3)

Reaching a specific, already-known holder is done by `peer_id`-pinned `PeerTarget` over the
`RangeTransport` (§9). Reaching *a DIG node* — for a node-class client that has no particular peer in
mind (a CLI, an SDK, a filesystem client holding a DIG identity key) — is a distinct concern and lives
here at L30 (a fetch-client concern; previously carried in the dig-store CLI, #1283). `resolve_node`
MUST select the endpoint in this fixed order, taking the FIRST tier that answers a cheap health probe
within a short timeout:

1. **Explicit override** — always wins, the ladder is not consulted. Precedence among override sources,
   highest first: an explicit `--node` flag/argument > `$DIG_NODE_URL` > a persisted `node.url` config
   value. A caller extracts these into `OverrideInputs` (this module performs no I/O).
2. **`dig.local`** — the installed local node (the installer's hosts registration).
3. **`localhost`** — a node on the loopback default read port (`DIG_NODE_PORT`, canonical 9778), when
   `dig.local` does not resolve/respond.
4. **`rpc.dig.net`** — the public gateway. FINAL fallback only; returned even if it does not itself
   answer the probe (nowhere left to fall through to). MUST NEVER be hard-coded as the primary endpoint.

- **Probe seam (MUST)** — resolution is transport-free: it takes a `HealthProbe` trait so the
  fall-through ORDER is unit-testable without a network. The optional `HttpHealthProbe` (feature
  `http-probe`) is a ready-made `GET {base}/health` probe that races the request against the
  caller-supplied timeout and treats any non-2xx / transport error / elapsed timeout as "not reachable".
- **Caching (MUST)** — the resolved choice is cached per invocation (`CachedResolver` resolves once);
  a command needing the endpoint more than once MUST NOT re-probe the ladder.
- **Transport mode (§5.3)** — a node-class client is required to speak mTLS to every tier, including
  `rpc.dig.net` (dual-mode: mTLS for node-class clients, plain HTTPS+CORS for browsers). `TransportMode`
  is the explicit-enum seam (`Https` default, `Mtls`) that flips the transport to mTLS once the
  gateway's mTLS endpoint exists — an additive change, not a break to the ladder logic.
