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
   holders after discovery ⇒ `DownloadError::NotFound`.
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

- **Concurrency** — up to `max_concurrency` range fetches in flight globally, and at most
  `max_inflight_per_source` to any one holder. The scheduler prefers the least-loaded available holder.
- **Source health** — a holder that fails or serves a bad range is penalized with capped-exponential
  backoff (`base_backoff` doubling per consecutive failure, capped at `max_backoff`); a success clears
  its failures + backoff. A holder is never permanently banned.
- **Rebalance** — a failed / dropped / unverifiable range is re-queued (state → `Pending`) and
  re-fetched from another holder. When a still-needed range has no live holder, `find_providers`
  re-runs (up to `max_relocate_attempts`) to discover more.
- **Termination (MUST)** — the download MUST terminate. It ends with `NoProviders { needed }` when the
  provider set is exhausted (no live holder for a still-missing range, or the retry budget
  `ranges.len() × max_range_attempts` is exceeded), and with `Cancelled` on `cancel()`.
- **Recoverable vs terminal** — `Transport` and `Verify` errors are recoverable per range (retry
  elsewhere). `Sink`, `State`, `NoProviders`, `NotFound`, `NotDownloadable`, `Cancelled`, `TaskEnded`
  are terminal for the download.

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

The real `RangeTransport` over dig-nat MUST NOT let a peer exhaust client memory:

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

`DownloadError`: `Transport { provider, reason }`, `Verify(VerifyError)`, `NoProviders { needed }`,
`NotFound { content }`, `Cancelled`, `State(reason)`, `Sink(reason)`, `NotDownloadable`, `TaskEnded`.
`Transport` and `Verify` are recoverable per range; the rest are terminal.

`VerifyError`: `Length { expected, actual }`, `Metadata(reason)`, `Alignment(reason)`, `Root`,
`MissingMetadata(reason)`. Every `VerifyError` is recoverable at the range level (the source is
penalized and the range re-fetched), except when it surfaces from the whole-resource backstop, which is
terminal for the download.
