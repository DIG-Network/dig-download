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
ascending `offset` order covering the requested range; the caller reassembles by `offset` and
stops on the frame marked `complete` (or on clean end-of-stream).

**Reassembly window (normative).** A holder **MUST NOT serve past `offset+length`** — the served span is
exactly the requested one, because a holder that streams to the end of a resource regardless of `length`
is a remote-amplification vector. A caller nevertheless **clips defensively**: it cannot know a holder is
compliant, and historically a chunk-granular holder answered a 1-byte metadata probe with a whole chunk.
Clipping is therefore defense-in-depth, NOT the primary bound, and it is never traded for rejection. The
caller:

- MUST place each frame's bytes at its range-relative `offset`, **clipped** to the requested `length`,
  and MUST stop reading frames once `length` bytes are assembled — so the assembled buffer is bounded
  by `length` regardless of what the holder streams. `length` is NOT self-evidently safe: it derives from
  the peer-DECLARED `chunk_lens`, so it is bounded in turn by the commitment ceiling (section 4) and the
  buffer's growth MUST be a FALLIBLE reservation. A frame sparse in a large window (a high `offset`, a few
  payload bytes) otherwise drives one allocation of the whole window from a single small frame.
- MUST NOT reject a frame merely for extending past the window. An over-long answer is handled by
  clipping; a client-side REJECTION of it is forbidden (it makes every chunk-granular holder unusable —
  the defect that broke the read leg). Verification therefore runs on the CLIPPED range: an
  exact-length check downstream is a check on the assembled range, never a verdict on what the holder
  streamed.
- MUST reject (as a protocol violation) a frame whose `offset` is at or beyond `length`: its bytes
  cannot belong to the requested range.
- MUST capture the first frame's verification metadata (below) before any window check, so a
  metadata-only probe (`length = 1`) succeeds against any granularity.
- MUST re-check every LATER frame against the identity the first frame declared, and MUST fail the fetch
  on any disagreement. Reading the first frame and discarding the rest lets a holder declare an honest
  shape on the frame the commitment binds to and a different one on every frame after it, and be believed
  on the first — a revision nothing downstream can recover, because the commitment is already adopted.
  The rule is over the CLASS of revision, not one direction of one field: a changed value MUST be
  rejected, and so MUST a value that appears only on a later frame after the first frame left it unstated,
  since that withholds it from the frame the reader binds to. A later frame that merely OMITS an identity
  field asserts nothing and MUST be accepted. `chunk_index` is the exception: it is per-FRAME, so it may
  advance but MUST NOT rewind (frames arrive in ascending `offset`). A reader MUST NOT enforce
  `chunk_index` as invariant — doing so rejects every conforming multi-frame stream.
- MUST reject a later frame that RESTATES a once-per-stream prologue field, whether or not it agrees.
  Refusing the restatement rather than comparing it is what makes "the first frame said A, a later frame
  said B" inexpressible instead of merely unpersuasive. The two prologue fields differ in what counts as a
  restatement, and conflating them refuses conforming senders:
  - `inclusion_proof` has NO paged form — there is only ever one proof — so ANY later frame carrying it is
    restating.
  - `chunk_lens` DOES have a paged form, so "MUST NOT be repeated" forbids re-covering entries an earlier
    page already filled; it does NOT forbid a later frame from carrying the NEXT page. The field that
    distinguishes them is `chunk_lens_offset`: a page whose offset is below the highest already-filled entry
    (including an absent offset, which means 0) MUST be rejected, and a page at or above it is a conforming
    continuation. An implementation MUST NOT read the rule as "only the first frame may carry `chunk_lens`":
    that hands a conforming paging holder a protocol-violation verdict.
- MUST terminate against a holder that streams without progressing. Every exit from the reassembly loop
  depends on the window filling or the holder setting `complete`, so a non-final frame that does not extend
  the assembled prefix — an empty payload, or a re-send of an already-written offset — MUST be rejected. The
  rule is over the CLASS (a frame that extends nothing), not over the empty-payload instance of it, because
  a re-send carries real bytes and advances just as little. Otherwise a holder streams indefinitely on a few
  dozen bytes per frame while the download holds its staging claim, making that staging path both permanently
  GC-exempt and permanently un-downloadable.

A range's frames additionally carry whole-resource verification metadata, and it splits into **two
sets with different rules** — conforming to the wrong one produces a verification miss on a
multi-frame read rather than a clean failure:

- **Identity — fixed-size, on EVERY frame:** `root` (64-hex, the generation the inclusion proof is
  against), `total_length`, `chunk_count`, and `chunk_index` (the index into `chunk_lens` of this
  frame's first chunk) wherever the window is chunk-aligned. These are what let a reader reject a
  wrong-generation or wrong-layout holder the moment a frame arrives — a property the once-per-stream
  set can never have, because it arrives once. They are bounded in size, so carrying them on every
  frame is cheap.
- **Prologue — resource-scaling, ONCE per range stream:** `chunk_lens` (per-chunk ciphertext lengths,
  in order, located by `chunk_lens_offset` when paged) and `inclusion_proof` (base64, absent for a
  capsule). Their size is a function of the RESOURCE rather than of the frame, so they ride the first
  frame or a paged prologue and MUST NOT be repeated on later frames. A request that set
  `skip_layout` suppresses them entirely.

Before dig-nat 0.13.0 every one of these was "first frame only", because the whole layout had to fit
one frame or the range was unservable. An implementation MUST NOT treat `chunk_index` as
first-frame-only: it is identity, and a chunk-aligned continuation frame states it.

A reader MUST NOT adopt an INCOMPLETE `chunk_lens` as a layout. `chunk_lens` is a decrypt input —
per-chunk AES-GCM-SIV needs the whole array — so a partial array is not a degraded layout but one
that decrypts every chunk to garbage. The sum check in section 4 ("`chunk_lens` MUST sum to
`total_length`") is what enforces this: a single page of a paged prologue sums short and is rejected.
Reassembling a paged prologue across frames is NOT yet implemented by this crate; such a resource is
refused rather than mis-read, and the refusal is NAMED: a holder that declares a `chunk_count` larger
than the number of `chunk_lens` entries it delivers MUST be rejected as `PagedPrologueUnsupported` — reporting it
as a generic all-holders-failed result cannot be told apart from "nobody holds this content".

---

## 3. The download flow (normative order)

An implementation MUST perform, in order:

1. **Guard** — reject a bare `Store` content id (`NotDownloadable`).
2. **Discover** — `ProviderLocator::find_providers(content)` returns candidate holders.
3. **Confirm** — `dig.getAvailability` per candidate; keep only confirmed holders. Zero confirmed
   holders after discovery ⇒ `DownloadError::NotFound`, whose `content` MUST say `no providers located
   for …`. A holder set that IS confirmed but cannot seed a layout is a different step and MUST use the
   distinct `MetadataProbeFailed` (§4), so a probe failure is never reported as a discovery miss. The
   confirm step also RETAINS each holder's declared `total_length` / `chunk_count` for §4's adoption
   order rather than reading only `available`.
4. **Establish the commitment** (§4) — unless resumed from persisted state.
5. **Plan** (§5) — partition the resource into chunk-aligned ranges; mark resume-done ranges done.
6. **Schedule** (§6) — fan ranges across holders concurrently, verify (§7) each, retry/rebalance.
7. **Whole-resource backstop** (§8) — bind the reassembled `resource_leaf` to the chain-anchored root.
8. **Finalize** — finalize the sink; clear the resume checkpoint; emit `Completed`.

---

## 4. The resource commitment

The `ResourceCommitment { layout, total_length, root, inclusion_proof }` is the
per-resource metadata every range verifies against. It is established via a meta-probe (fetch a tiny
range, read its first frame) and is immutable for the life of an ATTEMPT.

**It is a PROVISIONAL hypothesis, not trusted metadata (normative framing).** Every gate below except the
root binding compares fields the SAME unproven holder supplied, so a holder willing to lie consistently
passes all of them; the root binding only proves the holder named the right generation. The single check
that can refute an adopted layout is the chain-anchored whole-resource check of section 8, and it cannot
run until the resource has been fetched against that layout. An implementation MUST NOT treat adoption as
verification, and MUST NOT infer from a later refutation which holder was at fault — see the terminal-refutation
requirement below for why that inference is not available.

- **Declared-size ceiling (MUST — before anything is believed)** — a declared `total_length` above
  `max_resource_size` (default `DEFAULT_MAX_RESOURCE_SIZE`, 512 MiB) is REFUSED before the layout is
  built. The declared length sizes the plan and the range assembler's buffer, and it arrives from a peer
  that has proven nothing: `plan_ranges` always takes at least one WHOLE chunk regardless of the window,
  so `chunk_lens: [2^40]` becomes a single 1 TiB range and the assembler then buffers against it. An
  unbounded declared length is therefore a one-frame memory-exhaustion primitive. Like the module bound,
  the default is sized to what a modest host can hold; a deployment reading larger resources raises it
  explicitly.
- **From-frame validity** — `chunk_lens` MUST sum to `total_length`; otherwise the peer's frame is
  rejected and the next holder is probed. The sum + cumulative offsets MUST be computed with **CHECKED**
  arithmetic and the declared chunk COUNT bounded (`MAX_RESOURCE_CHUNK_COUNT`, 1 Mi) with a **FALLIBLE**
  reservation, all before the layout is built. Saturating or wrapping arithmetic here is a silent ACCEPT,
  not a panic: `{ total_length: u64::MAX, chunk_lens: [1, u64::MAX] }` SATURATES to exactly `u64::MAX`,
  matches its declared total, and yields a plan over spans no resource can have. A library MUST NOT
  delegate this to `[profile.release] overflow-checks` — only the ROOT package's profile applies to a
  build, so a dependency's is ignored and its validators are unsound in every consumer that omits it.
- **Root binding to the request (MUST)** — before adopting a peer's first-frame metadata, an
  implementation MUST require the peer-reported `root` to equal the content-id's own generation `root`
  (for `Root` / `Resource` granularities; a bare store carries no root). A peer whose reported root
  differs MUST be skipped, NOT adopted, and so MUST a holder that OMITS `root` entirely — a holder that
  will not say which generation it serves cannot be checked against the request at all, and adopting it
  costs a whole wasted fetch before the anchored check rejects it. This binds the plan's ground truth to
  the caller's request
  rather than to whichever peer answers the meta-probe first. If no holder can seed a layout, the failure
  MUST be reported as `MetadataProbeFailed` — naming how many holders were probed and WHY each was
  rejected — and MUST NOT be reported as `NotFound`: holders were found and confirmed, so "content not
  found" names the wrong step.
- **A whole-resource refutation is TERMINAL and attributes to nobody (MUST)** — when the chain-anchored
  check of section 8 rejects an assembly, the download fails. An implementation MUST NOT exclude the holder
  that supplied the layout, MUST NOT record its declared shape, and MUST NOT re-adopt a layout and retry.
  - The reason is an absence of evidence, not a preference. Deciding whether the SHAPE or the BYTES were
    wrong is not possible: per-range verification is length and alignment only, with no per-chunk hash, so
    nothing in this protocol identifies which holder served bad bytes.
  - **Standing in a vote over peer DECLARATIONS for that missing evidence is FORBIDDEN.** `total_length` and
    `chunk_count` in a `dig.getAvailability` answer are OPTIONAL fields: an attacker forges one for the price
    of a keypair and an announce, and an honest holder legitimately omits them — a conforming node populates
    them only at resource granularity, so at capsule granularity the honest population is SILENT. Any rule
    reading them is therefore decided by whoever chooses to declare. Three such rules were implemented and
    each produced a cheaper denial than the one it replaced, together with an egress amplifier (measured at
    up to one whole transfer per retry attempt, pulled from honest holders, triggered by one anonymous record
    — measured as 5 range fetches becoming 15 and 19 on two fixtures) and a terminal error
    naming honest peers as culprits.
  - **Consequence, stated rather than hidden: #1670 is OPEN.** A holder positioned first in the provider
    order can deny a read repeatably by declaring a short but self-consistent layout under the correct root.
    Integrity is never at risk — the anchored check is exactly what catches it, and nothing unverified is
    promoted — so this is availability only. Closing it requires per-chunk attribution, which is a format
    change, not a scheduling change.
- **Adoption ORDER (MUST be discovery's order)** — candidates MUST be probed in the order discovery produced.
  Every confirmed holder MUST remain eligible to seed the layout, and a resource with exactly ONE holder MUST
  be probed once and adopted immediately with no extra round trip. An implementation MUST NOT reorder
  candidates on anything a peer declares, and MUST NOT impose an agreement THRESHOLD — a threshold fails
  precisely when a resource has one honest holder, the normal state of newly published content.
  - The general rule, which the three rejected attributability rules also violated: an ordering may DEMOTE a
    candidate on evidence and MUST NEVER PROMOTE one on a declaration. "Eligible" is satisfied only nominally
    by an order that never reaches a holder within the retry budget; eligible-but-unreachable is a gate in
    effect. Ranking by the most-agreed declared shape, and ranking by declared-shape group SIZE with a key
    tiebreak, are both specifically forbidden — and a holder that declares NOTHING MUST NOT outrank one that
    declares something, since silence is the cheapest claim available.
- **Probe bounding (MUST)** — the metadata probe MUST be bounded by the same per-fetch timeout as an ordinary
  range fetch. It runs BEFORE the scheduler exists and does not poll the control channel, so nothing else can
  interrupt it: an unbounded probe lets a holder that accepts the stream and then trickles frames pin the
  download indefinitely while it holds the staging claim.
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
- **Recoverable vs terminal** — `Transport`, `Verify`, `Timeout`, and `PagedPrologueUnsupported` errors are
  recoverable per range/holder (retry elsewhere). `Sink`, `State`, `NoProviders`, `NotFound`,
  `MetadataProbeFailed`, `NotDownloadable`, `Cancelled`, `TaskEnded` are terminal for the
  download.

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

These checks run on the CLIPPED range (§2.2): the exact-length check is a statement about the assembled
range, NOT a verdict that an over-long holder answer was a violation. A conversion of any wire-derived
index or length MUST be checked (`usize::try_from`), never a truncating `as` cast — on a 32-bit target a
truncated absurd chunk index maps onto a VALID one, turning a rejection into a check against the wrong
chunk.

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
- **A RESUME MUST NOT skip the backstop (MUST).** A resumed download ends in the SAME chain-binding check
  as a fresh one. The ranges a prior process completed live only in the staging area, so before scheduling
  they are READ BACK from the sink, re-checked against the commitment exactly like freshly-fetched ranges,
  and fed into the whole-resource hash. A range that cannot be read back (a sink with no read-back
  support), reads short, or fails its per-range check is returned to `Pending` and RE-FETCHED. Either way
  the hash sees every byte of the resource, so there is no path on which a resumed download is
  structurally verified ONLY — that would be a fail-OPEN window in the read guarantee, since nothing
  would bind the assembled bytes to the chain-anchored root.
- **A failed backstop MUST discard the checkpoint and the staged bytes.** Fail-closed MUST NOT mean
  permanently DENIED: bytes that did not bind to the root are dropped along with their checkpoint so a
  later attempt re-fetches from scratch instead of re-reading the same poisoned prefix forever. The
  discard is best-effort; the `Verify` failure is what the caller sees.

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
  would overflow the expected length is a transport error. That length is itself bounded by the commitment
  ceiling (section 4), and the assembly buffer MUST grow through a **fallible** reservation, surfacing
  exhaustion as a recoverable `Transport` error. An infallible `resize` / `vec![0; n]` aborts the process
  through the uncatchable `handle_alloc_error`, which no peer may be able to trigger.
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
- **Explicit shortening** — because writing never shortens a staging area, a sink exposes `truncate(len)`,
  which reduces it to `len` bytes and never extends it. The trait default is **fail-closed** (an error): a
  sink with no staging area to shorten MUST opt in explicitly (`Ok(())`, asserting it commits whole).
  Overriding `truncate` ALONE does not make a sink promotable — see the next bullet.
- **Observable staged length (MUST)** — a sink declares whether it can read its own staged bytes back
  (`supports_read_back`), and a sink that cannot is **REFUSED promotion**. "Read-back unsupported" and
  "nothing is staged there" both surface as an `Err` from `read_at`, and conflating them is what let an
  unproven artifact be promoted: a sink overriding `truncate` to `Ok(())` while leaving `read_at` on its
  default shortens nothing, and its probe error then reads as "clean".
- **Proven promotion (MUST — the length is proven from BOTH sides)** — EVERY download, resource and module
  alike, reaches `finalize` through ONE path, which promotes only after proving the staged length is
  EXACTLY the verified length:
  1. the sink can observe its staged bytes at all (above), else refuse;
  2. the LAST verified byte is readable — else the staging area is SHORTER than what was verified;
  3. no byte AT the verified length is readable — else bytes past the verified end survive.
  Each violation is a fail-closed `Verify(Metadata)` error, never a promotion. A one-sided check (3 alone)
  fails OPEN on the short side with the SAME observable signature as the long side — `Ok(total_length)`
  plus a wrong artifact — and `truncate` cannot save it, since shortening never extends. A short staging
  area is reachable with no attacker at all: GC reaps a `.download.tmp` and its `.state` sidecar while the
  `StateStore` keeps its checkpoint elsewhere, so a checkpoint can outlive the bytes it describes.
- **The completeness guarantee does not depend on `verify_whole_resource` (MUST)** — with the
  whole-resource backstop disabled, the promotion length proof is the ONLY thing keeping an incomplete
  artifact off the final path, and it therefore still runs. Disabling the backstop drops CHAIN-ANCHORING,
  never completeness.
- **Staged bytes are NEVER trusted as content (MUST)** — a resumed range is only inherited if it can be
  bound to the commitment; when nothing can bind it (the whole-resource check is disabled, so only the
  structural per-range checks exist and right-length wrong bytes pass them) the range is RE-FETCHED. A
  checkpoint routinely outlives the bytes it describes, so inheriting them on the strength of the
  checkpoint alone promoted arbitrary bytes as a verified success. Disabling the whole-resource check
  therefore also costs the cross-process resume optimization, deliberately.
- **A promotion refusal MUST be recoverable** — a refused promotion discards the checkpoint that led to
  it together with the bytes it describes, on BOTH the resource and module paths, exactly as a failed
  whole-resource check does. Otherwise a checkpoint that outlived its staging bytes makes every later
  fetch of that content fail identically, forever: fail-closed MUST NOT mean permanently DENIED.
- **One download per staging area (MUST)** — a download CLAIMS its staging path exclusively, MUST refuse
  to start if a live download already holds it, and MUST release the claim on EVERY exit including an
  unwinding panic (an RAII guard — a leaked claim would make that path both permanently GC-exempt and
  permanently un-downloadable, i.e. the same denial the claim exists to prevent). Two downloads sharing a
  staging area write over each other by absolute offset, share one resume checkpoint, and can `truncate`
  each other's bytes away; per-range verification is structural, so a sibling's right-length bytes are
  indistinguishable from this download's own.
  - **Enforcement scope (honest limits).** The registry backing the claim is per-`Downloader`, so two
    `Downloader`s in one process — or two node processes over one download directory — share no claim and
    the MUST above is not mechanically enforced across them (there is no lock file). The promotion length
    proof is what keeps the guarantee: a corrupted or truncated shared staging area is REFUSED rather than
    promoted, so the outcome degrades to a failed download, never a wrong artifact. A caller running more
    than one `Downloader` against one directory MUST provide the exclusion itself.
  - The whole-module puller (`ModuleDownloader`) holds NO registry, so it gets neither GC protection nor
    this exclusivity; its promotion is protected by the same length proof.
- **A checkpoint for another plan MUST NOT be inherited** — `done_ranges` are range INDICES, so a
  checkpoint whose `chunk_lens` differ from the planned layout is discarded together with the bytes it
  staged, rather than marking arbitrary byte spans verified.
- **Resume** — per-range progress is checkpointed to a `StateStore`. A paused or crashed download
  resumes into the same staging file and re-fetches ONLY the still-missing ranges; a verified range is
  never re-fetched, but it IS re-checked from staging before the §8 backstop.
- **GC** — a stale `.download.tmp` is reaped by the GC sweep; a live or paused-resumable staging file
  (registered in `ActiveDownloads`) MUST NOT be reaped.

---

## 11. Progress and control

`Planned` is emitted exactly ONCE per download: the resource layout is established once and never re-adopted,
so `ranges_total` and `total_length` are fixed for the life of the download and byte progress is monotonic.

A download exposes a live `DownloadEvent` stream (`Planned`, `RangeCompleted`, `RangeFailed`,
`ProvidersRefreshed`, `Paused`, `Resumed`, `Completed`, `Failed`) and `pause()` / `resume()` /
`cancel()` / `join()`. `pause` issues no new fetches (in-flight fetches finish, progress is
checkpointed); `cancel` ends the download with `Cancelled`.

---

## 12. Error catalogue (stable)

`DownloadError`: `Transport { provider, reason }`, `Timeout { provider }`, `Verify(VerifyError)`,
`NoProviders { needed }`, `NotFound { content }`, `MetadataProbeFailed { content, holders, reasons }`,
`PagedPrologueUnsupported { provider, chunk_count, delivered }`,
`Cancelled`, `State(reason)`, `Sink(reason)`,
`NotDownloadable`, `TaskEnded`. `Transport`, `Timeout`, `Verify`, and `PagedPrologueUnsupported` are recoverable
per range/holder; the rest are terminal. An error raised by the pure reassembly core carries an empty
`provider` for the transport to ATTRIBUTE; the transport MUST fill it in rather than WRAP the error in a
fresh `Transport`, since wrapping flattens the typed variants and makes the recoverability distinction above
unobservable.

The three named failures exist because a single generic "every holder failed" result cannot be acted on.
`NotFound` MUST mean discovery found no holder. `MetadataProbeFailed` MUST mean holders WERE confirmed and
none could seed a layout, and MUST carry the per-holder reason. A refutation by the chain anchor MUST surface
as `Verify(VerifyError::Root)` (or `Length`), never re-described as a discovery or compatibility failure. An
implementation MUST NOT collapse these into one error.

`PagedPrologueUnsupported` names a READER limitation and MUST NOT be phrased as a holder fault. A holder
paging its prologue is conforming, and the 1-byte metadata probe legitimately receives only the first page,
so a conforming pager and a holder that would never have paged are indistinguishable from the adoption
path — attributing it would blame a peer that did nothing wrong.

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

---

## 17. Whole-`.dig`-module pull (`module`, the reshare leg)

`ModuleDownloader` pulls the ENTIRE `.dig` module blob for one `(store_id, root)` generation from
PEERS, so a node that read one resource can become a complete resharer of the capsule. It delivers
**whole-module semantics over the ranged transport** — the same multi-source, resumable, per-source
attributable machinery as §§5–10, addressed at the module blob rather than a resource within it.

### 17.1 Injection seams (MUST)

- **`ModuleTransport`** — the two peer calls, and the ONLY network the engine performs:
  - `get_module_info(provider_peer_id, store_id, root) -> ModuleInfo` (`dig.getModuleInfo`).
  - `fetch_module_range(provider_peer_id, store_id, root, offset, length) -> Vec<u8>`
    (`dig.fetchModuleRange`).
- **`ModuleAnchorVerifier`** — `verify_module_anchor(module, store_id, root) -> bool`, binding an
  assembled blob to its on-chain generation root. There is **NO fail-open production default**, and none is
  reachable: the no-op `AcceptAnyModuleAnchor` is compiled ONLY under `cfg(test)` or the explicit `testkit`
  feature, so a default consumer build cannot name it. A production caller MUST inject a real
  chain-anchored verifier (it is a required positional argument of `ModuleDownloader::new`).

`ModuleInfo` (`total_size`, `module_hash`, `chunk_hashes`, `chunk_lens`) is the **dig-rpc-protocol**
wire type, re-exported unchanged — this crate MUST NOT declare a second copy of the descriptor.

### 17.2 Normative order

1. **Locate** holders via `ProviderLocator::find_providers` on the capsule `ContentId`
   (`ContentId::root(store_id, root)`). An empty holder set is `NotFound`.
2. **Describe** — `get_module_info` against each holder until one answers; the descriptor is validated
   into a chunk plan (§17.3).
3. **Load** the resume checkpoint under the module-scoped key `module:<store_id>:<root>`, which MUST NOT
   collide with the resource `download_key` keyspace. A checkpoint whose `chunk_lens` differ from the
   current descriptor is discarded whole, never partially reused.
4. **Rehydrate** each checkpointed chunk from staging, re-attributing it (§17.5).
5. **Fetch** every still-missing chunk in ascending order, round-robin across holders from a per-chunk
   starting offset, attributing each on arrival (§17.4). Each accepted chunk is written to the sink and
   checkpointed before the next is requested.
6. **Gate, then finalize** (§17.6).

### 17.3 Descriptor validation (MUST — before allocation)

Descriptor validation is **TOTAL**: for EVERY `ModuleInfo` a hostile holder can send, validation MUST
terminate in either a chunk plan or a `Verify(Metadata)` rejection. It MUST NOT panic, abort, or wrap.

A `ModuleInfo` is rejected with `Verify(Metadata)` unless ALL hold, checked in this order:

- `total_size <= max_module_size` (`DEFAULT_MAX_MODULE_SIZE` = **512 MiB**). The descriptor is UNTRUSTED and
  `total_size` sizes the assembly buffer, so this bound MUST be checked **before any allocation** — an
  unbounded declared size is a one-message memory-exhaustion attack. The default is deliberately sized to
  what a modest host can hold: a ceiling above real host memory bounds nothing. A deployment that reshares
  larger capsules raises `max_module_size` explicitly.
- `chunk_lens` is non-empty (without it no byte→chunk mapping, hence no per-chunk check, exists).
- `chunk_lens.len() <= MAX_MODULE_CHUNK_COUNT` (1 Mi). The declared COUNT sizes the plan's own vectors, so an
  absurd count is the same one-message allocation attack as an absurd `total_size`; it MUST be bounded
  before the lengths are copied.
- `chunk_lens.len() == chunk_hashes.len()`.
- `chunk_lens` sums exactly to `total_size`, computed with **CHECKED** arithmetic; a sum that would overflow
  `u64` is a rejection. Unchecked, `{ total_size: 0, chunk_lens: [1, u64::MAX] }` WRAPS to a sum of 0,
  matches its declared total, and passes every other check — then either aborts the process inside the
  summation (where overflow checks are on) or yields spans that index past the assembled blob.
- Cumulative chunk offsets are likewise accumulated with **CHECKED** arithmetic.

**Allocation is FALLIBLE (MUST).** Every allocation sized by the descriptor — the assembly buffer, the chunk
plan, a staging read-back buffer — MUST use a fallible reservation and surface exhaustion as a
`Verify(Metadata)` / `Sink` error. An infallible `vec![0; n]` aborts the process (`handle_alloc_error`),
which an untrusted descriptor MUST never be able to cause. A declared size or span that does not fit the
platform's `usize` is likewise a rejection, never a truncating conversion.

### 17.4 Per-chunk attribution (MUST — fail-closed)

A returned range is accepted only if, after clipping, it fills the requested window AND its SHA-256
equals `chunk_hashes[index]`. Otherwise it is discarded and the next holder tried.

- **Clip, do not reject (MUST)** — a frame that OVERSHOOTS the requested window is truncated to the
  window and then attributed. A holder MUST NOT overshoot (§2.2), but a client cannot know a holder is
  compliant, so clipping is the defensive bound; treating an over-long answer as a violation would make
  every chunk-granular holder unusable. A range that is SHORT after clipping is a failure for that holder.
- **Surface every reason (MUST)** — each holder's rejection reason (`transport: …`, `timed out after …`,
  `short range: …`, `chunk hash mismatch`) is recorded and traced as it happens, and the terminal error
  names the failing STEP (`getModuleInfo` / `fetchModuleRange`), the chunk, its byte window, and every
  per-holder reason. A swallowed reason resurfacing as an unrelated message is a defect, not a nicety.
- **Sentinel untrusted identifiers (MUST)** — a `provider_peer_id` and the descriptor's hashes are
  free-form peer-supplied strings. Any such value reaching a log or an error message is rendered as
  lowercase 64-hex only when it IS canonical 64-hex, else as `<non-canonical-{label}>`. A log an attacker
  can write is not evidence. The rendering lives in `DownloadError`'s own `Display`, so a raw identifier is
  **unrepresentable** in an error string however the error was constructed — sanitizing only at the
  reporting call site is insufficient, because a wrapped `Transport` error carries the raw id back out.
- **Escape untrusted TEXT (MUST)** — a foreign error's message may carry peer-supplied content (a remote
  reason, a returned status line, a peer-reported first-frame `root` quoted by a `VerifyError`). Control
  characters AND Unicode bidirectional-formatting characters in it are ESCAPED and its length is bounded
  before it reaches an error or a log, so one holder reason is always exactly ONE line, reads in the order
  it is written, and cannot forge a log line. This applies to EVERY variant that carries foreign text,
  including a WRAPPED `VerifyError`, and it is applied in `Display`. `Debug` MUST delegate to that same
  `Display` rather than printing raw fields: `Debug` is emitted by `tracing`'s `?field` and by every
  `unwrap`/`expect` panic, so a derived one would be an unsanitized second door.
- **Relocate once** — when every known holder has failed one chunk, `find_providers` is re-queried and
  newly-discovered holders appended before the pull gives up on that chunk.

### 17.5 Resume (MUST NOT trust staging)

A checkpointed chunk is read back from the sink and **re-attributed against `chunk_hashes` exactly like a
freshly-fetched one**. The staging file survives crashes, other processes, and bit-rot, so it is not a
trusted input. A chunk that cannot be read back, reads short, or fails its hash is left NOT done, is
re-fetched, and the checkpoint is corrected to match. Resume is an OPTIMIZATION and MUST NEVER be a
correctness dependency, and MUST NEVER skip the §17.6 gates.

### 17.5a Descriptor-source demotion (MUST)

The descriptor defines the WHOLE plan, and holder order is deterministic, so a holder that answers
`get_module_info` first with a **well-formed but WRONG** descriptor MUST NOT be able to deny a capsule's
reshare: the bytes verify per chunk, the pull assembles, and only the final gates (§17.6) reject it.

- A pull whose assembled blob fails EITHER final gate, or whose descriptor is unusable, MUST **demote that
  descriptor's source** and re-handshake `get_module_info` with a holder that has not been demoted,
  discarding the checkpoint the rejected plan produced.
- Demotion is bounded by `MAX_DESCRIPTOR_ATTEMPTS` (3) and by the supply of un-demoted holders; when it is
  exhausted the pull fails with the **descriptor** failure (a gate `Verify`), never a `NotFound` — blaming
  discovery for a descriptor lie is the ambiguity §17.4's reason-surfacing rule exists to prevent.
- **Chunk exhaustion is attributed to the DESCRIPTOR (MUST).** Exhaustion is ambiguous: unavailable bytes
  and an unsatisfiable descriptor are indistinguishable from inside one attempt. So exhaustion always
  demotes the descriptor's source and re-handshakes, bounded by `MAX_DESCRIPTOR_ATTEMPTS` and the supply of
  un-demoted holders — the budget alone guarantees termination.
  - Whether any chunk had verified MUST NOT gate the retry. A bound that flips on the FIRST verified chunk
    is bypassable for ONE BYTE: a descriptor declaring `chunk_lens = [1, rest]` serves that single byte
    (matching its own fabricated first hash), then refuses everything, so no demotion happens and one liar
    denies the capsule's reshare with honest holders present.
  - The distinction remains as DIAGNOSIS in the error text — exhaustion after real progress is more likely
    genuine unavailability, exhaustion with none more likely a fabricated descriptor — never as control flow.
  - A non-recoverable LOCAL failure (a sink/state fault) stays terminal: that is this node failing, not a
    holder lying.
- **A LOCAL failure is never evidence against a holder (MUST) — and blame is a SEPARATE question from
  what happens next.** A failed allocation (the assembly buffer, the chunk plan), a sink or state-store
  fault, and an anchor check that could not COMPLETE are outcomes of this node, not claims about a peer,
  so none of them may record anything durable. What each does NEXT is decided independently:
  - a sink/state fault or an incomplete anchor check is TERMINAL — the local facility the pull depends on
    is broken, and another descriptor would meet the same wall;
  - a failed ALLOCATION is `UnsatisfiableDescriptor`: it demotes the descriptor's source for the current
    call and tries the next holder's descriptor, bounded by `MAX_DESCRIPTOR_ATTEMPTS`. The declared size
    is the attacker's choice, so making it terminal hands out a one-message reshare denial — a ~100-byte
    self-consistent descriptor with an inflated `total_size` (and matching final `chunk_len`) passes the
    ceiling, fails the reservation, and would kill every pull of that capsule on this node. Remotely
    inducible pressure is an argument for routing AROUND a descriptor, never for surrendering the pull.
  Allocation also must not brand: an honest descriptor for a large capsule under memory pressure would
  otherwise convict an honest holder, and that pressure is itself remotely inducible, since every
  concurrent pull reserves up to `max_module_size` for an attacker-declared size.
- **Only a PROVEN-FALSE descriptor earns a DURABLE verdict (MUST).** A final-gate rejection proves the
  descriptor was false and is attributable to its source. Chunk exhaustion does not: the bytes may be
  genuinely unavailable, and the holders refusing them need not be the holder that supplied the
  descriptor. Exhaustion therefore demotes for the CURRENT call only. Persisting it would be remotely
  INDUCIBLE — DHT provider announcement is unauthenticated, so sybil holders that refuse their assigned
  chunks would get an HONEST descriptor source blacklisted on the victim for the whole TTL, per capsule,
  repeatably, until only attacker-supplied descriptors were ever asked for.
- **A bad-descriptor verdict SHOULD be persisted (holder reputation).** In-call demotion alone re-asks the
  same liars on the next call or after a restart, each paying up to `MAX_DESCRIPTOR_ATTEMPTS` full attempts.
  A verdict is recorded per `(target, peer_id)` through the `StateStore` and consulted when ordering /
  filtering descriptor sources. It is bounded and advisory:
  - verdicts DECAY (`BAD_DESCRIPTOR_TTL`, 24 h) — a verdict is evidence about a moment, not a label;
  - the record is capped (`MAX_BAD_DESCRIPTOR_PEERS`, oldest evicted first), so reputation is never itself
    a growth vector, and only a canonical 64-hex `peer_id` is ever stored (no peer-supplied text as a key);
  - a demoted holder stays fully usable for CHUNK fetches (chunk bytes are independently hash-attributed,
    so excluding it would cost availability for no integrity gain);
  - reputation MUST NOT become a denial primitive: the moment honouring the remembered verdicts would
    leave NO holder to ask for a descriptor, the memory is dropped for the rest of that call and every
    located holder becomes askable again. The trigger is "no usable holder remains", NOT "all holders are
    remembered" — with verdicts on the honest holders and none on a liar, the latter excludes the honest
    holders, demotes the liar, and then denies a pull the network can serve. Holders demoted in the
    CURRENT call are never forgiven by this escape;
  - reputation OUTLIVES the checkpoint — completing a download clears the checkpoint, never the verdicts;
  - the attempt budget counts attempts made in THIS call, not the size of the demoted set, so a remembered
    verdict costs the call nothing.

### 17.5b Promotion (MUST — the promoted artifact IS the verified artifact)

The gates in §17.6 verify the assembled blob; `Sink::finalize` promotes the STAGING AREA. Those are the
same artifact only if nothing longer was ever staged, and a staging area is written by offset and **never
shortened by writing**. So:

- **The promoted artifact MUST be byte-identical to the verified one.** Before finalize the staging area
  MUST be reduced to the verified length (`Sink::truncate`), and a staged length ≠ the verified length is a
  **fail-closed `Verify(Metadata)` error, never a promotion**. `Sink::truncate` only ever shrinks; it never
  zero-extends.
- **An abandoned plan's bytes MUST be discarded with its checkpoint.** On descriptor demotion (§17.5a) the
  sink is RESET alongside the checkpoint, and a pull whose checkpoint does not resume the current plan
  (absent, or a different shape) resets the sink before staging. Otherwise a longer earlier attempt —
  a demoted holder's fabrication, or a leftover file from another shape — survives as a tail on a later,
  shorter promotion.
- Violating this is a cache-poisoning primitive, not a cosmetic length bug: the promoted `.dig` would hash
  to something other than `module_hash` while the pull reports success, so the reshare leg would announce
  the node as a holder of content every downstream peer rejects.

### 17.6 Final gates (MUST — fail-closed, both, every time)

Before `Sink::finalize`, on EVERY pull including a resumed one:

1. The reassembled blob's SHA-256 equals the descriptor's `module_hash`.
2. `ModuleAnchorVerifier::verify_module_anchor(blob, store_id, root)` reports `Anchored`.

The anchor answer is THREE-valued (`Anchored` / `NotAnchored` / `Unavailable`), and an implementation that
consults the chain MUST report `Unavailable` when it could not reach an answer:

- `NotAnchored` is EVIDENCE against the holder that supplied the descriptor: fail-closed, and durable
  demotion (section 17.5a).
- `Unavailable` is THIS node's own failure: fail-closed and TERMINAL, attributing nothing to any holder. A
  two-valued answer forced an outage to be reported as "not anchored", which branded every honest holder
  tried and then INVERTED descriptor preference toward unremembered (i.e. sybil) peers for the whole
  reputation TTL.

Both gates run on the single path to `finalize`, and finalize is reached only through the §17.5b promotion
check. If either gate fails, the pull returns `Verify(Metadata)`, the sink is **NOT finalized** (the staging file is
never promoted, so nothing is served or announced), and the checkpoint is left in place. There is no path
by which a module is finalized without both gates passing — an unanchored module is a clean miss, never a
serve. This is what makes reshare safe: only chain-anchored bytes can ever be re-announced.

### 17.7 Implementation status

This crate ships the ENGINE and the two seams. The production `ModuleTransport` adapter over the peer
client is wired by dig-node once module client methods exist on the shared peer client; the in-memory
`testkit::MockModuleTransport` is the reference double.
