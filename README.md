# dig-download

The node-side **multi-source download orchestrator** for the DIG Node peer network. It answers *"get
me this content, fast and verified"*: given a `ContentId` (store / root / capsule / resource) it uses
[`dig-dht`](https://github.com/DIG-Network/dig-dht) to locate the peers holding the content, then
streams it into the node from **multiple peers simultaneously** — byte-range fan-out over the L7 peer
RPC (`dig.fetchRange` on [`dig-nat`](https://github.com/DIG-Network/dig-nat)) — with per-range integrity
verification, interruption tolerance, and pause + resume. It is the Rust node engine that supersedes the
retired browser-side `dig-download-utility`.

## The multi-source flow (L7 §9)

1. **Discover** — `find_providers(content_id)` locates the holders in the DHT.
2. **Availability** — `dig.getAvailability` confirms which holders actually have it; a meta-probe reads
   the whole-resource `chunk_lens` to establish the resource commitment.
3. **Plan** — the resource is partitioned into chunk-aligned byte ranges.
4. **Fan out** — different ranges are fetched from different holders **concurrently** over dig-nat mux
   streams, N in flight per source, topped up as sources finish.
5. **Verify** — each range is verified independently as it arrives (exact expected length + chunk
   alignment + the declared generation `root`); a truncated, mis-sized, boundary-aligned-short, or
   wrong-generation range is discarded and its source penalized.
6. **Retry / rebalance** — a failed, dropped, or unverifiable range is re-queued to another holder
   (bounded backoff); when a still-needed range runs out of live holders, `find_providers` re-runs.
7. **Reassemble** — verified ranges are written to the sink by offset; once whole, the reassembled
   resource's `resource_leaf = SHA-256(concatenated chunk ciphertexts)` is verified against the
   chain-anchored generation root, then the sink is finalized.

## Public API

- **`Downloader`** — built once from injected dependencies, then `download(content, sink, opts)`ed,
  returning a **`DownloadHandle`** with a live progress event stream plus `pause()` / `resume()` /
  `cancel()` / `join()`.
- **Trait boundaries** (the injection seams — real impls over dig-dht/dig-nat, or the in-memory
  `testkit`):
  - `ProviderLocator` — "which peers hold this?" (`DhtProviderLocator` over dig-dht).
  - `RangeTransport` — fetch a range / availability from a peer (`NatRangeTransport` over dig-nat).
  - `Sink` — where verified bytes land (`FileSink` stages to `<target>.download.tmp` and atomically
    renames on finalize; a node supplies a store-backed sink).
  - `StateStore` — persist per-range resume progress (`InMemoryStateStore` / `FileStateStore`).
  - `Verifier` / `ProofVerifier` — per-range + chain-anchored integrity (`MerkleVerifier`; a node
    injects the digstore merkle-proof verifier to bind to the on-chain root).
- **`gc`** — reap stale `.download.tmp` staging files, never a live/paused-resumable one
  (`ActiveDownloads` + `TmpGc`; run `Downloader::gc(dir, ttl)` on an interval).

## Staging + resume + GC

A file-backed download streams into `<target>.download.tmp` and only **atomically renames** it onto the
final path once the whole resource is verified — so a reader never sees a partial file and a crash never
corrupts the real one. Per-range progress is checkpointed to the `StateStore`, so a **paused** or
**crashed** download resumes into the same staging file and re-fetches only the still-missing ranges.
Abandoned staging files are garbage-collected once stale; a live or paused-resumable one is protected.

## Testing

The whole orchestrator is tested over an **in-memory harness** (`testkit`): mock DHT providers + mock
range sources (honest / corrupt / truncating / dropping / unavailable) + an in-memory or temp-dir sink
+ an in-memory or file state store — **no real network or mainnet**. `cargo test` runs the unit +
scenario suites; `cargo llvm-cov --all --fail-under-lines 80` is CI-gated.

## License

Apache-2.0 OR MIT.
