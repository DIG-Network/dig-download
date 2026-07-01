//! # dig-download — the node-side multi-source download orchestrator for the DIG Node peer network
//!
//! `dig-download` answers **"get me this content, fast and verified."** Given a [`ContentId`] (store
//! / root / capsule / resource) it runs the normative L7 multi-source flow: **locate** the holders in
//! the DHT, **confirm** them with `dig.getAvailability`, **fan** different byte ranges across
//! different holders **simultaneously** (`dig.fetchRange` over dig-nat mux streams), **verify** each
//! range independently against the capsule's chain-anchored merkle root, **rebalance** around slow /
//! dropped / bad sources, and **reassemble** the verified bytes in order into the node's store — with
//! **pause + resume** that never re-fetches an already-verified range. It is the node engine that
//! supersedes the retired browser-side `dig-download-utility`.
//!
//! ## The public surface
//!
//! - [`Downloader`] — built once from injected dependencies, then [`download`](Downloader::download)ed
//!   against many content ids. Returns a [`DownloadHandle`] (progress event stream +
//!   [`pause`](DownloadHandle::pause) / [`resume`](DownloadHandle::resume) /
//!   [`cancel`](DownloadHandle::cancel) + [`join`](DownloadHandle::join)).
//! - Trait boundaries (the injection seams — real impls over dig-dht/dig-nat, or the in-memory
//!   [`testkit`]):
//!   - [`ProviderLocator`] — "which peers hold this?" ([`DhtProviderLocator`] over dig-dht).
//!   - [`RangeTransport`] — fetch a range / availability from a peer ([`NatRangeTransport`] over
//!     dig-nat).
//!   - [`Sink`] — where verified bytes land ([`FileSink`] stages to `<target>.download.tmp` and
//!     atomically finalizes; dig-node supplies a store-backed sink).
//!   - [`StateStore`] — persist per-range resume progress ([`InMemoryStateStore`] /
//!     [`FileStateStore`]).
//!   - [`Verifier`] / [`ProofVerifier`] — per-range + chain-anchored integrity ([`MerkleVerifier`];
//!     dig-node injects the digstore proof verifier to bind to the on-chain root).
//! - [`gc`] — reap stale `.download.tmp` staging files, never a live/paused-resumable one
//!   ([`ActiveDownloads`] + [`TmpGc`]; run [`Downloader::gc`] on an interval like dig-dht's provider
//!   `gc()`).
//!
//! ## Integrity model (L7 §9)
//!
//! Two checks, two moments. **Per range, immediately:** the returned bytes cover whole chunk(s) whose
//! lengths match the resource's `chunk_lens`, and the declared generation `root` matches — a
//! truncated / mis-sized / wrong-generation source is caught the instant its range arrives and the
//! range is re-fetched elsewhere. **Whole resource, at completion:** `resource_leaf =
//! SHA-256(concatenated chunk ciphertexts)` is the leaf committed under the chain-anchored `root`
//! (via an injected [`ProofVerifier`]). Whichever mix of peers served the ranges, they all verify
//! against the same on-chain root.
//!
//! ## Implementers' note — wiring dig-download into dig-node
//!
//! dig-node owns the runtime context the trait boundaries abstract, and constructs a [`Downloader`]
//! from it:
//!
//! 1. **Locator** — build a [`dig_dht::DhtService`] (its dig-nat transport + bootstrap peers from the
//!    relay introducer / gossip pool), wrap it in [`DhtProviderLocator::new`], `Arc` it.
//! 2. **Transport** — build a [`NatRangeTransport::new`] from the node's
//!    [`dig_nat::LocalIdentity`] + [`dig_nat::NatConfig`] + `network_id`; it dials providers over the
//!    NAT-traversal ladder and runs `dig.getAvailability` / `dig.fetchRange`.
//! 3. **Verifier** — [`MerkleVerifier::with_proof_verifier`] with the **digstore merkle-proof
//!    verifier** (the store crate owns the proof byte format) so the whole-resource check binds to the
//!    chain-anchored root. (Without it, [`MerkleVerifier::new`] enforces per-range + structural
//!    integrity only.)
//! 4. **Sink** — per download, a [`FileSink::new(final_path)`](FileSink) (stages to
//!    `<final_path>.download.tmp`, atomically renames on finalize), OR a digstore-backed [`Sink`] that
//!    writes the capsule/resource ciphertext into the store and finalizes on install.
//! 5. **State store** — a [`FileStateStore`] under the download/cache dir (survives restarts).
//! 6. **Construct + drive** — `Downloader::new(locator, transport, verifier, state_store, config)`,
//!    then `let handle = downloader.download(content_id, sink, opts);` and drive it:
//!    `handle.next_event()` for progress, `handle.pause()/resume()/cancel()`, `handle.join().await`
//!    for the result. On startup and on an interval, call `downloader.gc(download_dir, ttl)` to reap
//!    abandoned staging files (`downloader.active_downloads()` protects live/paused ones).
//!
//! A content-want handler thus becomes: derive the [`ContentId`], pick a sink, `download(...)`, and
//! surface progress — the crate does discovery, multi-source fan-out, verification, retry, and
//! resume.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod gc;
pub mod locate;
pub mod orchestrator;
pub mod plan;
pub mod progress;
pub mod sink;
pub mod source;
pub mod testkit;
pub mod verify;

// Re-export the content id from dig-dht so consumers use ONE `ContentId` type across locate +
// download (no divergent shape).
pub use dig_dht::{ContentId, ProviderRecord};

pub use error::{DownloadError, VerifyError};
pub use gc::{ActiveDownloads, GcConfig, TmpGc};
pub use locate::{DhtProviderLocator, ProviderLocator};
pub use orchestrator::{download_key, DownloadConfig, DownloadHandle, DownloadOptions, Downloader};
pub use plan::{plan_ranges, ChunkLayout, Range, RangeState};
pub use progress::{
    DownloadEvent, DownloadProgress, DownloadState, FileStateStore, InMemoryStateStore, StateStore,
};
pub use sink::{staging_path_for, FileSink, InMemorySink, Sink, STATE_SUFFIX, TMP_SUFFIX};
pub use source::{
    assemble_range_stream, FetchedRange, NatRangeTransport, RangeMeta, RangeTransport,
    SourceHealth, SourceTracker,
};
pub use verify::{
    MerkleVerifier, ProofVerifier, ResourceCommitment, TrustingProofVerifier, Verifier,
};
