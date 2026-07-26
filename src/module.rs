//! [`ModuleDownloader`] — the whole-`.dig`-module peer pull (the reshare leg, #1576).
//!
//! Where the resource [`Downloader`](crate::Downloader) fetches ONE resource within a capsule, the
//! `ModuleDownloader` pulls the ENTIRE `.dig` module blob for a `(store_id, root)` generation — the
//! complete, content-addressed, on-chain-anchored container — so a node that read one resource from a
//! peer can become a COMPLETE resharer of the whole capsule (it re-serves every retrieval key,
//! including private/encrypted resources, with valid proofs). This is the "whole-module semantics"
//! decision on #1576; it is delivered over the EXISTING ranged-fetch transport (multi-source,
//! resumable, per-source attributable) rather than a bespoke one-shot stream.
//!
//! ## The flow (decider plan #1576)
//!
//! 1. **Locate** the module's holders via the injected [`ProviderLocator`] (`find_providers` on the
//!    capsule [`ContentId`]).
//! 2. **Handshake** `dig.getModuleInfo` against a holder ([`ModuleTransport::get_module_info`]) →
//!    [`ModuleInfo`] (`total_size`, `module_hash`, per-chunk `chunk_hashes` + `chunk_lens`). This is
//!    the transfer descriptor: it defines the chunk plan AND the per-chunk + whole-blob checks.
//! 3. **Spread** the chunks across the located holders ([`ModuleTransport::fetch_module_range`],
//!    `dig.fetchModuleRange`), each chunk one range, round-robin from a per-chunk starting holder so a
//!    multi-holder set is genuinely pulled from multiple sources. Chunks are pulled in ascending order
//!    (one in flight); parallel in-flight chunks are a later optimization, not a contract.
//! 4. **Attribute** each returned range against `chunk_hashes[i]` the instant it arrives — a tampered
//!    or short range is REJECTED, its reason recorded against the serving holder, and the chunk
//!    re-fetched from the next holder (per-source attribution, fail-closed before assembly). A frame
//!    that OVERSHOOTS the requested window is clipped, not rejected: answering at chunk granularity is
//!    legitimate (the §2.2 clip contract, #836).
//! 5. **Resume** across pause / crash via the injected [`StateStore`]: a checkpointed chunk is read
//!    back from staging and RE-ATTRIBUTED against `chunk_hashes` rather than trusted, so it is skipped
//!    when still intact and re-fetched when the staging file has been corrupted since (#1605). A
//!    resumed pull always ends in the same two final gates below — resume can never bypass them.
//! 6. **Assemble** verified chunks in order into the [`Sink`]'s staging area, then run the two
//!    fail-closed final gates BEFORE finalize — (a) the reassembled blob hashes to `module_hash`
//!    (whole-blob integrity), and (b) the reassembled blob verifies against its chain-anchored `root`
//!    via the injected [`ModuleAnchorVerifier`] (NC-9 — verified-content-is-not-safe-until-chain-bound;
//!    a right-shaped-but-forged module a lying holder-set could otherwise agree on is caught here).
//!    Only if BOTH pass is the sink finalized + the resume checkpoint cleared. A failure leaves the
//!    staging file unfinalized (never written through) and is terminal for the pull.
//!
//! ## Trust model
//!
//! The [`ModuleInfo`] is obtained from ONE holder and used to plan + attribute ranges. It is NOT
//! trusted for safety: the per-chunk `chunk_hashes` only give cheap early rejection + attribution,
//! and a holder-set that consistently lies about BOTH the descriptor and the bytes still fails the
//! whole-blob `module_hash` check (if it disagrees with the served bytes) or — decisively — the
//! chain-anchor gate, which binds the assembled `.dig` to the on-chain `(store_id, root)`. The
//! chain-anchor gate is the sole root of trust; everything before it is optimization.
//!
//! ## Injection seams
//!
//! Like the rest of the crate, the network + store-format are INJECTABLE so the engine is tested over
//! an in-memory harness:
//! - [`ModuleTransport`] — the two `dig.getModuleInfo` / `dig.fetchModuleRange` peer calls. The real
//!   dig-nat/dig-peer adapter is wired by dig-node's serve/client legs (the module client methods do
//!   not yet exist on the shared peer client); this crate ships the seam + the in-memory
//!   [`testkit::MockModuleTransport`](crate::testkit) used by the tests.
//! - [`ModuleAnchorVerifier`] — binds the assembled blob to the chain root. dig-node injects the
//!   digstore verifier (which parses the `.dig`, extracts its committed root, and checks it equals the
//!   `getAnchoredRoot` value). There is no fail-open production default: the no-op
//!   `AcceptAnyModuleAnchor` exists ONLY under `cfg(test)` / the `testkit` feature, so a default
//!   consumer build cannot even name it.

use std::sync::Arc;

use async_trait::async_trait;
use dig_dht::ContentId;
use dig_rpc_protocol::types::ModuleInfo;
use sha2::{Digest, Sha256};

use crate::error::{
    hex64_or_sentinel, sanitize_untrusted_text, DownloadError, VerifyError, MAX_ERROR_REASON_CHARS,
};
use crate::locate::ProviderLocator;
use crate::progress::{DownloadState, StateStore};
use crate::sink::Sink;

/// The two peer calls the module pull needs, abstracted for testability (in-memory
/// [`MockModuleTransport`](crate::testkit) in tests; the real dig-nat/dig-peer adapter is wired by
/// dig-node's serve/client legs, #1576 sub-family 4).
#[async_trait]
pub trait ModuleTransport: Send + Sync {
    /// `dig.getModuleInfo` — the transfer descriptor for the `(store_id, root)` module from
    /// `provider_peer_id`. `store_id` / `root` are the 64-hex generation ids.
    ///
    /// # Errors
    /// A recoverable [`DownloadError::Transport`] on connect/stream failure — the caller tries
    /// another holder.
    async fn get_module_info(
        &self,
        provider_peer_id: &str,
        store_id: &str,
        root: &str,
    ) -> Result<ModuleInfo, DownloadError>;

    /// `dig.fetchModuleRange` — the `[offset, offset+length)` window of the module blob from
    /// `provider_peer_id`.
    ///
    /// # Errors
    /// A recoverable [`DownloadError::Transport`]/[`DownloadError::Timeout`] — the caller re-fetches
    /// the chunk from another holder.
    async fn fetch_module_range(
        &self,
        provider_peer_id: &str,
        store_id: &str,
        root: &str,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, DownloadError>;
}

/// Binds a fully-assembled `.dig` module blob to its chain-anchored `(store_id, root)` — the sole
/// root of trust of the module pull (NC-9). dig-node injects the digstore verifier; this crate ships
/// only the explicitly-opt-in, fail-OPEN [`AcceptAnyModuleAnchor`] for tests.
pub trait ModuleAnchorVerifier: Send + Sync {
    /// Return `true` iff `module` is the genuine `.dig` container committed on-chain under
    /// `(store_id, root)` (i.e. its embedded generation root equals the `getAnchoredRoot` value).
    fn verify_module_anchor(&self, module: &[u8], store_id: &str, root: &str) -> bool;
}

/// A **fail-OPEN** [`ModuleAnchorVerifier`] that accepts any blob without checking the chain — for
/// tests ONLY. Provides NO chain-anchored integrity; a production caller MUST inject the real digstore
/// anchor verifier.
///
/// COMPILED OUT of a default consumer build (`cfg(any(test, feature = "testkit"))`): `#[doc(hidden)]`
/// hides a type, it does not gate access, and the reshare path's only root of trust must not be
/// bypassable by a `use`. A consumer that genuinely wants a no-op verifier opts in by enabling the
/// `testkit` feature — a visible, reviewable choice in its `Cargo.toml`.
#[cfg(any(test, feature = "testkit"))]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAnyModuleAnchor;

#[cfg(any(test, feature = "testkit"))]
impl ModuleAnchorVerifier for AcceptAnyModuleAnchor {
    fn verify_module_anchor(&self, _module: &[u8], _store_id: &str, _root: &str) -> bool {
        true
    }
}

/// The default [`ModuleDownloadConfig::max_module_size`] — 512 MiB.
///
/// The puller assembles the module in memory, so this bound is what ONE lying `getModuleInfo` can
/// make a node try to allocate. It is deliberately sized to what a small node can actually hold, not
/// to the largest conceivable capsule: a ceiling above real host memory is not a bound at all (a
/// declared multi-gigabyte module would be an out-of-memory primitive costing the attacker one
/// message). A deployment that genuinely reshares larger capsules raises it explicitly, having sized
/// the host for it.
pub const DEFAULT_MAX_MODULE_SIZE: u64 = 512 * 1024 * 1024;

/// The hard upper bound on the number of chunks a [`ModuleInfo`] may declare.
///
/// The declared chunk COUNT sizes the puller's `offsets` + `done` vectors, so an absurd count is the
/// same one-message allocation attack as an absurd `total_size` — bounded here, before any allocation.
/// 1 Mi chunks covers any real capsule at any sane chunk size.
pub const MAX_MODULE_CHUNK_COUNT: usize = 1024 * 1024;

/// How many DIFFERENT holders' descriptors a single pull will try before giving up.
///
/// The descriptor defines the whole plan, so a holder that answers `getModuleInfo` first with a
/// well-formed but WRONG descriptor would otherwise deny the capsule's reshare permanently (holder
/// order is deterministic, so every retry re-asks the same liar). A descriptor whose blob fails the
/// whole-blob or chain-anchor gate is DEMOTED and the next holder's descriptor tried instead.
pub const MAX_DESCRIPTOR_ATTEMPTS: usize = 3;

/// Tunables for a module pull.
#[derive(Debug, Clone)]
pub struct ModuleDownloadConfig {
    /// Per-range fetch timeout — a holder that does not return a chunk within this window is treated
    /// as a failed source for that chunk and the next holder is tried.
    pub range_timeout: std::time::Duration,

    /// Upper bound on the `total_size` a [`ModuleInfo`] may declare. The descriptor comes from an
    /// UNTRUSTED holder and sizes the puller's assembly buffer, so without this bound a single lying
    /// `getModuleInfo` would make the node allocate arbitrarily much memory. A descriptor above the
    /// bound is refused before any allocation. Defaults to [`DEFAULT_MAX_MODULE_SIZE`].
    pub max_module_size: u64,
}

impl Default for ModuleDownloadConfig {
    fn default() -> Self {
        ModuleDownloadConfig {
            range_timeout: std::time::Duration::from_secs(30),
            max_module_size: DEFAULT_MAX_MODULE_SIZE,
        }
    }
}

/// The multi-source, resumable, fail-closed whole-`.dig`-module puller. Built once from injected
/// dependencies, then [`download`](ModuleDownloader::download)ed against many `(store_id, root)`
/// generations.
pub struct ModuleDownloader {
    locator: Arc<dyn ProviderLocator>,
    transport: Arc<dyn ModuleTransport>,
    anchor: Arc<dyn ModuleAnchorVerifier>,
    state_store: Arc<dyn StateStore>,
    config: ModuleDownloadConfig,
}

impl ModuleDownloader {
    /// Build a downloader from its injected seams.
    pub fn new(
        locator: Arc<dyn ProviderLocator>,
        transport: Arc<dyn ModuleTransport>,
        anchor: Arc<dyn ModuleAnchorVerifier>,
        state_store: Arc<dyn StateStore>,
        config: ModuleDownloadConfig,
    ) -> Self {
        ModuleDownloader {
            locator,
            transport,
            anchor,
            state_store,
            config,
        }
    }

    /// Pull the whole `.dig` module for `(store_id, root)`, writing the verified blob into `sink`.
    ///
    /// Returns the verified module byte length on success. See the module docs for the full flow +
    /// trust model.
    ///
    /// # Errors
    /// - [`DownloadError::NotFound`] — no holders located.
    /// - [`DownloadError::NoProviders`] — holders exhausted with chunks still missing.
    /// - [`DownloadError::Verify`] — the whole-blob `module_hash` or the chain-anchor gate failed
    ///   (fail-closed; the sink is NOT finalized).
    pub async fn download(
        &self,
        store_id: &str,
        root: &str,
        sink: &dyn Sink,
    ) -> Result<u64, DownloadError> {
        let content = module_content_id(store_id, root).ok_or(DownloadError::NotDownloadable)?;

        // 1. LOCATE the holders.
        let mut providers = self.locator.find_providers(&content).await?;
        if providers.is_empty() {
            return Err(DownloadError::NotFound {
                content: module_download_key(store_id, root),
            });
        }

        // 2. Pull against ONE holder's descriptor at a time. A descriptor that is well-formed but
        //    WRONG survives every per-chunk check and only dies at the final gates — so its SOURCE is
        //    demoted and the next holder's descriptor tried, rather than the pull going terminal. One
        //    holder winning the `getModuleInfo` race must not be able to deny a capsule's reshare.
        let mut demoted: Vec<String> = Vec::new();
        loop {
            let (source, info) = self
                .fetch_module_info(&providers, &demoted, store_id, root)
                .await?;
            match self
                .pull_with_descriptor(&info, store_id, root, sink, &mut providers)
                .await
            {
                Ok(len) => return Ok(len),
                Err(PullFailure::Terminal(e)) => return Err(e),
                Err(PullFailure::BadDescriptor(e)) => {
                    tracing::warn!(
                        peer = %hex64_or_sentinel(&source, "peer-id"),
                        error = %e,
                        "module pull: descriptor source failed a final gate; demoting it and \
                         re-handshaking with another holder"
                    );
                    demoted.push(source);
                    // Give up when the attempt budget is spent OR no un-demoted holder is left. The
                    // returned error is the DESCRIPTOR failure, never a "not found": blaming discovery
                    // for a descriptor lie is exactly the ambiguity that cost four #1586 rounds.
                    let usable = providers
                        .iter()
                        .filter(|p| !demoted.contains(&p.provider_peer_id))
                        .count();
                    if demoted.len() >= MAX_DESCRIPTOR_ATTEMPTS || usable == 0 {
                        return Err(e);
                    }
                    // The whole plan came from the demoted holder, so its partial progress is not
                    // resumable against the next descriptor — drop the checkpoint AND the bytes it
                    // staged. A demoted plan may have been LONGER than the next one, and a staging
                    // area is never shortened by writing, so leaving it would let the demoted
                    // holder's tail survive into a later promotion.
                    self.state_store
                        .clear(&module_download_key(store_id, root))
                        .await?;
                    sink.truncate(0).await?;
                }
            }
        }
    }

    /// Run one whole pull — plan, resume, fetch, and the two final gates — against ONE holder's
    /// descriptor. Returns [`PullFailure::BadDescriptor`] exactly when the assembled blob fails a
    /// final gate (the descriptor's source lied and another holder should be asked), and
    /// [`PullFailure::Terminal`] for every other failure.
    async fn pull_with_descriptor(
        &self,
        info: &ModuleInfo,
        store_id: &str,
        root: &str,
        sink: &dyn Sink,
        providers: &mut Vec<dig_dht::ProviderRecord>,
    ) -> Result<u64, PullFailure> {
        let layout = ChunkPlan::from_info(info, self.config.max_module_size)
            .map_err(PullFailure::BadDescriptor)?;

        // Load resume state; a checkpoint for a DIFFERENT generation shape is discarded (never mixed)
        // so a resume re-plans identically to the original.
        let key = module_download_key(store_id, root);
        let Resume {
            mut state,
            resumes_staging,
        } = self.load_or_fresh_state(&key, &layout).await?;
        if !resumes_staging {
            // No checkpoint resumes THIS plan, so anything already in the staging area belongs to a
            // different shape (an earlier abandoned attempt). It is discarded with the checkpoint —
            // otherwise a longer stale tail rides out inside this plan's promotion.
            sink.truncate(0).await?;
        }

        // Assemble into an in-memory blob (the final whole-blob-hash + chain-anchor gate needs the
        // complete bytes). The size is attacker-DECLARED, so the allocation is FALLIBLE: exhaustion
        // must be a `DownloadError`, never the uncatchable abort an infallible `vec![0; n]` produces.
        let mut blob = try_zeroed_blob(layout.total_size).map_err(PullFailure::BadDescriptor)?;
        let mut done: Vec<bool> = vec![false; layout.chunk_count()];
        self.rehydrate_done_chunks(sink, info, &layout, &mut state, &mut blob, &mut done)
            .await;

        // FETCH + ATTRIBUTE every still-missing chunk, fanned round-robin across the holders. A
        // rehydrated chunk verified against THIS descriptor's hashes, so it already makes the
        // descriptor credible for the exhaustion classification below.
        let mut any_chunk_verified = done.iter().any(|d| *d);
        for (index, already_done) in done.iter().enumerate() {
            if *already_done {
                continue;
            }
            let (offset, len) = layout.chunk_span(index);
            let bytes = match self
                .fetch_verified_chunk(providers, info, &layout, index, store_id, root)
                .await
            {
                Ok(bytes) => bytes,
                Err(e) => return Err(classify_chunk_exhaustion(e, any_chunk_verified)),
            };
            any_chunk_verified = true;
            sink.write_at(offset, &bytes).await?;
            blob[offset as usize..(offset + len) as usize].copy_from_slice(&bytes);
            state.mark_done(index);
            self.state_store.save(&state).await?;
        }

        // The two FAIL-CLOSED final gates, BEFORE finalize. Neither pass ⇒ the staging file is never
        // promoted (the module is rejected, not written through — NC-9).
        let assembled_hash = sha256_hex(&blob);
        if assembled_hash != info.module_hash {
            return Err(PullFailure::BadDescriptor(DownloadError::Verify(
                VerifyError::Metadata(format!(
                    "assembled module_hash {assembled_hash} != declared {}",
                    hex64_or_sentinel(&info.module_hash, "module-hash")
                )),
            )));
        }
        if !self.anchor.verify_module_anchor(&blob, store_id, root) {
            return Err(PullFailure::BadDescriptor(DownloadError::Verify(
                VerifyError::Metadata(format!(
                    "assembled module is not chain-anchored under ({store_id}, {root})"
                )),
            )));
        }

        self.promote_verified_module(sink, layout.total_size)
            .await?;
        self.state_store.clear(&key).await?;
        Ok(layout.total_size)
    }

    /// Promote the staging area, having PROVEN it holds exactly the bytes the gates above verified.
    ///
    /// The gates verify the assembled `blob`; finalize promotes the STAGING AREA — and the two are only
    /// the same artifact if nothing longer was ever staged. A staging area is written by offset and
    /// never shortened, so a demoted longer descriptor (or a leftover file from another shape) leaves a
    /// tail the verified blob does not contain. Promoting that would cache a `.dig` whose SHA-256 is
    /// not `module_hash` while reporting success — the node would then re-announce itself as a holder
    /// of content every downstream peer rejects.
    ///
    /// So the staging area is SHORTENED to the verified length and the reduction is then CONFIRMED: a
    /// readable byte at `verified_len` means bytes past the verified end survive, which is fail-closed
    /// (never promoted). A sink that cannot read back reports "unsupported" here exactly as it does
    /// elsewhere, in which case the shortening above is the enforcement.
    async fn promote_verified_module(
        &self,
        sink: &dyn Sink,
        verified_len: u64,
    ) -> Result<(), DownloadError> {
        sink.truncate(verified_len).await?;
        if sink.read_at(verified_len, 1).await.is_ok() {
            return Err(DownloadError::Verify(VerifyError::Metadata(format!(
                "staging area holds bytes past the verified length {verified_len}; refusing to \
                 promote an artifact that is not the verified one"
            ))));
        }
        sink.finalize().await
    }

    /// Try each not-yet-demoted holder's `dig.getModuleInfo` until one answers, returning the
    /// answering holder's `peer_id` alongside its descriptor so a lying source can be attributed +
    /// demoted.
    ///
    /// If every holder fails, the terminal error names the STEP (`getModuleInfo`) and carries each
    /// holder's own reason — a swallowed reason resurfacing as an unrelated message cost six blind
    /// diagnosis rounds on the read leg (#836).
    async fn fetch_module_info(
        &self,
        providers: &[dig_dht::ProviderRecord],
        demoted: &[String],
        store_id: &str,
        root: &str,
    ) -> Result<(String, ModuleInfo), DownloadError> {
        let mut reasons = HolderReasons::default();
        let mut tried = 0usize;
        for provider in providers {
            let peer = &provider.provider_peer_id;
            if demoted.iter().any(|d| d == peer) {
                continue; // this holder's descriptor already failed a final gate
            }
            tried += 1;
            match self.transport.get_module_info(peer, store_id, root).await {
                Ok(info) => return Ok((peer.clone(), info)),
                Err(e) if e.is_recoverable() => reasons.record(peer, e),
                Err(e) => return Err(e),
            }
        }
        Err(DownloadError::NotFound {
            content: format!(
                "getModuleInfo failed on all {tried} usable holder(s) ({} demoted) for module {} — \
                 {reasons}",
                demoted.len(),
                module_download_key(store_id, root),
            ),
        })
    }

    /// Fetch chunk `index` from the holders, verifying each returned range against
    /// `chunk_hashes[index]` for per-source attribution: a tampered range is rejected and the next
    /// holder tried. Fetching cycles the holders starting at `index` (round-robin spread), so a
    /// multi-holder set is pulled from multiple sources; one re-locate is attempted before giving up.
    ///
    /// Every rejection reason is recorded per holder and reported in the terminal error (#836).
    async fn fetch_verified_chunk(
        &self,
        providers: &mut Vec<dig_dht::ProviderRecord>,
        info: &ModuleInfo,
        layout: &ChunkPlan,
        index: usize,
        store_id: &str,
        root: &str,
    ) -> Result<Vec<u8>, DownloadError> {
        let (offset, len) = layout.chunk_span(index);
        let expected_hash = &info.chunk_hashes[index];
        let mut reasons = HolderReasons::default();

        let mut relocated = false;
        loop {
            let count = providers.len();
            for step in 0..count {
                let peer = providers[(index + step) % count].provider_peer_id.clone();
                match self
                    .fetch_chunk_from(&peer, store_id, root, offset, len, expected_hash)
                    .await
                {
                    Ok(bytes) => return Ok(bytes),
                    Err(reason) => reasons.record(&peer, reason),
                }
            }
            if relocated {
                return Err(DownloadError::NotFound {
                    content: format!(
                        "fetchModuleRange failed for chunk {index} ([{offset}, {}) of module {}) on \
                         all {count} known holder(s) — {reasons}",
                        offset + len,
                        module_download_key(store_id, root),
                    ),
                });
            }
            // Every known holder failed this chunk — ask the DHT for more before giving up.
            let content =
                module_content_id(store_id, root).ok_or(DownloadError::NotDownloadable)?;
            let refreshed = self.locator.find_providers(&content).await?;
            merge_new_providers(providers, refreshed);
            relocated = true;
        }
    }

    /// Fetch and attribute ONE chunk from ONE holder, returning either the verified bytes or a named
    /// reason this holder could not serve it.
    ///
    /// A frame that overshoots the requested window is CLIPPED to it, never rejected: a holder
    /// legitimately answers at its own chunk granularity (the §2.2 clip contract,
    /// [`assemble_range_stream`](crate::source::assemble_range_stream), #836). Only bytes that both
    /// fill the window and hash to `expected_hash` are accepted.
    async fn fetch_chunk_from(
        &self,
        peer: &str,
        store_id: &str,
        root: &str,
        offset: u64,
        len: u64,
        expected_hash: &str,
    ) -> Result<Vec<u8>, String> {
        let fetched = tokio::time::timeout(
            self.config.range_timeout,
            self.transport
                .fetch_module_range(peer, store_id, root, offset, len),
        )
        .await;

        let mut bytes = match fetched {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => return Err(format!("transport: {e}")),
            Err(_) => return Err(format!("timed out after {:?}", self.config.range_timeout)),
        };

        if bytes.len() as u64 > len {
            bytes.truncate(len as usize); // CLIP — a chunk-granular holder is legitimate.
        }
        if bytes.len() as u64 != len {
            return Err(format!(
                "short range: wanted {len} bytes, got {}",
                bytes.len()
            ));
        }
        if sha256_hex(&bytes) != expected_hash {
            return Err("chunk hash mismatch".to_string());
        }
        Ok(bytes)
    }

    /// Load the resume checkpoint for `key`, or a fresh one if none exists / the persisted generation
    /// shape does not match the current [`ModuleInfo`] (a stale checkpoint is never partially reused).
    async fn load_or_fresh_state(
        &self,
        key: &str,
        layout: &ChunkPlan,
    ) -> Result<Resume, DownloadError> {
        let fresh = || {
            let mut s = DownloadState::new(key);
            s.total_length = layout.total_size;
            s.chunk_lens = layout.chunk_lens.clone();
            Resume {
                state: s,
                resumes_staging: false,
            }
        };
        match self.state_store.load(key).await? {
            Some(prev) if prev.chunk_lens == layout.chunk_lens => Ok(Resume {
                state: prev,
                resumes_staging: true,
            }),
            _ => Ok(fresh()),
        }
    }

    /// Read each already-checkpointed chunk back from the sink's staging area into `blob`, marking it
    /// `done` so it is not re-fetched.
    ///
    /// A staged chunk is RE-ATTRIBUTED against `chunk_hashes` exactly like a freshly-fetched one: the
    /// staging file is not a trusted input (it survives a crash, another process, and bit-rot), so a
    /// resumed pull must not inherit corruption it can no longer localize. A chunk that cannot be read
    /// back, reads short, or fails its hash is left NOT done and simply re-fetched, and the checkpoint
    /// is corrected to match — resume is an optimization, never a correctness dependency (#1605).
    async fn rehydrate_done_chunks(
        &self,
        sink: &dyn Sink,
        info: &ModuleInfo,
        layout: &ChunkPlan,
        state: &mut DownloadState,
        blob: &mut [u8],
        done: &mut [bool],
    ) {
        for index in std::mem::take(&mut state.done_ranges) {
            if index >= layout.chunk_count() {
                continue;
            }
            let (offset, len) = layout.chunk_span(index);
            let Ok(bytes) = sink.read_at(offset, len).await else {
                continue;
            };
            if bytes.len() as u64 != len || sha256_hex(&bytes) != info.chunk_hashes[index] {
                tracing::warn!(
                    chunk = index,
                    offset,
                    "staged chunk failed re-attribution on resume; re-fetching"
                );
                continue;
            }
            blob[offset as usize..(offset + len) as usize].copy_from_slice(&bytes);
            done[index] = true;
            state.mark_done(index);
        }
    }
}

/// The resume checkpoint a pull starts from, and whether it belongs to THIS descriptor's plan.
///
/// `resumes_staging` is the licence to inherit what is already staged. A discarded (shape-mismatched
/// or absent) checkpoint means the staging area — which no write ever shortens — may still hold a
/// different plan's bytes, so it is reset rather than resumed.
struct Resume {
    state: DownloadState,
    resumes_staging: bool,
}

/// Why one descriptor's pull attempt failed — and therefore whether ANOTHER holder's descriptor is
/// worth trying.
///
/// A final-gate failure means the DESCRIPTOR was a lie and an honest holder may still serve the
/// capsule. Chunk exhaustion is AMBIGUOUS and classified by [`classify_chunk_exhaustion`]: unavailable
/// bytes and an unsatisfiable descriptor look identical from inside one attempt.
enum PullFailure {
    /// The assembled blob failed the whole-blob-hash or chain-anchor gate, the descriptor itself was
    /// unusable, or no chunk ever verified under it — attributable to the holder that supplied the
    /// descriptor, which is demoted.
    BadDescriptor(DownloadError),
    /// Any other failure (bytes genuinely unavailable under a credible descriptor, sink/state error) —
    /// terminal for the pull.
    Terminal(DownloadError),
}

/// Classify a chunk-level exhaustion: is the DESCRIPTOR unsatisfiable, or are the BYTES unavailable?
///
/// A holder that fabricates `chunk_hashes` (rather than `module_hash`) is the cheapest reshare-denial
/// attack there is — it serves ZERO bytes, and since no holder can satisfy hashes of nothing, the pull
/// exhausts its holders on the first chunk and never reaches a final gate. Treating that as terminal
/// lets one such holder deny a capsule's reshare permanently.
///
/// The honest bound is whether ANY chunk has verified under this descriptor: if one has, the descriptor
/// is credible and the exhaustion really is missing bytes (terminal — re-handshaking would only replay
/// the same fetches). If none ever has, the descriptor is the suspect, so its source is demoted and
/// another holder's descriptor tried (bounded by [`MAX_DESCRIPTOR_ATTEMPTS`]).
fn classify_chunk_exhaustion(e: DownloadError, any_chunk_verified: bool) -> PullFailure {
    if any_chunk_verified {
        PullFailure::Terminal(e)
    } else {
        PullFailure::BadDescriptor(e)
    }
}

impl From<DownloadError> for PullFailure {
    fn from(e: DownloadError) -> Self {
        PullFailure::Terminal(e)
    }
}

/// Allocate the `total_size`-byte assembly buffer FALLIBLY.
///
/// `total_size` is attacker-declared (bounded only by [`ModuleDownloadConfig::max_module_size`]), and
/// `vec![0u8; n]` aborts the process via `handle_alloc_error` when the allocation fails — an
/// uncatchable death a hostile descriptor must never be able to cause. `try_reserve` turns exhaustion
/// into an ordinary rejected-descriptor error.
fn try_zeroed_blob(total_size: u64) -> Result<Vec<u8>, DownloadError> {
    let len = usize::try_from(total_size).map_err(|_| {
        DownloadError::Verify(VerifyError::Metadata(format!(
            "declared module total_size {total_size} does not fit this platform's address space"
        )))
    })?;
    let mut blob: Vec<u8> = Vec::new();
    blob.try_reserve_exact(len).map_err(|e| {
        DownloadError::Verify(VerifyError::Metadata(format!(
            "cannot allocate the {len}-byte assembly buffer a descriptor declared: {e}"
        )))
    })?;
    blob.resize(len, 0); // within the reservation above — no further allocation
    Ok(blob)
}

/// Why each holder could not serve a step, accumulated so the terminal error explains the failure
/// instead of swallowing it (#836). Holder ids are sentinelled — a `provider_peer_id` is free-form
/// text off the wire, and a log an attacker can write is not evidence (#1603).
#[derive(Debug, Default)]
struct HolderReasons(Vec<String>);

impl HolderReasons {
    /// Record `reason` against `peer`, and trace it as it happens (per-holder visibility even when a
    /// later holder succeeds and no error is ever returned).
    fn record(&mut self, peer: &str, reason: impl std::fmt::Display) {
        let peer = hex64_or_sentinel(peer, "peer-id");
        // The REASON is as untrusted as the peer id: a foreign error's `Display` plausibly carries a
        // remote message or status line, and an un-escaped newline in it forges a whole log line just
        // as effectively as a hostile peer id would (#1603). Escape + bound it here, at the one place
        // every holder reason funnels through.
        let reason = sanitize_untrusted_text(&reason.to_string(), MAX_ERROR_REASON_CHARS);
        tracing::debug!(%peer, %reason, "module pull: holder rejected");
        self.0.push(format!("{peer}: {reason}"));
    }
}

impl std::fmt::Display for HolderReasons {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            return f.write_str("no holder reasons recorded");
        }
        write!(f, "reasons: [{}]", self.0.join("; "))
    }
}

/// The chunk layout derived from a [`ModuleInfo`]: per-chunk lengths + their cumulative offsets, with
/// the descriptor's self-consistency checked once up front.
#[derive(Debug)]
struct ChunkPlan {
    total_size: u64,
    chunk_lens: Vec<u64>,
    offsets: Vec<u64>,
}

impl ChunkPlan {
    /// Validate a [`ModuleInfo`] and derive its chunk plan. The descriptor MUST carry `chunk_lens`
    /// (required for the byte→chunk mapping), have one length per `chunk_hashes` entry, have the
    /// lengths sum to `total_size` — otherwise the per-chunk fail-closed check is unimplementable —
    /// declare no more than `max_module_size` bytes, and declare no more than
    /// [`MAX_MODULE_CHUNK_COUNT`] chunks. All of its arithmetic is CHECKED — a wrapping sum must be a
    /// typed rejection, not a panic (see the inline note below).
    ///
    /// The size bound is checked FIRST and before any allocation: the descriptor comes from an
    /// untrusted holder and `total_size` sizes the puller's assembly buffer, so an unbounded declared
    /// size is a one-message memory-exhaustion attack.
    fn from_info(info: &ModuleInfo, max_module_size: u64) -> Result<Self, DownloadError> {
        if info.total_size > max_module_size {
            return Err(DownloadError::Verify(VerifyError::Metadata(format!(
                "declared module total_size {} exceeds the maximum {max_module_size}",
                info.total_size
            ))));
        }
        if info.chunk_lens.is_empty() {
            return Err(DownloadError::Verify(VerifyError::Metadata(
                "ModuleInfo carries no chunk_lens (cannot map ranges to chunk hashes)".into(),
            )));
        }
        // Bound the declared COUNT before cloning it: the count sizes the plan's own vectors, so an
        // absurd one is the same one-message allocation attack as an absurd `total_size`.
        if info.chunk_lens.len() > MAX_MODULE_CHUNK_COUNT {
            return Err(DownloadError::Verify(VerifyError::Metadata(format!(
                "declared chunk_lens count {} exceeds the maximum {MAX_MODULE_CHUNK_COUNT}",
                info.chunk_lens.len()
            ))));
        }
        if info.chunk_lens.len() != info.chunk_hashes.len() {
            return Err(DownloadError::Verify(VerifyError::Metadata(format!(
                "chunk_lens ({}) != chunk_hashes ({})",
                info.chunk_lens.len(),
                info.chunk_hashes.len()
            ))));
        }
        // CHECKED arithmetic, both here and for the offsets below. Unchecked, a descriptor of
        // `{ total_size: 0, chunk_lens: [1, u64::MAX] }` WRAPS to a sum of 0, matches its declared
        // total, and passes every check above — then either aborts the node inside `sum()` (with
        // overflow checks on, as dig-node's release profile has them) or yields spans that index far
        // past the assembled blob. This validator's whole job is to be TOTAL over a hostile
        // descriptor, so no arithmetic in it may wrap or panic.
        let sum = info
            .chunk_lens
            .iter()
            .try_fold(0u64, |acc, &len| acc.checked_add(len))
            .ok_or_else(|| {
                DownloadError::Verify(VerifyError::Metadata(
                    "chunk_lens sum overflows u64 (hostile descriptor)".into(),
                ))
            })?;
        if sum != info.total_size {
            return Err(DownloadError::Verify(VerifyError::Metadata(format!(
                "chunk_lens sum {sum} != total_size {}",
                info.total_size
            ))));
        }
        let chunk_lens = info.chunk_lens.clone();
        let mut offsets = Vec::new();
        offsets.try_reserve_exact(chunk_lens.len()).map_err(|e| {
            DownloadError::Verify(VerifyError::Metadata(format!(
                "cannot allocate a {}-entry chunk plan: {e}",
                chunk_lens.len()
            )))
        })?;
        let mut acc = 0u64;
        for &len in &chunk_lens {
            offsets.push(acc);
            acc = acc.checked_add(len).ok_or_else(|| {
                DownloadError::Verify(VerifyError::Metadata(
                    "chunk offsets overflow u64 (hostile descriptor)".into(),
                ))
            })?;
        }
        Ok(ChunkPlan {
            total_size: info.total_size,
            chunk_lens,
            offsets,
        })
    }

    fn chunk_count(&self) -> usize {
        self.chunk_lens.len()
    }

    /// The `(offset, length)` byte span of chunk `index`.
    fn chunk_span(&self, index: usize) -> (u64, u64) {
        (self.offsets[index], self.chunk_lens[index])
    }
}

/// Append any newly-discovered holders (by `peer_id`) not already known.
fn merge_new_providers(
    known: &mut Vec<dig_dht::ProviderRecord>,
    fresh: Vec<dig_dht::ProviderRecord>,
) {
    for p in fresh {
        if !known
            .iter()
            .any(|k| k.provider_peer_id == p.provider_peer_id)
        {
            known.push(p);
        }
    }
}

/// The 64-hex SHA-256 of `bytes` — the module + per-chunk content-id derivation.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    out
}

/// The stable resume key for a module pull: `module:<store_id>:<root>`. Distinct from the resource
/// [`download_key`](crate::orchestrator::download_key) keyspace so a module checkpoint never collides
/// with a resource one.
pub fn module_download_key(store_id: &str, root: &str) -> String {
    format!("module:{store_id}:{root}")
}

/// The capsule [`ContentId`] a module pull locates holders by — the `(store_id, root)` generation.
/// `store_id` / `root` must be 64-hex; a malformed id yields `None`.
pub fn module_content_id(store_id: &str, root: &str) -> Option<ContentId> {
    Some(ContentId::root(hex32(store_id)?, hex32(root)?))
}

/// Decode a 64-hex string into a 32-byte array, or `None` if malformed.
fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::InMemoryStateStore;
    use crate::sink::InMemorySink;
    use crate::testkit::{
        mock_providers, MockModuleTransport, MockProviderLocator, RejectAllModuleAnchor,
    };
    use std::collections::BTreeSet;

    /// A 64-hex id whose every byte is `byte`.
    fn hex_id(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn locator_with(n: u8, store_id: &str, root: &str) -> Arc<MockProviderLocator> {
        let content = module_content_id(store_id, root).unwrap();
        Arc::new(MockProviderLocator::fixed(mock_providers(n, &content)))
    }

    #[tokio::test]
    async fn happy_path_assembles_verified_module_from_multiple_sources() {
        let store_id = hex_id(0x11);
        let root = hex_id(0x22);
        // 26 bytes over 8-byte chunks = 4 chunks, spread round-robin across 3 holders.
        let module = b"the whole .dig module blob".to_vec();

        let transport = Arc::new(MockModuleTransport::serving(
            &store_id,
            &root,
            module.clone(),
            8,
        ));
        let downloader = ModuleDownloader::new(
            locator_with(3, &store_id, &root),
            transport.clone(),
            Arc::new(AcceptAnyModuleAnchor),
            Arc::new(InMemoryStateStore::new()),
            ModuleDownloadConfig::default(),
        );
        let sink = InMemorySink::new();

        let len = downloader
            .download(&store_id, &root, &sink)
            .await
            .expect("pull succeeds");

        assert_eq!(len, module.len() as u64);
        assert_eq!(
            sink.contents().await,
            module,
            "reassembled blob is byte-exact"
        );
        assert!(sink.is_finalized().await, "verified module is finalized");

        // MULTI-SOURCE: the 4 chunks were pulled from more than one holder.
        let distinct: BTreeSet<String> = transport
            .fetches()
            .await
            .into_iter()
            .map(|(p, _)| p)
            .collect();
        assert!(
            distinct.len() > 1,
            "chunks came from multiple holders: {distinct:?}"
        );
    }

    #[tokio::test]
    async fn resume_after_interrupt_refetches_only_missing_chunks() {
        let store_id = hex_id(0x33);
        let root = hex_id(0x44);
        let module = (0u8..40).collect::<Vec<u8>>(); // 40 bytes / 8 = 5 chunks
        let state_store = Arc::new(InMemoryStateStore::new());
        let sink = InMemorySink::new();

        // First pass: only 2 fetches succeed, then the source starves → the pull fails partway.
        let interrupted = Arc::new(
            MockModuleTransport::serving(&store_id, &root, module.clone(), 8)
                .with_success_budget(2),
        );
        let first = ModuleDownloader::new(
            locator_with(1, &store_id, &root),
            interrupted.clone(),
            Arc::new(AcceptAnyModuleAnchor),
            state_store.clone(),
            ModuleDownloadConfig::default(),
        );
        let err = first
            .download(&store_id, &root, &sink)
            .await
            .expect_err("interrupted pull fails before finalize");
        assert!(
            matches!(err, DownloadError::NotFound { .. }),
            "exhaustion is terminal and names its step: {err}"
        );
        assert!(
            !sink.is_finalized().await,
            "an incomplete pull is never finalized"
        );

        // Second pass: a healthy source resumes against the SAME state + sink.
        let healthy = Arc::new(MockModuleTransport::serving(
            &store_id,
            &root,
            module.clone(),
            8,
        ));
        let second = ModuleDownloader::new(
            locator_with(1, &store_id, &root),
            healthy.clone(),
            Arc::new(AcceptAnyModuleAnchor),
            state_store,
            ModuleDownloadConfig::default(),
        );
        let len = second
            .download(&store_id, &root, &sink)
            .await
            .expect("resumed pull succeeds");
        assert_eq!(len, module.len() as u64);
        assert_eq!(sink.contents().await, module);
        assert!(sink.is_finalized().await);

        // RESUME optimization: the 2 already-verified chunks (offsets 0, 8) are NOT re-fetched.
        let resumed_offsets: BTreeSet<u64> = healthy
            .fetches()
            .await
            .into_iter()
            .map(|(_, o)| o)
            .collect();
        assert!(!resumed_offsets.contains(&0), "chunk 0 not re-fetched");
        assert!(!resumed_offsets.contains(&8), "chunk 1 not re-fetched");
        assert_eq!(
            resumed_offsets,
            BTreeSet::from([16, 24, 32]),
            "only missing chunks fetched"
        );
    }

    #[tokio::test]
    async fn tampered_range_is_rejected_and_routed_around() {
        let store_id = hex_id(0x55);
        let root = hex_id(0x66);
        let module = b"honest bytes across several chunks here".to_vec();

        // Holder 1 tampers every chunk; holders 2 + 3 are honest → the pull recovers.
        let peer1 = crate::testkit::mock_peer_hex(1);
        let transport = Arc::new(
            MockModuleTransport::serving(&store_id, &root, module.clone(), 8).tampering(&peer1),
        );
        let downloader = ModuleDownloader::new(
            locator_with(3, &store_id, &root),
            transport,
            Arc::new(AcceptAnyModuleAnchor),
            Arc::new(InMemoryStateStore::new()),
            ModuleDownloadConfig::default(),
        );
        let sink = InMemorySink::new();

        let len = downloader
            .download(&store_id, &root, &sink)
            .await
            .expect("pull recovers around the tampering holder");
        assert_eq!(
            sink.contents().await,
            module,
            "only honest bytes were accepted"
        );
        assert_eq!(len, module.len() as u64);
    }

    #[tokio::test]
    async fn all_sources_tampering_fails_closed_without_finalize() {
        let store_id = hex_id(0x77);
        let root = hex_id(0x88);
        let module = b"content nobody serves honestly".to_vec();
        let peer1 = crate::testkit::mock_peer_hex(1);

        // The ONLY holder tampers → every chunk fails its hash → nowhere to get honest bytes.
        let transport =
            Arc::new(MockModuleTransport::serving(&store_id, &root, module, 8).tampering(&peer1));
        let downloader = ModuleDownloader::new(
            locator_with(1, &store_id, &root),
            transport,
            Arc::new(AcceptAnyModuleAnchor),
            Arc::new(InMemoryStateStore::new()),
            ModuleDownloadConfig::default(),
        );
        let sink = InMemorySink::new();

        let err = downloader
            .download(&store_id, &root, &sink)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DownloadError::NotFound { .. }),
            "no honest source left is terminal: {err}"
        );
        assert!(
            !sink.is_finalized().await,
            "tampered content is never written through"
        );
    }

    #[tokio::test]
    async fn anchor_rejection_fails_closed_without_finalize() {
        let store_id = hex_id(0x99);
        let root = hex_id(0xAA);
        let module = b"assembles cleanly but is not chain-anchored".to_vec();

        // Every per-chunk + whole-blob check passes, but the chain-anchor gate rejects the blob.
        let transport = Arc::new(MockModuleTransport::serving(&store_id, &root, module, 8));
        let downloader = ModuleDownloader::new(
            locator_with(2, &store_id, &root),
            transport,
            Arc::new(RejectAllModuleAnchor),
            Arc::new(InMemoryStateStore::new()),
            ModuleDownloadConfig::default(),
        );
        let sink = InMemorySink::new();

        let err = downloader
            .download(&store_id, &root, &sink)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DownloadError::Verify(_)),
            "anchor rejection is a verify failure"
        );
        assert!(
            !sink.is_finalized().await,
            "an unanchored module is never finalized"
        );
    }

    #[tokio::test]
    async fn wrong_whole_module_hash_fails_closed() {
        let store_id = hex_id(0xBB);
        let root = hex_id(0xCC);
        let module = b"chunks are honest, module_hash lies".to_vec();

        // Per-chunk hashes are honest (every range verifies) but the declared module_hash is wrong.
        let transport = Arc::new(
            MockModuleTransport::serving(&store_id, &root, module, 8).with_corrupt_module_hash(),
        );
        let downloader = ModuleDownloader::new(
            locator_with(2, &store_id, &root),
            transport,
            Arc::new(AcceptAnyModuleAnchor),
            Arc::new(InMemoryStateStore::new()),
            ModuleDownloadConfig::default(),
        );
        let sink = InMemorySink::new();

        let err = downloader
            .download(&store_id, &root, &sink)
            .await
            .unwrap_err();
        assert!(matches!(err, DownloadError::Verify(_)));
        assert!(!sink.is_finalized().await);
    }

    #[tokio::test]
    async fn no_holders_located_is_not_found() {
        let store_id = hex_id(0x01);
        let root = hex_id(0x02);
        let transport = Arc::new(MockModuleTransport::serving(
            &store_id,
            &root,
            vec![1, 2, 3],
            8,
        ));
        let downloader = ModuleDownloader::new(
            Arc::new(MockProviderLocator::fixed(vec![])),
            transport,
            Arc::new(AcceptAnyModuleAnchor),
            Arc::new(InMemoryStateStore::new()),
            ModuleDownloadConfig::default(),
        );
        let sink = InMemorySink::new();
        let err = downloader
            .download(&store_id, &root, &sink)
            .await
            .unwrap_err();
        assert!(matches!(err, DownloadError::NotFound { .. }));
    }

    /// §2.2 CLIP CONTRACT — a holder that answers at CHUNK granularity returns MORE bytes than the
    /// requested window. That is legitimate (dig-download 0.7.4, #836), so the puller must clip the
    /// frame to the window and keep using the holder — NOT reject it as a length liar. Rejecting here
    /// would make every chunk-granular server unusable and starve the pull.
    #[tokio::test]
    async fn an_over_long_range_is_clipped_not_rejected() {
        let store_id = hex_id(0xD1);
        let root = hex_id(0xD2);
        let module = b"a chunk-granular holder overserves every window".to_vec();

        let transport = Arc::new(
            MockModuleTransport::serving(&store_id, &root, module.clone(), 8).overserving(),
        );
        let downloader = ModuleDownloader::new(
            locator_with(1, &store_id, &root),
            transport,
            Arc::new(AcceptAnyModuleAnchor),
            Arc::new(InMemoryStateStore::new()),
            ModuleDownloadConfig::default(),
        );
        let sink = InMemorySink::new();

        let len = downloader
            .download(&store_id, &root, &sink)
            .await
            .expect("an over-long frame is clipped, so the pull completes");
        assert_eq!(len, module.len() as u64);
        assert_eq!(
            sink.contents().await,
            module,
            "clipped to exactly the requested window — no bleed-through of the extra bytes"
        );
        assert!(sink.is_finalized().await);
    }

    /// #836 — a swallowed transport reason re-surfacing as an unrelated message cost six blind
    /// diagnosis iterations. When the holder set is exhausted the terminal error MUST name the failing
    /// STEP and carry the per-holder reasons, so the log alone explains the failure.
    #[tokio::test]
    async fn exhausted_holders_name_the_failing_step_and_the_reasons() {
        let store_id = hex_id(0xE1);
        let root = hex_id(0xE2);
        let peer1 = crate::testkit::mock_peer_hex(1);
        let transport = Arc::new(
            MockModuleTransport::serving(
                &store_id,
                &root,
                b"nobody serves this honestly".to_vec(),
                8,
            )
            .tampering(&peer1),
        );
        let downloader = ModuleDownloader::new(
            locator_with(1, &store_id, &root),
            transport,
            Arc::new(AcceptAnyModuleAnchor),
            Arc::new(InMemoryStateStore::new()),
            ModuleDownloadConfig::default(),
        );
        let sink = InMemorySink::new();

        let message = downloader
            .download(&store_id, &root, &sink)
            .await
            .unwrap_err()
            .to_string();

        assert!(
            message.contains("fetchModuleRange"),
            "names the step that failed: {message}"
        );
        assert!(
            message.contains("chunk 0"),
            "names the chunk that could not be fetched: {message}"
        );
        assert!(
            message.contains("chunk hash mismatch"),
            "carries the per-holder reason instead of swallowing it: {message}"
        );
        assert!(
            message.contains(&peer1),
            "attributes the reason to a holder"
        );
    }

    /// A hostile `getModuleInfo` descriptor declares a `total_size` the puller would allocate an
    /// assembly buffer for. Without a bound, one lying holder can OOM the node — so the declared size
    /// is refused against a configured cap BEFORE any allocation.
    #[tokio::test]
    async fn an_oversized_declared_module_is_refused_before_allocation() {
        let store_id = hex_id(0xF1);
        let root = hex_id(0xF2);
        let transport = Arc::new(
            MockModuleTransport::serving(&store_id, &root, b"small blob, huge lie".to_vec(), 8)
                .declaring_total_size(64 * 1024 * 1024 * 1024),
        );
        let downloader = ModuleDownloader::new(
            locator_with(1, &store_id, &root),
            transport,
            Arc::new(AcceptAnyModuleAnchor),
            Arc::new(InMemoryStateStore::new()),
            ModuleDownloadConfig {
                max_module_size: 1024,
                ..ModuleDownloadConfig::default()
            },
        );
        let sink = InMemorySink::new();

        let err = downloader
            .download(&store_id, &root, &sink)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DownloadError::Verify(_)),
            "an over-cap descriptor is a verify failure: {err}"
        );
        assert!(
            err.to_string().contains("exceeds the maximum"),
            "names the bound it broke: {err}"
        );
        assert!(!sink.is_finalized().await);
    }

    /// #1605 — a crash-RESUMED pull must not trust its own staging bytes. A chunk read back from
    /// staging is re-attributed against `chunk_hashes` exactly like a freshly-fetched one, so a
    /// staging file corrupted between runs is RE-FETCHED and the pull still completes correctly
    /// (rather than assembling corruption and dying at the whole-blob gate with no way forward).
    #[tokio::test]
    async fn a_corrupted_staged_chunk_is_re_fetched_on_resume() {
        let store_id = hex_id(0xA1);
        let root = hex_id(0xA2);
        let module = (0u8..40).collect::<Vec<u8>>(); // 40 bytes / 8 = 5 chunks
        let state_store = Arc::new(InMemoryStateStore::new());
        let sink = InMemorySink::new();

        // First pass: 2 chunks land, then the source starves.
        let interrupted = Arc::new(
            MockModuleTransport::serving(&store_id, &root, module.clone(), 8)
                .with_success_budget(2),
        );
        ModuleDownloader::new(
            locator_with(1, &store_id, &root),
            interrupted,
            Arc::new(AcceptAnyModuleAnchor),
            state_store.clone(),
            ModuleDownloadConfig::default(),
        )
        .download(&store_id, &root, &sink)
        .await
        .expect_err("interrupted pull fails before finalize");

        // Corrupt the staged bytes of chunk 0 behind the puller's back (bit-rot / tampering with the
        // staging file between runs).
        sink.write_at(0, &[0xFF; 8])
            .await
            .expect("staging is writable");

        let healthy = Arc::new(MockModuleTransport::serving(
            &store_id,
            &root,
            module.clone(),
            8,
        ));
        let len = ModuleDownloader::new(
            locator_with(1, &store_id, &root),
            healthy.clone(),
            Arc::new(AcceptAnyModuleAnchor),
            state_store,
            ModuleDownloadConfig::default(),
        )
        .download(&store_id, &root, &sink)
        .await
        .expect("resume detects the corrupt staged chunk and re-fetches it");

        assert_eq!(len, module.len() as u64);
        assert_eq!(
            sink.contents().await,
            module,
            "the corrupted staged chunk was replaced with honest bytes"
        );
        let refetched: BTreeSet<u64> = healthy
            .fetches()
            .await
            .into_iter()
            .map(|(_, o)| o)
            .collect();
        assert!(
            refetched.contains(&0),
            "the corrupt chunk was re-fetched: {refetched:?}"
        );
        assert!(
            !refetched.contains(&8),
            "the still-valid staged chunk was NOT re-fetched: {refetched:?}"
        );
    }

    /// #1603 — `ProviderRecord::provider_peer_id` is free-form text off the wire, so a hostile holder
    /// can publish arbitrary content there. It must never reach an error/log verbatim; a non-canonical
    /// id is replaced by a sentinel. A log an attacker can write is not evidence.
    #[tokio::test]
    async fn a_non_canonical_peer_id_is_sentinelled_not_echoed() {
        let store_id = hex_id(0xB1);
        let root = hex_id(0xB2);
        let hostile = "not-hex <script>alert(1)</script>\n[FATAL] forged log line";
        let content = module_content_id(&store_id, &root).unwrap();
        let locator = Arc::new(MockProviderLocator::fixed(vec![
            crate::testkit::mock_provider_with_peer_id(hostile, &content),
        ]));

        // The transport rejects everything, so every failure reason mentions the holder.
        let transport = Arc::new(MockModuleTransport::serving(
            "unrelated-store",
            &root,
            vec![1, 2, 3],
            8,
        ));
        let downloader = ModuleDownloader::new(
            locator,
            transport,
            Arc::new(AcceptAnyModuleAnchor),
            Arc::new(InMemoryStateStore::new()),
            ModuleDownloadConfig::default(),
        );
        let sink = InMemorySink::new();

        let message = downloader
            .download(&store_id, &root, &sink)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            !message.contains("<script>") && !message.contains("[FATAL]"),
            "peer-supplied text is never echoed: {message}"
        );
        assert!(
            message.contains("non-canonical-peer-id"),
            "a sentinel stands in for it: {message}"
        );
        assert!(
            !message.contains('\n'),
            "the whole record is ONE line — a forged log line cannot ride in on the reason: {message}"
        );
    }

    /// A peer-supplied hash from the descriptor is equally untrusted text and equally sentinelled when
    /// it is reported in the whole-blob mismatch message.
    #[test]
    fn untrusted_hex_is_sentinelled() {
        let canonical = "ab".repeat(32);
        assert_eq!(hex64_or_sentinel(&canonical, "peer-id"), canonical);
        assert_eq!(
            hex64_or_sentinel("AB".repeat(32).as_str(), "peer-id"),
            "ab".repeat(32),
            "canonical form is lowercase"
        );
        assert_eq!(
            hex64_or_sentinel("short", "peer-id"),
            "<non-canonical-peer-id>"
        );
        assert_eq!(
            hex64_or_sentinel("zz".repeat(32).as_str(), "hash"),
            "<non-canonical-hash>"
        );
    }

    #[test]
    fn malformed_ids_are_not_downloadable() {
        assert!(module_content_id("too-short", &hex_id(1)).is_none());
        assert!(module_content_id(&hex_id(1), "zz").is_none());
        assert!(module_content_id(&hex_id(1), &hex_id(2)).is_some());
    }

    #[test]
    fn download_key_is_module_scoped() {
        let k = module_download_key(&hex_id(1), &hex_id(2));
        assert!(k.starts_with("module:"));
    }

    /// RESHARE-DENIAL — the descriptor defines the WHOLE plan, and holder order is deterministic, so
    /// one holder that wins the `getModuleInfo` race with a well-formed-but-WRONG descriptor would
    /// otherwise deny a capsule's reshare forever: the pull assembles honest bytes, dies at the
    /// whole-blob gate, and every retry re-asks the same liar. The lying SOURCE must be demoted and
    /// the next holder's descriptor tried — an honest holder in the set means the pull SUCCEEDS.
    #[tokio::test]
    async fn a_lying_descriptor_source_is_demoted_and_an_honest_holder_completes_the_pull() {
        let store_id = hex_id(0xC1);
        let root = hex_id(0xC2);
        let module = b"honest bytes, one lying descriptor source".to_vec();
        let liar = crate::testkit::mock_peer_hex(1);

        let transport = Arc::new(
            MockModuleTransport::serving(&store_id, &root, module.clone(), 8)
                .lying_descriptor_from(&liar),
        );
        let downloader = ModuleDownloader::new(
            locator_with(2, &store_id, &root),
            transport.clone(),
            Arc::new(AcceptAnyModuleAnchor),
            Arc::new(InMemoryStateStore::new()),
            ModuleDownloadConfig::default(),
        );
        let sink = InMemorySink::new();

        let len = downloader
            .download(&store_id, &root, &sink)
            .await
            .expect("the honest holder's descriptor completes the pull");
        assert_eq!(len, module.len() as u64);
        assert_eq!(sink.contents().await, module);
        assert!(sink.is_finalized().await);

        let handshakes = transport.module_info_calls().await;
        assert_eq!(
            handshakes.len(),
            2,
            "the liar's descriptor was demoted and another holder re-handshaked: {handshakes:?}"
        );
        assert_eq!(handshakes[0], liar, "the liar answered first");
        assert_ne!(
            handshakes[1], liar,
            "the demoted source is never re-asked: {handshakes:?}"
        );
    }

    /// A pull that resumes over an earlier run's staging + checkpoint must not re-adopt a descriptor
    /// THIS call already proved wrong: the checkpoint the liar's plan produced is dropped on demotion
    /// and the pull re-handshakes with another holder.
    ///
    /// The demotion set is per-CALL (a local `Vec`), so this covers within-call resume only — a fresh
    /// process re-asks the same liar first and demotes it again. Holder reputation that outlives a call
    /// would have to live in the [`StateStore`]; it is deliberately not claimed here.
    #[tokio::test]
    async fn a_pull_does_not_re_adopt_a_demoted_descriptor_within_the_same_call() {
        let store_id = hex_id(0xC5);
        let root = hex_id(0xC6);
        let module = (0u8..40).collect::<Vec<u8>>(); // 40 bytes / 8 = 5 chunks
        let liar = crate::testkit::mock_peer_hex(1);
        let state_store = Arc::new(InMemoryStateStore::new());
        let sink = InMemorySink::new();

        // First run: 2 chunks land, then the source starves — the pull ends without finalize.
        let interrupted = Arc::new(
            MockModuleTransport::serving(&store_id, &root, module.clone(), 8)
                .lying_descriptor_from(&liar)
                .with_success_budget(2),
        );
        ModuleDownloader::new(
            locator_with(2, &store_id, &root),
            interrupted,
            Arc::new(AcceptAnyModuleAnchor),
            state_store.clone(),
            ModuleDownloadConfig::default(),
        )
        .download(&store_id, &root, &sink)
        .await
        .expect_err("the interrupted pull fails before finalize");

        // Resumed run against the SAME staging + checkpoint, with the liar still answering first.
        let healthy = Arc::new(
            MockModuleTransport::serving(&store_id, &root, module.clone(), 8)
                .lying_descriptor_from(&liar),
        );
        let len = ModuleDownloader::new(
            locator_with(2, &store_id, &root),
            healthy,
            Arc::new(AcceptAnyModuleAnchor),
            state_store,
            ModuleDownloadConfig::default(),
        )
        .download(&store_id, &root, &sink)
        .await
        .expect("the resumed pull completes via the honest holder");
        assert_eq!(len, module.len() as u64);
        assert_eq!(sink.contents().await, module);
        assert!(sink.is_finalized().await);
    }

    /// Demotion is BOUNDED: when every holder lies about the descriptor the pull still ends — with a
    /// fail-closed verify error and no finalize — rather than looping over holders forever.
    #[tokio::test]
    async fn every_descriptor_source_lying_is_terminal_and_never_finalizes() {
        let store_id = hex_id(0xC3);
        let root = hex_id(0xC4);
        let liar = crate::testkit::mock_peer_hex(1);
        let transport = Arc::new(
            MockModuleTransport::serving(&store_id, &root, b"only a liar holds this".to_vec(), 8)
                .lying_descriptor_from(&liar),
        );
        let downloader = ModuleDownloader::new(
            locator_with(1, &store_id, &root),
            transport.clone(),
            Arc::new(AcceptAnyModuleAnchor),
            Arc::new(InMemoryStateStore::new()),
            ModuleDownloadConfig::default(),
        );
        let sink = InMemorySink::new();

        let err = downloader
            .download(&store_id, &root, &sink)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DownloadError::Verify(_)),
            "fail-closed: {err}"
        );
        assert!(!sink.is_finalized().await);
        assert!(
            transport.module_info_calls().await.len() <= MAX_DESCRIPTOR_ATTEMPTS,
            "descriptor attempts are bounded"
        );
    }

    /// A hostile descriptor whose `chunk_lens` SUM WRAPS: `1 + u64::MAX == 0`, which equals the
    /// declared `total_size`, so every self-consistency check passes on unchecked arithmetic. The
    /// descriptor validator's whole job is to be TOTAL over a hostile descriptor before any
    /// allocation, so the wrap must be a typed error — never a panic (with overflow checks on, an
    /// unchecked `sum()` aborts the node from ONE `getModuleInfo` response, zero bytes fetched) and
    /// never an accepted plan (with them off, the derived spans index past a zero-length blob).
    #[test]
    fn a_wrapping_chunk_len_sum_is_rejected_not_panicked() {
        let hostile = ModuleInfo {
            total_size: 0,
            module_hash: "ab".repeat(32),
            chunk_hashes: vec!["cd".repeat(32), "ef".repeat(32)],
            chunk_lens: vec![1, u64::MAX],
        };
        let err = ChunkPlan::from_info(&hostile, DEFAULT_MAX_MODULE_SIZE)
            .expect_err("a wrapping descriptor is refused");
        assert!(
            matches!(err, DownloadError::Verify(_)),
            "a hostile descriptor is a verify failure: {err}"
        );
        assert!(
            err.to_string().contains("overflow"),
            "names the arithmetic it broke: {err}"
        );
    }

    /// The declared chunk COUNT is as unbounded as the declared size: a descriptor claiming billions
    /// of zero-length chunks costs the puller two big allocations (`offsets` + the `done` bitmap)
    /// before a byte is fetched. It is refused against a fixed cap.
    #[test]
    fn an_absurd_chunk_count_is_refused() {
        let hostile = ModuleInfo {
            total_size: 0,
            module_hash: "ab".repeat(32),
            chunk_hashes: Vec::new(),
            chunk_lens: vec![0; MAX_MODULE_CHUNK_COUNT + 1],
        };
        let err = ChunkPlan::from_info(&hostile, DEFAULT_MAX_MODULE_SIZE)
            .expect_err("an over-count descriptor is refused");
        assert!(
            err.to_string().contains("chunk_lens"),
            "names the bound it broke: {err}"
        );
    }

    #[test]
    fn chunk_plan_rejects_inconsistent_descriptor() {
        // chunk_lens sum (5) != total_size (99)
        let bad = ModuleInfo {
            total_size: 99,
            module_hash: "ab".repeat(32),
            chunk_hashes: vec!["cd".repeat(32)],
            chunk_lens: vec![5],
        };
        assert!(ChunkPlan::from_info(&bad, DEFAULT_MAX_MODULE_SIZE).is_err());

        // missing chunk_lens
        let no_lens = ModuleInfo {
            total_size: 5,
            module_hash: "ab".repeat(32),
            chunk_hashes: vec!["cd".repeat(32)],
            chunk_lens: vec![],
        };
        assert!(ChunkPlan::from_info(&no_lens, DEFAULT_MAX_MODULE_SIZE).is_err());

        // chunk_hashes / chunk_lens length disagree
        let mismatched = ModuleInfo {
            total_size: 5,
            module_hash: "ab".repeat(32),
            chunk_hashes: vec!["cd".repeat(32), "ef".repeat(32)],
            chunk_lens: vec![5],
        };
        assert!(ChunkPlan::from_info(&mismatched, DEFAULT_MAX_MODULE_SIZE).is_err());
    }

    /// A throwaway directory for the file-backed promotion tests.
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "dig-download-module-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// CACHE POISONING — the artifact VERIFIED must be the artifact PROMOTED.
    ///
    /// A holder that wins the `getModuleInfo` race with a self-consistent fabrication LARGER than the
    /// real module gets its long bytes staged (they pass every per-chunk check and the whole-blob hash
    /// gate) and only dies at the chain-anchor gate. The pull then re-handshakes and completes against
    /// the honest, SHORTER module — so unless the staging area is provably reduced to the verified
    /// length, the promoted `.dig` is honest bytes followed by the attacker's tail: a file whose
    /// SHA-256 is not `module_hash`, cached and re-announced as a holder by the reshare leg.
    #[tokio::test]
    async fn the_promoted_artifact_is_byte_equal_to_the_verified_one_after_a_shorter_retry() {
        let dir = temp_dir("shrinking-lie");
        let final_path = dir.join("module.dig");
        let store_id = hex_id(0xE1);
        let root = hex_id(0xE2);
        let honest = b"honest!!".to_vec(); // 8 bytes, one 8-byte chunk
        let fabricated = vec![0xAA; 32]; // 32 bytes, four self-consistent chunks
        let liar = crate::testkit::mock_peer_hex(1); // providers[0] — wins the handshake race

        let transport = Arc::new(
            MockModuleTransport::serving(&store_id, &root, honest.clone(), 8)
                .serving_alternate_module_from(&liar, fabricated.clone()),
        );
        let downloader = ModuleDownloader::new(
            locator_with(3, &store_id, &root),
            transport,
            Arc::new(crate::testkit::OnlyThisModuleAnchor::new(honest.clone())),
            Arc::new(InMemoryStateStore::new()),
            ModuleDownloadConfig::default(),
        );
        let sink = crate::sink::FileSink::new(&final_path);

        let len = downloader
            .download(&store_id, &root, &sink)
            .await
            .expect("the honest holder's descriptor completes the pull");
        assert_eq!(
            len,
            honest.len() as u64,
            "the VERIFIED length is the honest one"
        );

        let promoted = std::fs::read(&final_path).expect("the module was promoted");
        assert_eq!(
            promoted,
            honest,
            "the promoted artifact carries the attacker's tail: {} promoted bytes vs {} verified",
            promoted.len(),
            honest.len()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The SAME divergence with NO attacker: a staging file left by an earlier attempt at a DIFFERENT
    /// module shape (its checkpoint is discarded as mismatched, but the FILE is not) must not survive
    /// into the promotion of a shorter, freshly-verified module.
    #[tokio::test]
    async fn leftover_staging_of_another_shape_never_survives_into_the_promotion() {
        let dir = temp_dir("stale-staging");
        let final_path = dir.join("module.dig");
        let store_id = hex_id(0xE3);
        let root = hex_id(0xE4);
        let honest = b"honest!!".to_vec();

        // An earlier, differently-shaped attempt left a LONGER staging file plus its checkpoint.
        let staging = crate::sink::staging_path_for(&final_path);
        std::fs::write(&staging, vec![0xAA; 32]).unwrap();
        let state_store = Arc::new(InMemoryStateStore::new());
        let key = module_download_key(&store_id, &root);
        let mut stale = DownloadState::new(&key);
        stale.total_length = 32;
        stale.chunk_lens = vec![8, 8, 8, 8];
        stale.mark_done(0);
        state_store.save(&stale).await.unwrap();

        let downloader = ModuleDownloader::new(
            locator_with(2, &store_id, &root),
            Arc::new(MockModuleTransport::serving(
                &store_id,
                &root,
                honest.clone(),
                8,
            )),
            Arc::new(crate::testkit::OnlyThisModuleAnchor::new(honest.clone())),
            state_store,
            ModuleDownloadConfig::default(),
        );
        let sink = crate::sink::FileSink::new(&final_path);

        let len = downloader.download(&store_id, &root, &sink).await.unwrap();
        assert_eq!(len, honest.len() as u64);
        assert_eq!(
            std::fs::read(&final_path).unwrap(),
            honest,
            "the stale longer staging tail was promoted with the verified bytes"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A sink that implements `read_at` (delegating to an inner [`InMemorySink`]) but IGNORES
    /// `truncate` — the ONE-DEFAULT case: a staging area that simply cannot shrink, paired with a
    /// working read-back. `truncate`'s own default is now fail-closed (it must be OPTED IN to model
    /// "ignores truncate" rather than "unsupported"), so this claims success without ever shortening
    /// the inner buffer — the exact contract the trait doc's opt-in example describes. Everything else
    /// delegates to the inner sink.
    struct UnshrinkableSink(InMemorySink);

    #[async_trait]
    impl Sink for UnshrinkableSink {
        async fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<(), DownloadError> {
            self.0.write_at(offset, bytes).await
        }
        async fn truncate(&self, _len: u64) -> Result<(), DownloadError> {
            Ok(()) // models a staging area that cannot shrink: claims success but never truncates
        }
        async fn read_at(&self, offset: u64, len: u64) -> Result<Vec<u8>, DownloadError> {
            self.0.read_at(offset, len).await
        }
        async fn finalize(&self) -> Result<(), DownloadError> {
            self.0.finalize().await
        }
    }

    /// The promotion check is a CONFIRMATION, not just a shortening: a sink that cannot shrink must
    /// FAIL CLOSED rather than promote an artifact longer than the verified one.
    #[tokio::test]
    async fn a_staging_area_that_cannot_shrink_is_never_promoted() {
        let store_id = hex_id(0xE7);
        let root = hex_id(0xE8);
        let honest = b"honest!!".to_vec();
        let fabricated = vec![0xAA; 32];
        let liar = crate::testkit::mock_peer_hex(1);

        let downloader = ModuleDownloader::new(
            locator_with(3, &store_id, &root),
            Arc::new(
                MockModuleTransport::serving(&store_id, &root, honest.clone(), 8)
                    .serving_alternate_module_from(&liar, fabricated),
            ),
            Arc::new(crate::testkit::OnlyThisModuleAnchor::new(honest.clone())),
            Arc::new(InMemoryStateStore::new()),
            ModuleDownloadConfig::default(),
        );
        let sink = UnshrinkableSink(InMemorySink::new());

        let err = downloader
            .download(&store_id, &root, &sink)
            .await
            .expect_err("a staging area that still holds the demoted tail is not promoted");
        assert!(
            err.to_string().contains("past the verified length"),
            "names the promotion invariant it refused: {err}"
        );
        assert!(!sink.0.is_finalized().await, "and it never finalized");
    }

    /// A sink implementing ONLY `write_at` + `finalize` — BOTH `truncate` and `read_at` left on the
    /// trait's defaults. This is the TWO-DEFAULT combination that used to fail OPEN: the old
    /// `truncate` default silently no-op'd (nothing ever shortened) while `read_at`'s default already
    /// failed closed, so `promote_verified_module`'s "bytes past the verified end" probe read that
    /// failure as "nothing past the end" and promoted a longer, un-truncated, poisoned artifact.
    /// Delegates storage + finalized-tracking to an inner [`InMemorySink`]; everything else is the
    /// plain trait default — this is exactly the shape of a pre-existing external `Sink` that never
    /// anticipated a promotable staging area.
    struct TwoDefaultSink(InMemorySink);

    #[async_trait]
    impl Sink for TwoDefaultSink {
        async fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<(), DownloadError> {
            self.0.write_at(offset, bytes).await
        }
        async fn finalize(&self) -> Result<(), DownloadError> {
            self.0.finalize().await
        }
    }

    /// The TWO-DEFAULT case, proven previously fail-OPEN: an external sink on both the `truncate` AND
    /// `read_at` defaults must never promote a longer, un-truncated tail behind a shorter verified
    /// artifact — the pull errors and the sink is never finalized.
    #[tokio::test]
    async fn a_sink_on_both_truncate_and_read_at_defaults_never_promotes_a_poisoned_tail() {
        let store_id = hex_id(0xE9);
        let root = hex_id(0xEA);
        let honest = b"honest!!".to_vec();
        let fabricated = vec![0xAA; 32];
        let liar = crate::testkit::mock_peer_hex(1);

        let downloader = ModuleDownloader::new(
            locator_with(3, &store_id, &root),
            Arc::new(
                MockModuleTransport::serving(&store_id, &root, honest.clone(), 8)
                    .serving_alternate_module_from(&liar, fabricated),
            ),
            Arc::new(crate::testkit::OnlyThisModuleAnchor::new(honest.clone())),
            Arc::new(InMemoryStateStore::new()),
            ModuleDownloadConfig::default(),
        );
        let sink = TwoDefaultSink(InMemorySink::new());

        let err = downloader
            .download(&store_id, &root, &sink)
            .await
            .expect_err("a sink on both defaults must fail closed, never promote blind");
        assert!(
            matches!(err, DownloadError::Sink(_)),
            "the fail-closed truncate default refuses rather than promoting blind: {err}"
        );
        assert!(!sink.0.is_finalized().await, "and it never finalized");
    }

    /// RESHARE-DENIAL, the CHEAPEST variant — a descriptor whose per-chunk hashes are FABRICATED.
    ///
    /// Nobody can satisfy those hashes, so the pull exhausts every holder on chunk 0 and never reaches
    /// a final gate. Treating that exhaustion as terminal lets a holder that serves ZERO bytes deny a
    /// capsule's reshare forever: while no chunk has verified, the descriptor itself is the suspect, so
    /// its source is demoted and an honest holder's descriptor completes the pull.
    #[tokio::test]
    async fn a_fabricated_chunk_hash_descriptor_source_is_demoted_and_the_pull_completes() {
        let store_id = hex_id(0xF1);
        let root = hex_id(0xF2);
        let module = b"honest bytes behind a zero-byte liar".to_vec();
        let liar = crate::testkit::mock_peer_hex(1);

        let transport = Arc::new(
            MockModuleTransport::serving(&store_id, &root, module.clone(), 8)
                .fabricating_chunk_hashes_from(&liar),
        );
        let downloader = ModuleDownloader::new(
            locator_with(3, &store_id, &root),
            transport.clone(),
            Arc::new(crate::testkit::OnlyThisModuleAnchor::new(module.clone())),
            Arc::new(InMemoryStateStore::new()),
            ModuleDownloadConfig::default(),
        );
        let sink = InMemorySink::new();

        let len = downloader
            .download(&store_id, &root, &sink)
            .await
            .expect("an honest holder's descriptor completes the pull");
        assert_eq!(len, module.len() as u64);
        assert_eq!(sink.contents().await, module);

        let handshakes = transport.module_info_calls().await;
        assert_eq!(handshakes[0], liar, "the liar answered first");
        assert!(
            handshakes.len() >= 2 && handshakes[1] != liar,
            "the fabricating source was demoted and another holder re-handshaked: {handshakes:?}"
        );
    }
}
