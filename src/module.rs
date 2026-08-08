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
//! 6. **Assemble** verified chunks in order into the [`Sink`]'s staging area, hashing each into a
//!    running whole-module SHA-256 as it lands, then run the two fail-closed final gates BEFORE
//!    finalize — (a) that running hash equals `module_hash` (whole-blob integrity), and (b) the staged
//!    module verifies against its chain-anchored `root` via the injected [`ModuleAnchorVerifier`],
//!    which reads it through the bounded [`ModuleReader`] seam (NC-9 —
//!    verified-content-is-not-safe-until-chain-bound; a right-shaped-but-forged module a lying
//!    holder-set could otherwise agree on is caught here). Only if BOTH pass is the sink finalized +
//!    the resume checkpoint cleared. A failure leaves the staging file unfinalized (never written
//!    through) and is terminal for the pull.
//!
//!    **Peak memory is ONE CHUNK, not one module** (#1610). Nothing sized by the declared `total_size`
//!    is ever allocated, so a small host can reshare a capsule far larger than its RAM. Streaming the
//!    hash opens no window on partially-verified bytes: a chunk is absorbed only after it matches
//!    `chunk_hashes[i]`, the bytes live in the STAGING area — never the artifact — and promotion is a
//!    single atomic step strictly after both gates pass.
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
//! - [`ModuleAnchorVerifier`] + [`ModuleReader`] — bind the STAGED module to the chain root, read
//!   through a bounded window rather than handed over as one slice. dig-node injects the
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
use crate::sink::{promote_verified, Sink};

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

/// Random-access read over the module bytes a pull has staged — the seam the anchor gate sees
/// INSTEAD of a `&[u8]` of the whole module (#1610).
///
/// A `&[u8]` parameter forced the puller to hold the entire module in RAM before it could ask the one
/// question that decides the pull, so peak RSS was the module size and a small host simply could not
/// reshare a large capsule. Behind this trait the same gate reads the staging area on demand, so peak
/// RSS is one chunk.
///
/// ## What an implementation MUST guarantee
///
/// Every byte this reader returns is already **chunk-hash-verified against the descriptor**, and the
/// readable window is exactly the `total_size` the whole-module-hash gate has already accepted — the
/// gate never sees an unverified or out-of-window byte ([`StagedModuleReader`] is this crate's
/// implementation and enforces both).
#[async_trait]
pub trait ModuleReader: Send + Sync {
    /// The module's verified length in bytes. Reads are clamped to `[0, len())`.
    fn len(&self) -> u64;

    /// Whether the module is empty — present because clippy requires it beside [`len`](Self::len);
    /// a real `.dig` module is never empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read the `[offset, offset + len)` window of the module.
    ///
    /// # Errors
    /// [`DownloadError::Sink`] when the window falls outside the module or the staged bytes cannot be
    /// read back / no longer match the descriptor's chunk hashes. A read error is never "zeroes": the
    /// caller MUST treat it as a failure to verify, never as absent content.
    async fn read_at(&self, offset: u64, len: u64) -> Result<Vec<u8>, DownloadError>;
}

/// Binds a fully-staged `.dig` module to its chain-anchored `(store_id, root)` — the sole root of
/// trust of the module pull (NC-9). dig-node injects the digstore verifier; this crate ships only the
/// explicitly-opt-in, fail-OPEN [`AcceptAnyModuleAnchor`] for tests.
#[async_trait]
pub trait ModuleAnchorVerifier: Send + Sync {
    /// Whether the module behind `module` is the genuine `.dig` container committed on-chain under
    /// `(store_id, root)` (i.e. its embedded generation root equals the `getAnchoredRoot` value).
    ///
    /// `module` is a **borrowed, read-only** view of the staged bytes and is valid only for the
    /// duration of this call: it cannot be retained, and it cannot promote or mutate anything. The
    /// bytes it yields are chunk-hash-verified and bounded to the already-hash-gated module length,
    /// so reading them incrementally is not a weaker check than being handed the whole slice was —
    /// it is the same bytes, materialized one window at a time.
    ///
    /// An implementation that consults the chain MUST report [`ModuleAnchor::Unavailable`] when it
    /// could not reach an answer, NEVER [`ModuleAnchor::NotAnchored`]. The two are acted on very
    /// differently: `NotAnchored` is EVIDENCE against the holder that supplied the descriptor and earns
    /// it a durable demotion, while `Unavailable` is this node's own failure and is terminal for the
    /// pull. Collapsing them lets a chain-source blip brand every honest holder tried (see
    /// [`ModuleAnchor`]). A read error from `module` is likewise the LOCAL node failing to read its own
    /// staging area ⇒ `Unavailable`, not `NotAnchored`.
    async fn verify_module_anchor(
        &self,
        module: &dyn ModuleReader,
        store_id: &str,
        root: &str,
    ) -> ModuleAnchor;
}

/// The three answers a [`ModuleAnchorVerifier`] can give — the reason this is not a `bool`.
///
/// A two-valued answer forces an implementation that cannot reach the chain to say "not anchored",
/// which is a claim about the HOLDER. That mislabels an honest holder serving a correct blob during a
/// chain-source outage, and the resulting durable verdict then INVERTS the node's descriptor preference
/// for the whole reputation TTL: remembered honest holders are skipped and unremembered peers — which
/// is what a sybil is — are asked first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleAnchor {
    /// The blob IS the module committed on-chain under `(store_id, root)`.
    Anchored,
    /// The blob is definitively NOT that module — evidence against the descriptor's source.
    NotAnchored,
    /// The check could not be completed (chain source unreachable, timeout, malformed local state).
    /// Says NOTHING about the holder: terminal for the pull, never a verdict. Carries a short reason
    /// for the terminal error.
    Unavailable(String),
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
#[async_trait]
impl ModuleAnchorVerifier for AcceptAnyModuleAnchor {
    async fn verify_module_anchor(
        &self,
        _module: &dyn ModuleReader,
        _store_id: &str,
        _root: &str,
    ) -> ModuleAnchor {
        ModuleAnchor::Anchored
    }
}

/// The default [`ModuleDownloadConfig::max_module_size`] — 512 MiB.
///
/// **This is a DISK policy knob, no longer a memory bound (#1610).** The puller used to assemble the
/// whole module in RAM, so the declared size was what one lying `getModuleInfo` could make a node
/// allocate — a ceiling above host memory was then an out-of-memory primitive costing the attacker one
/// message. Chunks are now hashed as they land and the anchor gate reads the staging area, so peak RSS
/// is ONE CHUNK regardless of the declared size and no RAM ceiling is being defended.
///
/// What the bound still limits is the STAGING BYTES an unproven descriptor can make this node write to
/// disk before either gate can reject it, so it is kept rather than removed. A deployment that
/// reshares larger capsules now raises it on the disk budget alone; it no longer has to size host
/// memory to the largest capsule it wants to serve.
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
    /// UNTRUSTED holder and sizes the bytes this node will STAGE on disk before either final gate can
    /// reject it, so it is refused above this bound before a single range is fetched. It is a disk
    /// policy knob, not a memory bound — see [`DEFAULT_MAX_MODULE_SIZE`]. Defaults to
    /// [`DEFAULT_MAX_MODULE_SIZE`].
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
        let key = module_download_key(store_id, root);
        let mut exclusions = DescriptorExclusions::new(self.remembered_verdicts(&key).await);
        let mut attempts = 0usize;
        loop {
            // Reputation is consulted, never obeyed to the point of denial: the moment excluding the
            // remembered holders would leave NOBODY to ask, the memory is dropped for the rest of this
            // call and every located holder becomes askable again (#1611). This covers the case where
            // some honest holders are remembered and the liar is not — excluding them, demoting the
            // liar, and then finding "no usable holder" would deny a pull the network can serve.
            if exclusions.usable_holders(&providers) == 0 && exclusions.stop_trusting_memory() {
                tracing::warn!(
                    holders = providers.len(),
                    "no holder is left to ask for a descriptor once past verdicts are honoured; \
                     re-asking every holder rather than letting reputation deny the pull"
                );
                continue;
            }
            let (source, info) = self
                .fetch_module_info(&providers, &exclusions.excluded(), store_id, root)
                .await?;
            attempts += 1;
            let failure = match self
                .pull_with_descriptor(&info, store_id, root, sink, &mut providers)
                .await
            {
                Ok(len) => return Ok(len),
                // A LOCAL failure — this node's memory, sink, state store, or an anchor check it could
                // not COMPLETE — ends the pull and attributes nothing to any holder.
                Err(PullFailure::Terminal(e)) => return Err(e),
                Err(failure) => failure,
            };
            let proven_false = failure.is_proven_false();
            tracing::warn!(
                peer = %hex64_or_sentinel(&source, "peer-id"),
                error = %failure.error(),
                proven_false,
                "module pull: descriptor attempt failed; demoting this source and re-handshaking \
                 with another holder"
            );
            // Only a PROVEN-false descriptor earns a durable verdict. Chunk exhaustion demotes for
            // this call (that is #1613's point) but carries no evidence the descriptor was false —
            // the bytes may simply be unavailable, and the peers refusing them need not be the peer
            // that supplied the descriptor. Persisting it would let sybils that refuse their assigned
            // chunks brand an HONEST holder for 24 h, per capsule, until only attacker-supplied
            // descriptors are ever asked for (#1611 security finding).
            if proven_false {
                if let Err(store_err) = self.state_store.record_bad_descriptor(&key, &source).await
                {
                    tracing::debug!(error = %store_err, "could not persist a bad-descriptor verdict");
                }
            }
            exclusions.demote(source);
            // Give up when THIS call's attempt budget is spent OR no askable holder is left (the
            // memory has already been dropped above if it was what exhausted them). The budget counts
            // attempts made here, not the exclusion set — which also carries remembered verdicts that
            // cost this call nothing. The returned error is the DESCRIPTOR failure, never a "not
            // found": blaming discovery for a descriptor lie is exactly the ambiguity that cost four
            // #1586 rounds.
            if attempts >= MAX_DESCRIPTOR_ATTEMPTS
                || (exclusions.usable_holders(&providers) == 0 && !exclusions.trusts_memory())
            {
                return Err(match failure {
                    PullFailure::BadDescriptor(e) | PullFailure::UnsatisfiableDescriptor(e) => e,
                    PullFailure::Terminal(e) => e,
                });
            }
            // The whole plan came from the demoted holder, so its partial progress is not resumable
            // against the next descriptor — drop the checkpoint AND the bytes it staged. A demoted
            // plan may have been LONGER than the next one, and a staging area is never shortened by
            // writing, so leaving it would let the demoted holder's tail survive into a later
            // promotion.
            self.state_store.clear(&key).await?;
            sink.truncate(0).await?;
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
        let layout = ChunkPlan::from_info(info, self.config.max_module_size)?;

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

        // STAGE + HASH the module CHUNK BY CHUNK, in ascending chunk order (#1610). There is no
        // whole-module buffer: peak RSS is ONE CHUNK, and the attacker-declared `total_size` sizes no
        // allocation at all — it now only bounds the staged bytes on disk.
        //
        // The fail-closed property is unchanged, and rests on the SAME two facts as before:
        //   1. a chunk is absorbed into the running whole-module hash only AFTER it has matched the
        //      descriptor's `chunk_hashes[i]`, so no unattributed byte ever reaches the hash gate; and
        //   2. bytes land in the STAGING area, which is never the artifact — promotion is the atomic
        //      `promote_verified` below, strictly after BOTH gates pass. Nothing partially verified is
        //      observable at the final path, exactly as when a RAM blob held the same bytes.
        let checkpointed = std::mem::take(&mut state.done_ranges);
        let mut hasher = Sha256::new();
        let mut any_chunk_verified = false;
        for index in 0..layout.chunk_count() {
            let (offset, len) = layout.chunk_span(index);
            let staged = if checkpointed.contains(&index) {
                self.read_back_verified_chunk(sink, info, index, offset, len)
                    .await
            } else {
                None
            };
            let bytes = match staged {
                Some(bytes) => bytes,
                None => {
                    // FETCH + ATTRIBUTE the chunk, fanned round-robin across the holders.
                    let bytes = match self
                        .fetch_verified_chunk(providers, info, &layout, index, store_id, root)
                        .await
                    {
                        Ok(bytes) => bytes,
                        // Exhaustion is attributed to the DESCRIPTOR whether or not a chunk has
                        // verified: a liar can buy credibility for one byte, so only the attempt
                        // budget may bound the retry (#1613). A non-recoverable failure (a sink/state
                        // fault) stays terminal — it is the local node failing, not a holder lying.
                        Err(e)
                            if e.is_recoverable()
                                || matches!(e, DownloadError::NotFound { .. }) =>
                        {
                            return Err(PullFailure::UnsatisfiableDescriptor(
                                describe_chunk_exhaustion(e, any_chunk_verified),
                            ))
                        }
                        Err(e) => return Err(PullFailure::Terminal(e)),
                    };
                    sink.write_at(offset, &bytes).await?;
                    state.mark_done(index);
                    self.state_store.save(&state).await?;
                    bytes
                }
            };
            any_chunk_verified = true;
            hasher.update(&bytes);
            state.mark_done(index);
        }

        // The two FAIL-CLOSED final gates, BEFORE finalize. Neither pass ⇒ the staging file is never
        // promoted (the module is rejected, not written through — NC-9).
        let assembled_hash = hex_of(hasher.finalize());
        if assembled_hash != info.module_hash {
            return Err(PullFailure::BadDescriptor(DownloadError::Verify(
                VerifyError::Metadata(format!(
                    "assembled module_hash {assembled_hash} != declared {}",
                    hex64_or_sentinel(&info.module_hash, "module-hash")
                )),
            )));
        }
        // The anchor gate reads the staging area through a bounded, read-only, chunk-re-verifying
        // window instead of being handed the whole module. It runs AFTER the whole-module hash gate,
        // so every byte it can see belongs to a blob this node has already hashed end to end, and it
        // runs BEFORE `promote_verified`, so its verdict still gates the whole artifact.
        //
        // The gate reads through the SINK, so a sink that cannot expose its staged bytes is refused
        // here — explicitly, and named for what it is. Such a sink could never be promoted either
        // (`promote_verified` refuses an unprovable staged length), so this is the same refusal one
        // step earlier; naming it "the chain anchor could not be verified" would blame the chain for a
        // local capability the sink simply does not have.
        if !sink.supports_read_back() {
            return Err(PullFailure::Terminal(DownloadError::sink(
                "this sink cannot read back its staged bytes, so the chain-anchor gate has nothing \
                 to read and the module could never be promoted; implement Sink::read_at + \
                 Sink::supports_read_back",
            )));
        }
        let reader = StagedModuleReader::new(sink, &layout, &info.chunk_hashes);
        match self
            .anchor
            .verify_module_anchor(&reader, store_id, root)
            .await
        {
            ModuleAnchor::Anchored => {}
            ModuleAnchor::NotAnchored => {
                return Err(PullFailure::BadDescriptor(DownloadError::Verify(
                    VerifyError::Metadata(format!(
                        "assembled module is not chain-anchored under ({store_id}, {root})"
                    )),
                )))
            }
            // The gate could not reach an answer. That is THIS node's failure, so it is terminal and
            // earns the holder nothing: branding an honest holder for a chain-source blip would invert
            // the node's descriptor preference toward unremembered (i.e. sybil) peers for the whole
            // reputation TTL.
            ModuleAnchor::Unavailable(reason) => {
                return Err(PullFailure::Terminal(DownloadError::state(format!(
                    "cannot verify the chain anchor for ({store_id}, {root}): {}",
                    sanitize_untrusted_text(&reason, MAX_ERROR_REASON_CHARS)
                ))))
            }
        }

        // A promotion refusal is fail-closed AND recoverable: the checkpoint that led here is dropped
        // with the bytes it describes, so a later pull re-fetches instead of failing identically forever
        // (a checkpoint can outlive its staging file — GC reaps the `.download.tmp` while the
        // `StateStore` keeps its record elsewhere). Best-effort: the promotion error is what the caller
        // must see.
        if let Err(e) = promote_verified(sink, layout.total_size).await {
            let _ = self.state_store.clear(&key).await;
            let _ = sink.truncate(0).await;
            return Err(PullFailure::Terminal(e));
        }
        self.state_store.clear(&key).await?;
        Ok(layout.total_size)
    }

    /// The holders this node has already caught supplying a PROVEN-false descriptor for `key` — the
    /// [`StateStore`]'s remembered reputation, used to start a pull with the known liars already
    /// demoted instead of re-discovering them (#1611). An unreadable store simply yields none:
    /// reputation is advisory and must never fail a pull.
    async fn remembered_verdicts(&self, key: &str) -> Vec<String> {
        match self.state_store.bad_descriptor_peers(key).await {
            Ok(peers) => peers,
            Err(e) => {
                tracing::debug!(error = %e, "could not read remembered descriptor verdicts");
                Vec::new()
            }
        }
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
        excluded: &[String],
        store_id: &str,
        root: &str,
    ) -> Result<(String, ModuleInfo), DownloadError> {
        let mut reasons = HolderReasons::default();
        let mut tried = 0usize;
        for provider in providers {
            let peer = &provider.provider_peer_id;
            if excluded.iter().any(|d| d == peer) {
                continue; // demoted in this call, or carrying a remembered verdict
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
                excluded.len(),
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

    /// Read one already-checkpointed chunk back from the sink's staging area, returning it only if it
    /// still passes the SAME attribution a freshly-fetched chunk gets.
    ///
    /// The staging file is not a trusted input (it survives a crash, another process, and bit-rot), so
    /// a resumed pull must not inherit corruption it can no longer localize. A chunk that cannot be
    /// read back, reads short, or fails its hash yields `None` and is simply re-fetched — resume is an
    /// optimization, never a correctness dependency (#1605).
    async fn read_back_verified_chunk(
        &self,
        sink: &dyn Sink,
        info: &ModuleInfo,
        index: usize,
        offset: u64,
        len: u64,
    ) -> Option<Vec<u8>> {
        let bytes = sink.read_at(offset, len).await.ok()?;
        if bytes.len() as u64 != len || sha256_hex(&bytes) != info.chunk_hashes[index] {
            tracing::warn!(
                chunk = index,
                offset,
                "staged chunk failed re-attribution on resume; re-fetching"
            );
            return None;
        }
        Some(bytes)
    }
}

/// The [`ModuleReader`] the puller hands the anchor gate: a bounded, read-only, chunk-re-verifying
/// window onto the sink's staging area (#1610).
///
/// It exists so the gate never needs the whole module in RAM. Two properties make that safe to
/// substitute for the `&[u8]` it replaced:
///
/// - **Bounded.** Reads outside `[0, total_size)` are refused, so the gate cannot see a byte outside
///   the blob the whole-module hash gate accepted — including any longer tail a demoted descriptor
///   may have left staged (a staging area is never shortened by writing).
/// - **Re-verified.** Every chunk is re-read from the artifact and re-hashed against the descriptor's
///   `chunk_hashes` on each read, so a staging area mutated between the hash gate and the anchor gate
///   fails closed instead of feeding the gate bytes nothing has attributed. Being handed a RAM blob
///   gave weaker cover than this: it verified a COPY while promotion promoted the file.
///
/// Peak memory for one read is the caller's requested span plus one chunk. The anchor verifier is an
/// injected, trusted component of the node (never a peer), so the span is not attacker-controlled.
struct StagedModuleReader<'a> {
    sink: &'a dyn Sink,
    layout: &'a ChunkPlan,
    chunk_hashes: &'a [String],
}

impl<'a> StagedModuleReader<'a> {
    fn new(sink: &'a dyn Sink, layout: &'a ChunkPlan, chunk_hashes: &'a [String]) -> Self {
        StagedModuleReader {
            sink,
            layout,
            chunk_hashes,
        }
    }

    /// Read chunk `index` back from staging and re-attribute it against the descriptor.
    async fn verified_chunk(&self, index: usize) -> Result<Vec<u8>, DownloadError> {
        let (offset, len) = self.layout.chunk_span(index);
        let bytes = self.sink.read_at(offset, len).await?;
        if bytes.len() as u64 != len {
            return Err(DownloadError::sink(format!(
                "staged chunk {index} reads {} bytes, expected {len}",
                bytes.len()
            )));
        }
        if sha256_hex(&bytes) != self.chunk_hashes[index] {
            return Err(DownloadError::sink(format!(
                "staged chunk {index} no longer matches its verified hash"
            )));
        }
        Ok(bytes)
    }
}

#[async_trait]
impl ModuleReader for StagedModuleReader<'_> {
    fn len(&self) -> u64 {
        self.layout.total_size
    }

    async fn read_at(&self, offset: u64, len: u64) -> Result<Vec<u8>, DownloadError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let end = offset.checked_add(len).filter(|e| *e <= self.len());
        let Some(end) = end else {
            return Err(DownloadError::sink(format!(
                "read [{offset}, {offset}+{len}) falls outside the {}-byte module",
                self.len()
            )));
        };
        let mut out = Vec::with_capacity(usize::try_from(len).map_err(|_| {
            DownloadError::sink(format!(
                "read of {len} bytes exceeds this platform's address space"
            ))
        })?);
        // Start at the last chunk beginning at or before `offset`; zero-length chunks in between are
        // stepped over by the loop rather than special-cased.
        let mut index = self
            .layout
            .offsets
            .partition_point(|&start| start <= offset)
            .saturating_sub(1);
        while (out.len() as u64) < len {
            if index >= self.layout.chunk_count() {
                // Unreachable while `end <= total_size` holds, but fail CLOSED rather than return a
                // short read that a caller could mistake for the whole window.
                return Err(DownloadError::sink(format!(
                    "the staged chunk plan does not cover [{offset}, {end})"
                )));
            }
            let (chunk_offset, chunk_len) = self.layout.chunk_span(index);
            if chunk_len == 0 {
                index += 1;
                continue;
            }
            let chunk = self.verified_chunk(index).await?;
            let want_from = offset + out.len() as u64;
            let start = usize::try_from(want_from - chunk_offset).unwrap_or(usize::MAX);
            let take = chunk
                .len()
                .saturating_sub(start)
                .min(usize::try_from(len - out.len() as u64).unwrap_or(usize::MAX));
            out.extend_from_slice(&chunk[start..start + take]);
            index += 1;
        }
        Ok(out)
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
    /// The descriptor was PROVEN false: the assembled blob failed the whole-blob-hash or chain-anchor
    /// gate, or the descriptor was structurally unusable. Attributable to the holder that supplied it,
    /// which is demoted for this call AND recorded durably.
    BadDescriptor(DownloadError),
    /// The descriptor could not be SATISFIED — the chunks it declares could not be fetched from any
    /// holder. Its source is demoted for this call so another descriptor is tried (#1613), but nothing
    /// here proves the descriptor was false: the bytes may be genuinely unavailable, and the holders
    /// refusing them need not be the holder that supplied the descriptor. So it earns NO durable
    /// verdict — see [`DescriptorEvidence`].
    UnsatisfiableDescriptor(DownloadError),
    /// Any other failure (a local sink/state fault) — terminal for the pull.
    Terminal(DownloadError),
}

/// Which holders a pull will not ask for a descriptor, and whether it is still honouring the
/// [`StateStore`]'s remembered verdicts.
///
/// Two sources of exclusion with DIFFERENT authority: holders demoted in THIS call (a failed attempt
/// happened here — always excluded) and holders remembered from a past call (advisory, and droppable).
/// Keeping them apart is what lets reputation be dropped without also forgiving a liar caught seconds
/// ago — the bug of a single flat list.
struct DescriptorExclusions {
    demoted_here: Vec<String>,
    remembered: Vec<String>,
    trusts_memory: bool,
}

impl DescriptorExclusions {
    fn new(remembered: Vec<String>) -> Self {
        let trusts_memory = !remembered.is_empty();
        DescriptorExclusions {
            demoted_here: Vec::new(),
            remembered,
            trusts_memory,
        }
    }

    /// The peers not to ask right now.
    fn excluded(&self) -> Vec<String> {
        let mut excluded = self.demoted_here.clone();
        if self.trusts_memory {
            excluded.extend(self.remembered.iter().cloned());
        }
        excluded
    }

    /// How many located holders are still askable for a descriptor.
    fn usable_holders(&self, providers: &[dig_dht::ProviderRecord]) -> usize {
        let excluded = self.excluded();
        providers
            .iter()
            .filter(|p| !excluded.contains(&p.provider_peer_id))
            .count()
    }

    /// Record that `peer` failed an attempt in THIS call (never droppable).
    fn demote(&mut self, peer: String) {
        self.demoted_here.push(peer);
    }

    /// Stop honouring the remembered verdicts, returning whether that actually changed anything (i.e.
    /// whether the memory was what left nobody to ask).
    fn stop_trusting_memory(&mut self) -> bool {
        let was_trusting = self.trusts_memory;
        self.trusts_memory = false;
        was_trusting && !self.remembered.is_empty()
    }

    fn trusts_memory(&self) -> bool {
        self.trusts_memory
    }
}

/// Explain a chunk-level exhaustion: were the BYTES unavailable under a credible descriptor, or was
/// the DESCRIPTOR itself unsatisfiable?
///
/// This is DIAGNOSIS, not control flow. Exhaustion always demotes the descriptor source and re-tries
/// another holder's descriptor (bounded by [`MAX_DESCRIPTOR_ATTEMPTS`] and the un-demoted holder set),
/// because "did any chunk verify?" is not a bound an attacker respects: a holder declaring
/// `chunk_lens = [1, rest]` serves that ONE byte — matching its own fabricated first hash — and then
/// refuses everything, so a retry gated on the flag never happens and one liar denies the capsule's
/// reshare for the price of a single byte (#1613). The attempt budget alone guarantees termination.
///
/// Whether a chunk verified is still worth SAYING: exhaustion after real progress is more likely
/// genuine unavailability, exhaustion with none more likely a fabricated descriptor, and an operator
/// reading the log should not have to guess which.
fn describe_chunk_exhaustion(e: DownloadError, any_chunk_verified: bool) -> DownloadError {
    let diagnosis = if any_chunk_verified {
        "some chunk(s) had already verified under this descriptor, so the missing bytes are more \
         likely genuinely unavailable than fabricated"
    } else {
        "no chunk ever verified under this descriptor, so it is more likely fabricated than the \
         bytes unavailable"
    };
    match e {
        DownloadError::NotFound { content } => DownloadError::NotFound {
            content: format!("{content} — {diagnosis}"),
        },
        other => other,
    }
}

impl PullFailure {
    /// The underlying error, whatever the attribution.
    fn error(&self) -> &DownloadError {
        match self {
            PullFailure::BadDescriptor(e)
            | PullFailure::UnsatisfiableDescriptor(e)
            | PullFailure::Terminal(e) => e,
        }
    }

    /// Whether this failure PROVES the descriptor false, and so may be remembered against its source.
    fn is_proven_false(&self) -> bool {
        matches!(self, PullFailure::BadDescriptor(_))
    }
}

impl From<DownloadError> for PullFailure {
    fn from(e: DownloadError) -> Self {
        PullFailure::Terminal(e)
    }
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
    /// untrusted holder and `total_size` bounds the bytes staged on disk before either final gate can
    /// reject them.
    fn from_info(info: &ModuleInfo, max_module_size: u64) -> Result<Self, PullFailure> {
        // Every rejection below is a statement about the DESCRIPTOR, so it is attributable to the holder
        // that supplied it. The one exception is the allocation further down, which is a local outcome —
        // see its comment.
        let false_descriptor = |reason: String| {
            PullFailure::BadDescriptor(DownloadError::Verify(VerifyError::Metadata(reason)))
        };
        if info.total_size > max_module_size {
            return Err(false_descriptor(format!(
                "declared module total_size {} exceeds the maximum {max_module_size}",
                info.total_size
            )));
        }
        if info.chunk_lens.is_empty() {
            return Err(false_descriptor(
                "ModuleInfo carries no chunk_lens (cannot map ranges to chunk hashes)".into(),
            ));
        }
        // Bound the declared COUNT before cloning it: the count sizes the plan's own vectors, so an
        // absurd one is the same one-message allocation attack as an absurd `total_size`.
        if info.chunk_lens.len() > MAX_MODULE_CHUNK_COUNT {
            return Err(false_descriptor(format!(
                "declared chunk_lens count {} exceeds the maximum {MAX_MODULE_CHUNK_COUNT}",
                info.chunk_lens.len()
            )));
        }
        if info.chunk_lens.len() != info.chunk_hashes.len() {
            return Err(false_descriptor(format!(
                "chunk_lens ({}) != chunk_hashes ({})",
                info.chunk_lens.len(),
                info.chunk_hashes.len()
            )));
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
                false_descriptor("chunk_lens sum overflows u64 (hostile descriptor)".into())
            })?;
        if sum != info.total_size {
            return Err(false_descriptor(format!(
                "chunk_lens sum {sum} != total_size {}",
                info.total_size
            )));
        }
        let chunk_lens = info.chunk_lens.clone();
        let mut offsets = Vec::new();
        // Not descriptor evidence — the count is already bounded above, so a refusal here is this host
        // running out of memory and must brand nobody. But it is still UNSATISFIABLE rather than
        // terminal: another holder's descriptor deserves a try (blame and next-step are two
        // INDEPENDENT axes, chosen separately).
        offsets.try_reserve_exact(chunk_lens.len()).map_err(|e| {
            PullFailure::UnsatisfiableDescriptor(DownloadError::sink(format!(
                "this host cannot allocate the {}-entry chunk plan this descriptor declares: {e}",
                chunk_lens.len()
            )))
        })?;
        let mut acc = 0u64;
        for &len in &chunk_lens {
            offsets.push(acc);
            acc = acc.checked_add(len).ok_or_else(|| {
                false_descriptor("chunk offsets overflow u64 (hostile descriptor)".into())
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

/// The 64-hex SHA-256 of `bytes` — the per-chunk content-id derivation.
fn sha256_hex(bytes: &[u8]) -> String {
    hex_of(Sha256::digest(bytes))
}

/// Lower-hex encode bytes. The single shared hex encoder for the crate.
///
/// Split out from [`sha256_hex`] because the whole-module hash is now accumulated INCREMENTALLY
/// over the chunks (#1610) and so finalizes a digest that never had a contiguous `&[u8]` behind it.
pub(crate) fn hex_of(digest: impl AsRef<[u8]>) -> String {
    let mut out = String::with_capacity(64);
    for b in digest.as_ref() {
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

    /// A hostile `getModuleInfo` descriptor declares a `total_size` the puller would STAGE on disk
    /// before either final gate could reject it. The declared size is refused against the configured
    /// cap before a single range is fetched.
    #[tokio::test]
    async fn an_oversized_declared_module_is_refused_before_staging() {
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
            err.is_proven_false(),
            "a hostile descriptor is attributable to the holder that supplied it"
        );
        let err = err.error();
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
        assert!(err.is_proven_false(), "attributable to its source");
        let err = err.error();
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
        // Read-back WORKS here, so the refusal below can only come from the length proof itself — not
        // from the "cannot observe my staging area" refusal that guards an unproven sink.
        fn supports_read_back(&self) -> bool {
            true
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
    /// failed closed, so [`promote_verified`]'s "bytes past the verified end" probe read that
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

    /// A sink on BOTH the `truncate` and `read_at` defaults fails closed — at the FIRST place it is
    /// asked to shorten anything, which is the abandoned-plan reset, long before promotion.
    ///
    /// Named for what it actually proves. It was previously named for the promotion tail and asserted
    /// only `DownloadError::Sink(_)`, which this pull produces without reaching `promote_verified` at
    /// all: `pull_with_descriptor` resets a non-resuming staging area first, the fail-closed `truncate`
    /// default rejects that, and the pull dies before any liar tail is staged. It therefore passed with
    /// the entire promotion proof deleted. The promotion path for a defaulted `read_at` is covered by
    /// `the_documented_whole_commit_sink_recipe_cannot_promote_unproven_bytes`; this cell covers the
    /// reset, and asserts the MESSAGE so it cannot silently start proving something else.
    #[tokio::test]
    async fn a_sink_on_both_truncate_and_read_at_defaults_fails_closed_at_the_first_reset() {
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
        // The MESSAGE, not just the variant: this pull dies at the abandoned-plan reset, and asserting
        // only `Sink(_)` passed even with the whole promotion proof deleted.
        assert!(
            err.to_string().contains("truncation unsupported"),
            "it is the fail-closed truncate DEFAULT that refuses, at the plan reset: {err}"
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

    /// #1613 — a descriptor retry gated on "did ANY chunk verify?" is bypassable for ONE BYTE.
    ///
    /// The liar declares `chunk_lens = [1, rest]` with an honest hash for the first byte and a
    /// fabricated one for the rest, serves that single byte, then refuses everything. Under the old
    /// bound the first verified chunk flipped the pull into "the descriptor is credible", so the
    /// inevitable exhaustion on chunk 1 was Terminal — no demotion, no re-handshake — and the pull died
    /// with two honest holders standing right there. Cost to the attacker: one byte.
    ///
    /// The attempt budget, not the flag, is what bounds termination: exhaustion always demotes the
    /// descriptor source and tries the next holder's descriptor while the budget allows.
    #[tokio::test]
    async fn a_liar_that_serves_one_byte_then_refuses_is_still_demoted() {
        let store_id = hex_id(0x5A);
        let root = hex_id(0x5B);
        let module = b"an honest module blob of some length".to_vec();
        let liar = crate::testkit::mock_peer_hex(1);

        let transport = Arc::new(
            MockModuleTransport::serving(&store_id, &root, module.clone(), 8)
                .serving_one_byte_then_refusing_from(&liar),
        );
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
            .expect("an honest holder's descriptor completes the pull");

        assert_eq!(len, module.len() as u64);
        assert_eq!(sink.contents().await, module, "only honest bytes promoted");
        let handshakes = transport.module_info_calls().await;
        assert!(
            handshakes.len() > 1,
            "the one-byte liar was demoted and another holder's descriptor tried: {handshakes:?}"
        );
        assert!(
            handshakes.len() <= MAX_DESCRIPTOR_ATTEMPTS + 1,
            "descriptor retries stay bounded by the attempt budget: {handshakes:?}"
        );
    }

    /// The exhaustion DIAGNOSIS still distinguishes the two cases even though the control flow no
    /// longer does: exhaustion after some chunk verified is more likely genuine unavailability, and
    /// exhaustion with none verified more likely a fabricated descriptor. That is a message, not a gate.
    #[test]
    fn exhaustion_diagnosis_names_whether_any_chunk_had_verified() {
        let base = DownloadError::NotFound {
            content: "fetchModuleRange failed for chunk 3".into(),
        };
        let with_progress = describe_chunk_exhaustion(base, true).to_string();
        let without_progress = describe_chunk_exhaustion(
            DownloadError::NotFound {
                content: "fetchModuleRange failed for chunk 3".into(),
            },
            false,
        )
        .to_string();
        assert!(
            with_progress.contains("chunk 3"),
            "keeps the original reason: {with_progress}"
        );
        assert_ne!(
            with_progress, without_progress,
            "the two exhaustion cases read differently"
        );
    }

    /// #1611 — a liar caught in ONE call must not be re-asked as a descriptor source in the NEXT.
    ///
    /// Demotion used to live in a local `Vec` inside `download()`, so a fresh call re-asked the same
    /// liars from scratch and paid up to `MAX_DESCRIPTOR_ATTEMPTS` full pull attempts again. The verdict
    /// is now persisted in the `StateStore`, so the second call skips the known liar's handshake
    /// entirely — while still fetching CHUNKS from it (chunk bytes are hash-attributed, so excluding it
    /// there would cost availability for no integrity gain).
    #[tokio::test]
    async fn a_liar_demoted_in_one_call_is_not_re_asked_in_the_next() {
        let store_id = hex_id(0x6A);
        let root = hex_id(0x6B);
        let module = b"an honest module across chunks".to_vec();
        let liar = crate::testkit::mock_peer_hex(1);
        let state_store = Arc::new(InMemoryStateStore::new());

        // Call 1: the liar wins the handshake race, fails the whole-blob gate, and is demoted.
        let first_transport = Arc::new(
            MockModuleTransport::serving(&store_id, &root, module.clone(), 8)
                .lying_descriptor_from(&liar),
        );
        let first = ModuleDownloader::new(
            locator_with(3, &store_id, &root),
            first_transport.clone(),
            Arc::new(AcceptAnyModuleAnchor),
            state_store.clone(),
            ModuleDownloadConfig::default(),
        );
        first
            .download(&store_id, &root, &InMemorySink::new())
            .await
            .expect("an honest holder completes call 1");
        assert!(
            first_transport.module_info_calls().await.contains(&liar),
            "call 1 did ask the liar (that is how it learned)"
        );

        // Call 2: the SAME state store, so the verdict is remembered.
        let second_transport = Arc::new(
            MockModuleTransport::serving(&store_id, &root, module.clone(), 8)
                .lying_descriptor_from(&liar),
        );
        let second = ModuleDownloader::new(
            locator_with(3, &store_id, &root),
            second_transport.clone(),
            Arc::new(AcceptAnyModuleAnchor),
            state_store.clone(),
            ModuleDownloadConfig::default(),
        );
        let len = second
            .download(&store_id, &root, &InMemorySink::new())
            .await
            .expect("call 2 completes");

        assert_eq!(len, module.len() as u64);
        assert!(
            !second_transport.module_info_calls().await.contains(&liar),
            "the remembered liar is never asked for a descriptor again: {:?}",
            second_transport.module_info_calls().await
        );
        assert_eq!(
            second_transport.module_info_calls().await.len(),
            1,
            "and exactly one honest handshake was needed"
        );
        assert!(
            second_transport
                .fetches()
                .await
                .iter()
                .any(|(peer, _)| peer == &liar),
            "a demoted descriptor source is still used for CHUNK fetches"
        );
        assert_eq!(
            state_store
                .bad_descriptor_peers(&module_download_key(&store_id, &root))
                .await
                .unwrap(),
            vec![liar],
            "the verdict is what the store persisted"
        );
    }

    /// Reputation must not be able to deny a pull: when EVERY located holder carries a past verdict the
    /// memory is ignored for that attempt (a verdict is evidence about a moment, and holders get fixed).
    #[tokio::test]
    async fn reputation_never_denies_a_pull_when_every_holder_is_remembered() {
        let store_id = hex_id(0x6C);
        let root = hex_id(0x6D);
        let module = b"honest bytes from a once-bad holder".to_vec();
        let key = module_download_key(&store_id, &root);
        let state_store = Arc::new(InMemoryStateStore::new());
        // The only holder is remembered as a past liar — but it serves honestly now.
        state_store
            .record_bad_descriptor(&key, &crate::testkit::mock_peer_hex(1))
            .await
            .unwrap();

        let downloader = ModuleDownloader::new(
            locator_with(1, &store_id, &root),
            Arc::new(MockModuleTransport::serving(
                &store_id,
                &root,
                module.clone(),
                8,
            )),
            Arc::new(AcceptAnyModuleAnchor),
            state_store,
            ModuleDownloadConfig::default(),
        );
        let sink = InMemorySink::new();
        let len = downloader
            .download(&store_id, &root, &sink)
            .await
            .expect("a remembered holder is still asked when it is the only one");
        assert_eq!(len, module.len() as u64);
        assert_eq!(sink.contents().await, module);
    }

    /// GATE #1, the PARTIAL case — reputation must not deny a pull the network can serve.
    ///
    /// Verdicts on the two HONEST holders and none on the liar: honouring the memory excludes the honest
    /// holders from the descriptor role, the liar wins the handshake, fails a final gate, is demoted —
    /// and `usable == 0`, so the pull returned the descriptor error with honest holders sitting right
    /// there. `demoted` started empty before #1611, so that was a regression, and the total-case test
    /// (`reputation_never_denies_a_pull_when_every_holder_is_remembered`) never reached it. The escape
    /// now triggers on "no usable holder remains", not on "all holders remembered".
    #[tokio::test]
    async fn reputation_never_denies_a_pull_when_only_the_honest_holders_are_remembered() {
        let store_id = hex_id(0x7A);
        let root = hex_id(0x7B);
        let module = b"honest bytes the network can still serve".to_vec();
        let key = module_download_key(&store_id, &root);
        let liar = crate::testkit::mock_peer_hex(1);
        let state_store = Arc::new(InMemoryStateStore::new());
        // The HONEST holders carry the verdicts; the liar does not.
        for honest in [
            crate::testkit::mock_peer_hex(2),
            crate::testkit::mock_peer_hex(3),
        ] {
            state_store
                .record_bad_descriptor(&key, &honest)
                .await
                .unwrap();
        }

        let downloader = ModuleDownloader::new(
            locator_with(3, &store_id, &root),
            Arc::new(
                MockModuleTransport::serving(&store_id, &root, module.clone(), 8)
                    .lying_descriptor_from(&liar),
            ),
            Arc::new(AcceptAnyModuleAnchor),
            state_store,
            ModuleDownloadConfig::default(),
        );
        let sink = InMemorySink::new();

        let len = downloader
            .download(&store_id, &root, &sink)
            .await
            .expect("remembered HONEST holders are re-asked rather than denying the pull");
        assert_eq!(len, module.len() as u64);
        assert_eq!(sink.contents().await, module);
    }

    /// GATE #1(b) — chunk exhaustion must NOT leave a durable verdict against the descriptor source.
    ///
    /// DHT provider announcement is unauthenticated, so if unsatisfied chunks were durable evidence,
    /// sybil holders could refuse their assigned chunks and get an HONEST descriptor source blacklisted
    /// on the victim for 24 h — per capsule, repeatably — until only attacker-supplied descriptors were
    /// ever asked for. Exhaustion still demotes for THIS call (#1613); it just earns no memory.
    #[tokio::test]
    async fn chunk_exhaustion_demotes_for_this_call_but_records_no_durable_verdict() {
        let store_id = hex_id(0x7C);
        let root = hex_id(0x7D);
        let key = module_download_key(&store_id, &root);
        let state_store = Arc::new(InMemoryStateStore::new());

        // The only holder answers `getModuleInfo` honestly and then serves nothing: the chunks cannot be
        // fetched, so the pull exhausts and fails — with no evidence its descriptor was false.
        let downloader = ModuleDownloader::new(
            locator_with(1, &store_id, &root),
            Arc::new(
                MockModuleTransport::serving(&store_id, &root, b"unavailable bytes".to_vec(), 8)
                    .with_success_budget(0),
            ),
            Arc::new(AcceptAnyModuleAnchor),
            state_store.clone(),
            ModuleDownloadConfig::default(),
        );
        let sink = InMemorySink::new();

        downloader
            .download(&store_id, &root, &sink)
            .await
            .expect_err("unavailable chunks fail the pull");
        assert!(
            state_store
                .bad_descriptor_peers(&key)
                .await
                .unwrap()
                .is_empty(),
            "no durable verdict from mere unavailability — else sybils can brand an honest holder"
        );
        assert!(!sink.is_finalized().await);
    }

    /// GATE #4 — the sink recipe this crate's own docs give MUST NOT fail open.
    ///
    /// `truncate` overridden to `Ok(())` (the blessed "I commit whole" opt-in) with `read_at` left on its
    /// default was the one untested combination: nothing is shortened, the past-the-end probe's
    /// "read-back unsupported" reads as "nothing there", and an unproven artifact promotes. Promotion now
    /// requires `supports_read_back`, so a sink that cannot show its staged bytes is refused.
    #[tokio::test]
    async fn the_documented_whole_commit_sink_recipe_cannot_promote_unproven_bytes() {
        /// `truncate` → `Ok(())` exactly as the [`Sink::truncate`] doc's opt-in shows, `read_at` left on
        /// the trait default. The shape a real store-write sink following that recipe would have.
        struct RecipeSink(InMemorySink);

        #[async_trait]
        impl Sink for RecipeSink {
            async fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<(), DownloadError> {
                self.0.write_at(offset, bytes).await
            }
            async fn truncate(&self, _len: u64) -> Result<(), DownloadError> {
                Ok(()) // "this sink commits whole, so there is never a tail to shrink"
            }
            async fn finalize(&self) -> Result<(), DownloadError> {
                self.0.finalize().await
            }
        }

        let store_id = hex_id(0x7E);
        let root = hex_id(0x7F);
        let honest = b"honest!!".to_vec();
        let liar = crate::testkit::mock_peer_hex(1);

        // The liar stages a LONGER fabrication first, then the honest, shorter module is pulled — so the
        // staging area holds a tail the verified bytes do not contain.
        let downloader = ModuleDownloader::new(
            locator_with(3, &store_id, &root),
            Arc::new(
                MockModuleTransport::serving(&store_id, &root, honest.clone(), 8)
                    .serving_alternate_module_from(&liar, vec![0xAA; 32]),
            ),
            Arc::new(crate::testkit::OnlyThisModuleAnchor::new(honest)),
            Arc::new(InMemoryStateStore::new()),
            ModuleDownloadConfig::default(),
        );
        let sink = RecipeSink(InMemorySink::new());

        let err = downloader
            .download(&store_id, &root, &sink)
            .await
            .expect_err("a sink that cannot prove its staged length is never promoted");
        assert!(
            err.to_string().contains("cannot read back"),
            "names WHY it refused — an unprovable promotion, not a length verdict: {err}"
        );
        assert!(!sink.0.is_finalized().await, "and it never finalized");
    }

    /// A declared size far past any real module costs no allocation at all (#1610).
    ///
    /// Before #1610 this descriptor made the puller try to reserve ~18 EiB — the failure the deleted
    /// `try_zeroed_blob` had to classify. The plan now derives from the descriptor without allocating
    /// anything proportional to `total_size`, so the same hostile claim is simply *planned* and then
    /// dies as unfetchable chunks (see the two end-to-end tests below). Pinning it here keeps the
    /// no-allocation property from silently regressing back into a reservation.
    #[test]
    fn an_18_exbibyte_declaration_costs_no_allocation() {
        let hostile = ModuleInfo {
            total_size: u64::MAX,
            module_hash: hex_id(0x01),
            chunk_hashes: vec![hex_id(0x02)],
            chunk_lens: vec![u64::MAX],
        };
        let Ok(plan) = ChunkPlan::from_info(&hostile, u64::MAX) else {
            panic!("the plan is derived, not allocated — an 18 EiB claim is now cheap to hold")
        };
        assert_eq!(plan.total_size, u64::MAX);
        assert_eq!(plan.chunk_count(), 1);
    }

    /// GATE, end to end — a ~100-byte inflated descriptor must not deny the capsule.
    ///
    /// The attacker announces as a provider, wins the `getModuleInfo` race, and answers a SELF-CONSISTENT
    /// descriptor whose `total_size` (and matching final `chunk_len`) this host cannot allocate. It must
    /// cost the attacker the descriptor role and nothing else: no durable verdict against anyone, and the
    /// honest holder standing right there completes the pull.
    ///
    /// Only the LIAR inflates. With every holder inflating — as this test first did — a puller that dies
    /// instead of retrying is indistinguishable from one that recovers, so the regression was invisible.
    #[tokio::test]
    async fn an_honest_holder_completes_the_pull_after_an_impossible_descriptor() {
        let store_id = hex_id(0x8A);
        let root = hex_id(0x8B);
        let key = module_download_key(&store_id, &root);
        let module = b"a real module served honestly".to_vec();
        let liar = crate::testkit::mock_peer_hex(1);
        let state_store = Arc::new(InMemoryStateStore::new());

        let transport = Arc::new(
            MockModuleTransport::serving(&store_id, &root, module.clone(), 8)
                .inflating_total_size_from(&liar, u64::MAX),
        );
        let downloader = ModuleDownloader::new(
            locator_with(3, &store_id, &root),
            transport.clone(),
            Arc::new(AcceptAnyModuleAnchor),
            state_store.clone(),
            // A ceiling that admits the declared size, so the SIZE guard is not what rejects it and the
            // allocation is genuinely what fails.
            ModuleDownloadConfig {
                max_module_size: u64::MAX,
                ..ModuleDownloadConfig::default()
            },
        );
        let sink = InMemorySink::new();

        let len = downloader
            .download(&store_id, &root, &sink)
            .await
            .expect("an honest holder's descriptor completes the pull");
        assert_eq!(len, module.len() as u64);
        assert_eq!(sink.contents().await, module);
        assert!(
            transport.module_info_calls().await.len() > 1,
            "the unallocatable descriptor's source was demoted and another holder asked: {:?}",
            transport.module_info_calls().await
        );
        assert!(
            state_store
                .bad_descriptor_peers(&key)
                .await
                .unwrap()
                .is_empty(),
            "and NOBODY is branded: an unsatisfiable descriptor is not PROOF the holder lied — the \
             bytes it declares may simply be unavailable"
        );
        let _ = &liar;
    }

    /// The same failure when EVERY holder declares an impossible module: the pull fails closed
    /// (bounded by the attempt budget) and promotes nothing.
    #[tokio::test]
    async fn every_holder_declaring_an_impossible_module_fails_closed() {
        let store_id = hex_id(0x8E);
        let root = hex_id(0x8F);
        let key = module_download_key(&store_id, &root);
        let state_store = Arc::new(InMemoryStateStore::new());

        let downloader = ModuleDownloader::new(
            locator_with(2, &store_id, &root),
            Arc::new(
                MockModuleTransport::serving(&store_id, &root, b"a real module".to_vec(), 8)
                    .declaring_total_size(u64::MAX),
            ),
            Arc::new(AcceptAnyModuleAnchor),
            state_store.clone(),
            ModuleDownloadConfig {
                max_module_size: u64::MAX,
                ..ModuleDownloadConfig::default()
            },
        );
        let sink = InMemorySink::new();

        downloader
            .download(&store_id, &root, &sink)
            .await
            .expect_err("no holder offers a module that could exist");
        assert!(
            state_store
                .bad_descriptor_peers(&key)
                .await
                .unwrap()
                .is_empty(),
            "no holder is branded for a descriptor merely unsatisfiable"
        );
        assert!(!sink.is_finalized().await, "and nothing is promoted");
    }

    /// GATE — an anchor gate that cannot REACH an answer must not brand the holder.
    ///
    /// With a `bool` return an implementation that consults the chain had to answer `false` during an
    /// outage, which was read as "proven not anchored" and persisted. An honest holder, a correct blob
    /// and a chain-source blip then branded every holder tried — and for the whole TTL the node's
    /// descriptor preference INVERTED, skipping remembered honest holders and asking unremembered
    /// (i.e. sybil) peers first. `ModuleAnchor::Unavailable` is the third answer that fixes it.
    #[tokio::test]
    async fn an_unreachable_chain_anchor_is_terminal_and_brands_nobody() {
        let store_id = hex_id(0x8C);
        let root = hex_id(0x8D);
        let key = module_download_key(&store_id, &root);
        let state_store = Arc::new(InMemoryStateStore::new());

        let downloader = ModuleDownloader::new(
            locator_with(3, &store_id, &root),
            Arc::new(MockModuleTransport::serving(
                &store_id,
                &root,
                b"a correct, genuinely anchored module".to_vec(),
                8,
            )),
            Arc::new(crate::testkit::UnreachableChainAnchor),
            state_store.clone(),
            ModuleDownloadConfig::default(),
        );
        let sink = InMemorySink::new();

        let err = downloader
            .download(&store_id, &root, &sink)
            .await
            .expect_err("an unverifiable anchor is fail-closed");
        assert!(
            err.to_string().contains("cannot verify the chain anchor"),
            "it reports an unfinished CHECK, not a verdict on the module: {err}"
        );
        assert!(
            state_store
                .bad_descriptor_peers(&key)
                .await
                .unwrap()
                .is_empty(),
            "and no honest holder is branded by this node's own outage"
        );
        assert!(
            !sink.is_finalized().await,
            "fail-closed: nothing is promoted while the anchor is unproven"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // #1610 — the streaming whole-module hash + the reader-based anchor gate.
    // ---------------------------------------------------------------------------------------------

    /// The whole-module hash is taken in CHUNK order, not in the order chunks became available.
    ///
    /// The nearest wrong implementation absorbs each chunk as it lands — which is what the previous
    /// structure did in effect, rehydrating the checkpointed chunks first and only then fetching the
    /// rest. Every existing resume test survives that bug, because their checkpoints hold a PREFIX
    /// (chunks 0,1): prefix-first arrival order and ascending chunk order are the same sequence, so
    /// the fixture cannot tell them apart.
    ///
    /// The distinguishing fixture is a checkpoint holding exactly the MIDDLE chunk of five, over
    /// content where every chunk differs. Arrival-order hashing then computes `c2‖c0‖c1‖c3‖c4`, which
    /// fails the whole-module gate; chunk-order hashing completes the pull.
    #[tokio::test]
    async fn the_whole_module_hash_is_taken_in_chunk_order_not_arrival_order() {
        let store_id = hex_id(0x90);
        let root = hex_id(0x91);
        let key = module_download_key(&store_id, &root);
        // 40 bytes / 8 = 5 chunks, each with distinct content.
        let module = (0u8..40).collect::<Vec<u8>>();

        // Stage ONLY the middle chunk (index 2, bytes [16, 24)) and checkpoint exactly it.
        let sink = InMemorySink::new();
        sink.write_at(16, &module[16..24]).await.unwrap();
        let state_store = Arc::new(InMemoryStateStore::new());
        let mut state = DownloadState::new(&key);
        state.total_length = module.len() as u64;
        state.chunk_lens = vec![8; 5];
        state.mark_done(2);
        state_store.save(&state).await.unwrap();

        let downloader = ModuleDownloader::new(
            locator_with(1, &store_id, &root),
            Arc::new(MockModuleTransport::serving(
                &store_id,
                &root,
                module.clone(),
                8,
            )),
            // Anchored on the exact bytes — so this test also proves the READER reassembles the module
            // the gate sees in chunk order, not merely that the hash does.
            Arc::new(crate::testkit::OnlyThisModuleAnchor::new(module.clone())),
            state_store,
            ModuleDownloadConfig::default(),
        );

        let len = downloader
            .download(&store_id, &root, &sink)
            .await
            .expect("a mid-module checkpoint resumes and still passes both gates");
        assert_eq!(len, module.len() as u64);
        assert_eq!(sink.contents().await, module);
        assert!(sink.is_finalized().await);
    }

    /// The anchor gate cannot read outside the module the whole-module hash gate accepted.
    ///
    /// A staging area is never SHORTENED by writing, so bytes past `total_size` can genuinely be
    /// there — a longer earlier attempt's tail. An unbounded reader would hand them to the gate as if
    /// they were part of the verified artifact.
    #[tokio::test]
    async fn the_anchor_gate_cannot_read_past_the_verified_module() {
        /// An anchor gate that tries to read one byte beyond the module's end.
        struct ReadsPastTheEnd;

        #[async_trait]
        impl ModuleAnchorVerifier for ReadsPastTheEnd {
            async fn verify_module_anchor(
                &self,
                module: &dyn ModuleReader,
                _store_id: &str,
                _root: &str,
            ) -> ModuleAnchor {
                match module.read_at(module.len().saturating_sub(1), 2).await {
                    Ok(_) => ModuleAnchor::Anchored,
                    Err(e) => ModuleAnchor::Unavailable(e.to_string()),
                }
            }
        }

        let store_id = hex_id(0x92);
        let root = hex_id(0x93);
        let module = (0u8..40).collect::<Vec<u8>>();

        let downloader = ModuleDownloader::new(
            locator_with(1, &store_id, &root),
            Arc::new(MockModuleTransport::serving(
                &store_id,
                &root,
                module.clone(),
                8,
            )),
            Arc::new(ReadsPastTheEnd),
            Arc::new(InMemoryStateStore::new()),
            ModuleDownloadConfig::default(),
        );
        let sink = InMemorySink::new();

        let err = downloader
            .download(&store_id, &root, &sink)
            .await
            .expect_err("a read past the verified end is refused, so the gate reaches no answer");
        assert!(
            err.to_string().contains("falls outside"),
            "the refusal names the out-of-range window: {err}"
        );
        assert!(!sink.is_finalized().await, "and nothing is promoted");
    }

    /// Staging bytes that change between the hash gate and the anchor read fail CLOSED, and brand
    /// nobody.
    ///
    /// The two gates now read the staging area at two different moments (they used to share one RAM
    /// copy), so the window between them has to be closed by re-attributing every chunk the reader
    /// serves. Asserting only "the pull fails" would not distinguish a reader that re-verifies from
    /// one that does not: without the check the anchor gate simply sees the corrupted bytes and
    /// answers `NotAnchored`, which also fails the pull — but as a durable verdict against a holder
    /// that did nothing wrong. So the load-bearing assertion is WHO gets blamed.
    #[tokio::test]
    async fn staging_corrupted_between_the_two_gates_fails_closed_and_brands_nobody() {
        /// A sink that stages honestly but returns a flipped byte on read-back — a staging area
        /// mutated (by bit-rot, another process, or a local attacker) after the hash gate passed.
        struct CorruptingReadBack(InMemorySink);

        #[async_trait]
        impl Sink for CorruptingReadBack {
            async fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<(), DownloadError> {
                self.0.write_at(offset, bytes).await
            }
            async fn truncate(&self, len: u64) -> Result<(), DownloadError> {
                self.0.truncate(len).await
            }
            fn supports_read_back(&self) -> bool {
                true
            }
            async fn read_at(&self, offset: u64, len: u64) -> Result<Vec<u8>, DownloadError> {
                let mut bytes = self.0.read_at(offset, len).await?;
                if let Some(first) = bytes.first_mut() {
                    *first ^= 0xFF;
                }
                Ok(bytes)
            }
            async fn finalize(&self) -> Result<(), DownloadError> {
                self.0.finalize().await
            }
        }

        let store_id = hex_id(0x94);
        let root = hex_id(0x95);
        let key = module_download_key(&store_id, &root);
        let module = (0u8..40).collect::<Vec<u8>>();
        let state_store = Arc::new(InMemoryStateStore::new());

        let downloader = ModuleDownloader::new(
            locator_with(2, &store_id, &root),
            Arc::new(MockModuleTransport::serving(
                &store_id,
                &root,
                module.clone(),
                8,
            )),
            Arc::new(crate::testkit::OnlyThisModuleAnchor::new(module.clone())),
            state_store.clone(),
            ModuleDownloadConfig::default(),
        );
        let sink = CorruptingReadBack(InMemorySink::new());

        let err = downloader
            .download(&store_id, &root, &sink)
            .await
            .expect_err("the gate must not run on bytes nothing has attributed");
        assert!(
            err.to_string()
                .contains("no longer matches its verified hash"),
            "the failure names the staging area, not the chain or a holder: {err}"
        );
        assert!(
            state_store
                .bad_descriptor_peers(&key)
                .await
                .unwrap()
                .is_empty(),
            "local corruption is never evidence against a holder that served correct bytes"
        );
        assert!(!sink.0.is_finalized().await, "and nothing is promoted");
    }
}
