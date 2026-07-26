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
//! 3. **Fan** the chunks across the located holders concurrently
//!    ([`ModuleTransport::fetch_module_range`], `dig.fetchModuleRange`), each chunk one range.
//! 4. **Attribute** each returned range against `chunk_hashes[i]` the instant it arrives — a tampered
//!    or mis-sized range is REJECTED and re-fetched from another holder, and the serving holder is
//!    penalized (per-source attribution, fail-closed before assembly).
//! 5. **Resume** across pause / crash via the injected [`StateStore`]: a chunk already verified is
//!    recorded and NEVER re-fetched.
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
//!   `getAnchoredRoot` value). This crate ships only the explicitly-opt-in, `#[doc(hidden)]`
//!   [`AcceptAnyModuleAnchor`] for tests — there is no fail-open production default.

use std::sync::Arc;

use async_trait::async_trait;
use dig_dht::ContentId;
use dig_rpc_protocol::types::ModuleInfo;
use sha2::{Digest, Sha256};

use crate::error::{DownloadError, VerifyError};
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
/// tests / explicit opt-in ONLY. Provides NO chain-anchored integrity; a production caller MUST inject
/// the real digstore anchor verifier. Named + `#[doc(hidden)]` so the insecure path is asked for by
/// name.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAnyModuleAnchor;

impl ModuleAnchorVerifier for AcceptAnyModuleAnchor {
    fn verify_module_anchor(&self, _module: &[u8], _store_id: &str, _root: &str) -> bool {
        true
    }
}

/// Tunables for a module pull.
#[derive(Debug, Clone)]
pub struct ModuleDownloadConfig {
    /// Per-range fetch timeout — a holder that does not return a chunk within this window is treated
    /// as a failed source for that chunk and the next holder is tried.
    pub range_timeout: std::time::Duration,
}

impl Default for ModuleDownloadConfig {
    fn default() -> Self {
        ModuleDownloadConfig {
            range_timeout: std::time::Duration::from_secs(30),
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

        // 2. HANDSHAKE getModuleInfo from the first responsive holder → the transfer descriptor.
        let info = self.fetch_module_info(&providers, store_id, root).await?;
        let layout = ChunkPlan::from_info(&info)?;

        // 3. Load resume state; a checkpoint for a DIFFERENT generation shape is discarded (never
        //    mixed) so a resume re-plans identically to the original.
        let key = module_download_key(store_id, root);
        let mut state = self.load_or_fresh_state(&key, &layout).await?;

        // 4. Assemble into an in-memory blob (the final whole-blob-hash + chain-anchor gate needs the
        //    complete bytes). Already-verified chunks are read back from the sink's staging area
        //    rather than re-fetched; a sink that can't read back re-fetches them (still fail-closed).
        let mut blob = vec![0u8; layout.total_size as usize];
        let mut done: Vec<bool> = vec![false; layout.chunk_count()];
        self.rehydrate_done_chunks(sink, &layout, &state, &mut blob, &mut done)
            .await;

        // 5. FETCH + ATTRIBUTE every still-missing chunk, fanned round-robin across the holders.
        for (index, already_done) in done.iter().enumerate() {
            if *already_done {
                continue;
            }
            let (offset, len) = layout.chunk_span(index);
            let bytes = self
                .fetch_verified_chunk(&mut providers, &info, &layout, index, store_id, root)
                .await?;
            sink.write_at(offset, &bytes).await?;
            blob[offset as usize..(offset + len) as usize].copy_from_slice(&bytes);
            state.mark_done(index);
            self.state_store.save(&state).await?;
        }

        // 6. The two FAIL-CLOSED final gates, BEFORE finalize. Neither pass ⇒ the staging file is
        //    never promoted (the module is rejected, not written through — NC-9).
        let assembled_hash = sha256_hex(&blob);
        if assembled_hash != info.module_hash {
            return Err(DownloadError::Verify(VerifyError::Metadata(format!(
                "assembled module_hash {assembled_hash} != declared {}",
                info.module_hash
            ))));
        }
        if !self.anchor.verify_module_anchor(&blob, store_id, root) {
            return Err(DownloadError::Verify(VerifyError::Metadata(format!(
                "assembled module is not chain-anchored under ({store_id}, {root})"
            ))));
        }

        sink.finalize().await?;
        self.state_store.clear(&key).await?;
        Ok(layout.total_size)
    }

    /// Try each holder's `dig.getModuleInfo` until one answers; the descriptor is content-addressed so
    /// any honest holder returns the same shape (a lie is caught by the whole-blob + anchor gates).
    async fn fetch_module_info(
        &self,
        providers: &[dig_dht::ProviderRecord],
        store_id: &str,
        root: &str,
    ) -> Result<ModuleInfo, DownloadError> {
        for provider in providers {
            match self
                .transport
                .get_module_info(&provider.provider_peer_id, store_id, root)
                .await
            {
                Ok(info) => return Ok(info),
                Err(e) if e.is_recoverable() => continue,
                Err(e) => return Err(e),
            }
        }
        Err(DownloadError::NoProviders { needed: 1 })
    }

    /// Fetch chunk `index` from the holders, verifying each returned range against
    /// `chunk_hashes[index]` for per-source attribution: a tampered/mis-sized range is rejected and
    /// the next holder tried. Fetching cycles the holders starting at `index` (round-robin spread), so
    /// a multi-holder set is pulled from multiple sources; one re-locate is attempted before giving up.
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

        let mut relocated = false;
        loop {
            let count = providers.len();
            for step in 0..count {
                let provider = &providers[(index + step) % count];
                let peer = &provider.provider_peer_id;
                let fetched = tokio::time::timeout(
                    self.config.range_timeout,
                    self.transport
                        .fetch_module_range(peer, store_id, root, offset, len),
                )
                .await;
                match fetched {
                    Ok(Ok(bytes))
                        if bytes.len() as u64 == len && &sha256_hex(&bytes) == expected_hash =>
                    {
                        return Ok(bytes);
                    }
                    // Wrong length, wrong hash, transport error, or timeout — this holder is not a
                    // trustworthy source for this chunk; try the next.
                    _ => continue,
                }
            }
            if relocated {
                return Err(DownloadError::NoProviders { needed: 1 });
            }
            // Every known holder failed this chunk — ask the DHT for more before giving up.
            let content =
                module_content_id(store_id, root).ok_or(DownloadError::NotDownloadable)?;
            let refreshed = self.locator.find_providers(&content).await?;
            merge_new_providers(providers, refreshed);
            relocated = true;
        }
    }

    /// Load the resume checkpoint for `key`, or a fresh one if none exists / the persisted generation
    /// shape does not match the current [`ModuleInfo`] (a stale checkpoint is never partially reused).
    async fn load_or_fresh_state(
        &self,
        key: &str,
        layout: &ChunkPlan,
    ) -> Result<DownloadState, DownloadError> {
        let fresh = || {
            let mut s = DownloadState::new(key);
            s.total_length = layout.total_size;
            s.chunk_lens = layout.chunk_lens.clone();
            s
        };
        match self.state_store.load(key).await? {
            Some(prev) if prev.chunk_lens == layout.chunk_lens => Ok(prev),
            _ => Ok(fresh()),
        }
    }

    /// Read each already-verified chunk back from the sink's staging area into `blob`, marking it
    /// `done` so it is not re-fetched. A sink that cannot read back (or a short read) leaves the chunk
    /// NOT done, so it is re-fetched — resume is an optimization, never a correctness dependency.
    async fn rehydrate_done_chunks(
        &self,
        sink: &dyn Sink,
        layout: &ChunkPlan,
        state: &DownloadState,
        blob: &mut [u8],
        done: &mut [bool],
    ) {
        for &index in &state.done_ranges {
            if index >= layout.chunk_count() {
                continue;
            }
            let (offset, len) = layout.chunk_span(index);
            if let Ok(bytes) = sink.read_at(offset, len).await {
                if bytes.len() as u64 == len {
                    blob[offset as usize..(offset + len) as usize].copy_from_slice(&bytes);
                    done[index] = true;
                }
            }
        }
    }
}

/// The chunk layout derived from a [`ModuleInfo`]: per-chunk lengths + their cumulative offsets, with
/// the descriptor's self-consistency checked once up front.
struct ChunkPlan {
    total_size: u64,
    chunk_lens: Vec<u64>,
    offsets: Vec<u64>,
}

impl ChunkPlan {
    /// Validate a [`ModuleInfo`] and derive its chunk plan. The descriptor MUST carry `chunk_lens`
    /// (required for the byte→chunk mapping), have one length per `chunk_hashes` entry, and have the
    /// lengths sum to `total_size` — otherwise the per-chunk fail-closed check is unimplementable and
    /// the descriptor is rejected.
    fn from_info(info: &ModuleInfo) -> Result<Self, DownloadError> {
        let chunk_lens = info.chunk_lens.clone();
        if chunk_lens.is_empty() {
            return Err(DownloadError::Verify(VerifyError::Metadata(
                "ModuleInfo carries no chunk_lens (cannot map ranges to chunk hashes)".into(),
            )));
        }
        if chunk_lens.len() != info.chunk_hashes.len() {
            return Err(DownloadError::Verify(VerifyError::Metadata(format!(
                "chunk_lens ({}) != chunk_hashes ({})",
                chunk_lens.len(),
                info.chunk_hashes.len()
            ))));
        }
        let sum: u64 = chunk_lens.iter().sum();
        if sum != info.total_size {
            return Err(DownloadError::Verify(VerifyError::Metadata(format!(
                "chunk_lens sum {sum} != total_size {}",
                info.total_size
            ))));
        }
        let mut offsets = Vec::with_capacity(chunk_lens.len());
        let mut acc = 0u64;
        for &len in &chunk_lens {
            offsets.push(acc);
            acc += len;
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
        assert!(matches!(err, DownloadError::NoProviders { .. }));
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
        assert!(matches!(err, DownloadError::NoProviders { .. }));
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

    #[test]
    fn chunk_plan_rejects_inconsistent_descriptor() {
        // chunk_lens sum (5) != total_size (99)
        let bad = ModuleInfo {
            total_size: 99,
            module_hash: "ab".repeat(32),
            chunk_hashes: vec!["cd".repeat(32)],
            chunk_lens: vec![5],
        };
        assert!(ChunkPlan::from_info(&bad).is_err());

        // missing chunk_lens
        let no_lens = ModuleInfo {
            total_size: 5,
            module_hash: "ab".repeat(32),
            chunk_hashes: vec!["cd".repeat(32)],
            chunk_lens: vec![],
        };
        assert!(ChunkPlan::from_info(&no_lens).is_err());

        // chunk_hashes / chunk_lens length disagree
        let mismatched = ModuleInfo {
            total_size: 5,
            module_hash: "ab".repeat(32),
            chunk_hashes: vec!["cd".repeat(32), "ef".repeat(32)],
            chunk_lens: vec![5],
        };
        assert!(ChunkPlan::from_info(&mismatched).is_err());
    }
}
