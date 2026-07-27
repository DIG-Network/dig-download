//! In-memory test doubles for driving a [`Downloader`](crate::Downloader) with NO real network — a
//! mock [`ProviderLocator`] and a mock [`RangeTransport`] over a known "true" resource, with per-
//! provider misbehaviour (corrupt / truncated / dropping / unavailable sources).
//!
//! Used by this crate's own tests, and exported so a consumer (e.g. dig-node) can unit-test its
//! download wiring the same way. The doubles model the L7 peer network faithfully enough to exercise
//! the whole orchestrator: multi-source concurrent fan-out, per-range verification + bad-source
//! refetch, mid-download source drop + rebalance, provider-set refresh, and pause/resume.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use dig_dht::{CandidateAddr, ContentId, PeerId, ProviderRecord};
use dig_nat::{AvailabilityAnswer, AvailabilityItem, AvailabilityResponse};
use dig_rpc_protocol::types::ModuleInfo;
use tokio::sync::Mutex;

use crate::error::DownloadError;
use crate::locate::ProviderLocator;
use crate::select::{RangeOutcome, SelectPlan, SelectRequest, SourceSelector};
use crate::source::{FetchedRange, RangeMeta, RangeTransport};

/// The known "true" content the mock transport serves: the resource ciphertext + its chunk layout +
/// the chain-anchored metadata. A test builds one and asserts a download reproduces `bytes` exactly.
#[derive(Debug, Clone)]
pub struct MockContent {
    /// The full resource ciphertext an honest provider serves.
    pub bytes: Vec<u8>,
    /// The per-chunk ciphertext lengths (must sum to `bytes.len()`).
    pub chunk_lens: Vec<u64>,
    /// The chain-anchored generation root (64-hex) reported in each range's first frame.
    pub root: String,
    /// The whole-resource inclusion proof (base64), or `None` for a capsule.
    pub inclusion_proof: Option<String>,
    offsets: Vec<u64>,
    /// A DECLARED first-frame `(total_length, chunk_lens)` that does not describe `bytes` at all — see
    /// [`declaring`](Self::declaring).
    declared_layout: Option<(u64, Vec<u64>)>,
}

impl MockContent {
    /// Build content from raw bytes + chunk lengths (which must sum to `bytes.len()`).
    pub fn new(bytes: Vec<u8>, chunk_lens: Vec<u64>) -> Self {
        assert_eq!(
            bytes.len() as u64,
            chunk_lens.iter().sum::<u64>(),
            "chunk_lens must sum to bytes.len()"
        );
        let mut offsets = Vec::with_capacity(chunk_lens.len() + 1);
        let mut acc = 0u64;
        offsets.push(0);
        for &l in &chunk_lens {
            acc += l;
            offsets.push(acc);
        }
        MockContent {
            bytes,
            chunk_lens,
            root: "ab".repeat(32),
            inclusion_proof: Some("mock-proof".into()),
            offsets,
            declared_layout: None,
        }
    }

    /// Report `(total_length, chunk_lens)` in every first frame while still serving only the real
    /// `bytes` — a peer whose DECLARED resource shape is a lie.
    ///
    /// The declared shape is what sizes the client: the plan, and the range assembler's buffer. So this
    /// is the double needed to express "declares 1 TiB, sends 64 bytes", which no amount of honest
    /// content can model (`new` requires the lengths to describe the bytes). A misbehaviour double that
    /// cannot state the attack defends nothing.
    pub fn declaring(mut self, total_length: u64, chunk_lens: Vec<u64>) -> Self {
        self.declared_layout = Some((total_length, chunk_lens));
        self
    }

    /// Evenly-chunked content of `n` bytes in `chunks` chunks (last chunk takes the remainder) —
    /// convenience for tests.
    pub fn even(n: usize, chunks: usize) -> Self {
        let chunks = chunks.max(1);
        let base = n / chunks;
        let mut lens = vec![base as u64; chunks];
        let assigned: u64 = lens.iter().sum();
        if let Some(last) = lens.last_mut() {
            *last += n as u64 - assigned;
        }
        let bytes: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        MockContent::new(bytes, lens)
    }

    fn chunk_index_at(&self, offset: u64) -> u64 {
        self.offsets.iter().position(|&o| o == offset).unwrap_or(0) as u64
    }

    fn meta(&self, offset: u64) -> RangeMeta {
        let (total_length, chunk_lens) = match &self.declared_layout {
            Some((declared_total, declared_lens)) => (*declared_total, declared_lens.clone()),
            None => (self.bytes.len() as u64, self.chunk_lens.clone()),
        };
        RangeMeta {
            total_length: Some(total_length),
            chunk_lens: Some(chunk_lens),
            chunk_index: Some(self.chunk_index_at(offset)),
            root: Some(self.root.clone()),
            inclusion_proof: self.inclusion_proof.clone(),
        }
    }
}

/// How one provider (mock source) behaves when asked for a range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Behavior {
    /// Serves correct bytes for every range (a good peer).
    Honest,
    /// Returns right-length but wrong (bit-flipped) bytes — passes the per-range length check but
    /// fails the whole-resource root binding (needs a real proof verifier to catch).
    Corrupt,
    /// Returns one byte short — caught immediately by the per-range length/alignment check.
    Truncate,
    /// Returns a boundary-aligned SHORT range: only the FIRST whole chunk of a multi-chunk range,
    /// so the bytes still start AND end on a chunk boundary. This defeats a purely structural
    /// alignment check (the short prefix is chunk-aligned) and is caught only by a per-range LENGTH
    /// check comparing `bytes.len()` to the requested `range.length` (the CRITICAL #179 finding).
    ShortAligned,
    /// Availability says "not held" and every fetch errors (a peer that does not have the content).
    Unavailable,
    /// Honest for the first `n` successful fetches, then every fetch errors — models a peer dropping
    /// mid-download so its ranges must rebalance to others.
    DropAfter(usize),
    /// Every fetch errors (a dead/unreachable peer).
    AlwaysFail,
    /// Serves correct-length bytes but reports a DIFFERENT generation `root` in the first-frame
    /// metadata than the content-id's root — a peer trying to shape the commitment to a different
    /// (attacker-chosen) generation. Must be rejected before the commitment is adopted (HIGH #179).
    WrongRoot,
}

/// A mock [`RangeTransport`] serving [`MockContent`] with per-provider [`Behavior`], recording fetch
/// attempts so tests can assert scheduling (which ranges went where, how often, and that resumed
/// ranges are not re-fetched).
pub struct MockRangeTransport {
    content: MockContent,
    behaviors: Mutex<HashMap<String, Behavior>>,
    provider_attempts: Mutex<HashMap<String, usize>>,
    offset_attempts: Mutex<HashMap<u64, usize>>,
    delay: Mutex<Option<std::time::Duration>>,
}

impl MockRangeTransport {
    /// A transport serving `content`; every provider is [`Behavior::Honest`] unless overridden.
    pub fn new(content: MockContent) -> Self {
        MockRangeTransport {
            content,
            behaviors: Mutex::new(HashMap::new()),
            provider_attempts: Mutex::new(HashMap::new()),
            offset_attempts: Mutex::new(HashMap::new()),
            delay: Mutex::new(None),
        }
    }

    /// Add an artificial per-fetch delay (so a test can reliably pause a download mid-flight).
    pub async fn set_delay(&self, delay: std::time::Duration) {
        *self.delay.lock().await = Some(delay);
    }

    /// Set `peer_id`'s behaviour (default [`Behavior::Honest`]).
    pub async fn set_behavior(&self, peer_id: &str, behavior: Behavior) {
        self.behaviors
            .lock()
            .await
            .insert(peer_id.to_string(), behavior);
    }

    /// Total fetch attempts made against `peer_id`.
    pub async fn attempts_for(&self, peer_id: &str) -> usize {
        self.provider_attempts
            .lock()
            .await
            .get(peer_id)
            .copied()
            .unwrap_or(0)
    }

    /// Total fetch attempts made for the range starting at `offset` (0 means never fetched — used to
    /// assert a resumed/verified range was NOT re-fetched).
    pub async fn attempts_at(&self, offset: u64) -> usize {
        self.offset_attempts
            .lock()
            .await
            .get(&offset)
            .copied()
            .unwrap_or(0)
    }

    async fn behavior(&self, peer_id: &str) -> Behavior {
        self.behaviors
            .lock()
            .await
            .get(peer_id)
            .cloned()
            .unwrap_or(Behavior::Honest)
    }
}

#[async_trait]
impl RangeTransport for MockRangeTransport {
    async fn query_availability(
        &self,
        provider: &ProviderRecord,
        items: Vec<AvailabilityItem>,
    ) -> Result<AvailabilityResponse, DownloadError> {
        let behavior = self.behavior(&provider.provider_peer_id).await;
        let held = !matches!(behavior, Behavior::Unavailable | Behavior::AlwaysFail);
        let answers = items
            .iter()
            .map(|_| {
                let answer = if held {
                    AvailabilityAnswer::available()
                } else {
                    AvailabilityAnswer::unavailable()
                };
                answer
                    .with_roots(vec![self.content.root.clone()])
                    .with_total_length(self.content.bytes.len() as u64)
                    .with_chunk_count(self.content.chunk_lens.len() as u64)
                    .with_complete(true)
            })
            .collect();
        Ok(AvailabilityResponse::new(answers))
    }

    async fn fetch_range(
        &self,
        provider: &ProviderRecord,
        req: &dig_nat::RangeRequest,
    ) -> Result<FetchedRange, DownloadError> {
        let peer = provider.provider_peer_id.clone();
        let attempts = {
            let mut a = self.provider_attempts.lock().await;
            let n = a.entry(peer.clone()).or_insert(0);
            *n += 1;
            *n
        };
        *self
            .offset_attempts
            .lock()
            .await
            .entry(req.offset)
            .or_insert(0) += 1;

        if let Some(d) = *self.delay.lock().await {
            tokio::time::sleep(d).await;
        }

        let behavior = self.behavior(&peer).await;
        let fail = || DownloadError::transport(&peer, "mock: source failed");
        match behavior {
            Behavior::Unavailable | Behavior::AlwaysFail => return Err(fail()),
            Behavior::DropAfter(n) if attempts > n => return Err(fail()),
            _ => {}
        }

        let start = req.offset as usize;
        let end = (req.offset + req.length).min(self.content.bytes.len() as u64) as usize;
        let mut bytes = self.content.bytes[start..end].to_vec();
        match behavior {
            Behavior::Truncate => {
                bytes.pop(); // one byte short → per-range length check fails
            }
            Behavior::Corrupt => {
                for b in bytes.iter_mut() {
                    *b ^= 0xFF; // right length, wrong content → fails whole-resource root binding
                }
            }
            Behavior::ShortAligned => {
                // Serve only the FIRST whole chunk of the requested range. The result still starts
                // and ends on a chunk boundary (so a purely structural alignment check passes) but
                // is shorter than req.length — the CRITICAL boundary-aligned-short case.
                let first_chunk_idx = self.content.chunk_index_at(req.offset) as usize;
                if let Some(&first_len) = self.content.chunk_lens.get(first_chunk_idx) {
                    let keep = (first_len as usize).min(bytes.len());
                    if keep < bytes.len() {
                        bytes.truncate(keep);
                    }
                }
            }
            _ => {}
        }
        let mut meta = self.content.meta(req.offset);
        if matches!(behavior, Behavior::WrongRoot) {
            // Report a root that differs from both the honest content root and the content-id root.
            meta.root = Some("cd".repeat(32));
        }
        Ok(FetchedRange {
            request_offset: req.offset,
            bytes,
            meta,
        })
    }
}

/// A mock [`ProviderLocator`] returning a scripted sequence of provider batches — the first
/// `find_providers` returns batch 0, the next returns batch 1, etc. (the last batch repeats). Lets a
/// test model "the initial holders all failed; a re-locate discovers a fresh one".
pub struct MockProviderLocator {
    batches: Vec<Vec<ProviderRecord>>,
    calls: Mutex<usize>,
}

impl MockProviderLocator {
    /// A locator that always returns the same `providers`.
    pub fn fixed(providers: Vec<ProviderRecord>) -> Self {
        MockProviderLocator {
            batches: vec![providers],
            calls: Mutex::new(0),
        }
    }

    /// A locator returning `batches[0]`, then `batches[1]`, … on successive calls (last repeats).
    pub fn scripted(batches: Vec<Vec<ProviderRecord>>) -> Self {
        MockProviderLocator {
            batches: if batches.is_empty() {
                vec![vec![]]
            } else {
                batches
            },
            calls: Mutex::new(0),
        }
    }

    /// How many times `find_providers` has been called (to assert a re-locate happened).
    pub async fn call_count(&self) -> usize {
        *self.calls.lock().await
    }
}

#[async_trait]
impl ProviderLocator for MockProviderLocator {
    async fn find_providers(
        &self,
        _content: &ContentId,
    ) -> Result<Vec<ProviderRecord>, DownloadError> {
        let mut calls = self.calls.lock().await;
        let idx = (*calls).min(self.batches.len() - 1);
        *calls += 1;
        Ok(self.batches[idx].clone())
    }
}

/// A recording mock [`SourceSelector`] — proves dig-download DELEGATES peer choice (calls `select`)
/// and reports every range outcome (`record`), keeping NO ranking of its own.
///
/// By default it echoes the candidate set back in the order given (a pass-through order). A test can
/// pin an explicit preference order via [`with_order`](Self::with_order) to assert dig-download honors
/// the selector's choice, and inspect the recorded [`RangeOutcome`]s + `select` call count.
#[derive(Default)]
pub struct MockSelector {
    select_calls: AtomicUsize,
    // std (not tokio) mutex: `select`/`record` are SYNC trait methods invoked from async scheduler
    // code, where a tokio `blocking_lock` would panic. The critical sections are trivial + non-await.
    recorded: std::sync::Mutex<Vec<RangeOutcome>>,
    forced_order: std::sync::Mutex<Option<Vec<String>>>,
}

impl MockSelector {
    /// A pass-through selector (echoes the candidates in the order the scheduler offers them).
    pub fn new() -> Arc<Self> {
        Arc::new(MockSelector::default())
    }

    /// A selector that always prefers `order` (peer_ids best-first); any offered candidate absent from
    /// `order` is appended after, so the plan still covers every live candidate.
    pub fn with_order(order: Vec<String>) -> Arc<Self> {
        let sel = MockSelector::default();
        *sel.forced_order.lock().unwrap() = Some(order);
        Arc::new(sel)
    }

    /// How many times [`SourceSelector::select`] has been called (proves dig-download consults the
    /// selector rather than ranking internally).
    pub fn select_call_count(&self) -> usize {
        self.select_calls.load(Ordering::Relaxed)
    }

    /// A snapshot of every [`RangeOutcome`] reported so far (peer, bytes, elapsed, result).
    pub fn outcomes(&self) -> Vec<RangeOutcome> {
        self.recorded.lock().unwrap().clone()
    }
}

impl SourceSelector for MockSelector {
    fn select(&self, req: &SelectRequest) -> SelectPlan {
        self.select_calls.fetch_add(1, Ordering::Relaxed);
        let offered: Vec<String> = req.candidates.iter().map(|c| c.peer_id.clone()).collect();
        match self.forced_order.lock().unwrap().as_ref() {
            Some(order) => {
                // Preferred peers that are actually offered, then any remaining offered peers.
                let mut plan: Vec<String> = order
                    .iter()
                    .filter(|p| offered.contains(p))
                    .cloned()
                    .collect();
                for p in &offered {
                    if !plan.contains(p) {
                        plan.push(p.clone());
                    }
                }
                SelectPlan::ordered(plan)
            }
            None => SelectPlan::ordered(offered),
        }
    }

    fn record(&self, outcome: &RangeOutcome) {
        self.recorded.lock().unwrap().push(outcome.clone());
    }
}

/// Build a mock provider record for a peer numbered `n`, holding `content`, at a dummy direct address.
pub fn mock_provider(n: u8, content: &ContentId) -> ProviderRecord {
    ProviderRecord::new(
        &content.to_key(),
        &PeerId::from_bytes([n; 32]),
        vec![CandidateAddr::direct(format!("10.0.0.{n}"), 9444)],
        u64::MAX,
    )
}

/// The 64-hex `peer_id` of the mock provider numbered `n` (to key behaviours/assertions).
pub fn mock_peer_hex(n: u8) -> String {
    PeerId::from_bytes([n; 32]).to_hex()
}

/// Build a mock provider record carrying an ARBITRARY `provider_peer_id` string, bypassing the
/// [`ProviderRecord::new`] canonicalization the way a record deserialized straight off the wire does.
///
/// `ProviderRecord::provider_peer_id` is a plain `String`, so a hostile peer can publish any text it
/// likes there. Tests use this to prove that peer-supplied text never reaches a log/error verbatim
/// (#1603).
pub fn mock_provider_with_peer_id(peer_id: &str, content: &ContentId) -> ProviderRecord {
    let mut record = mock_provider(1, content);
    record.provider_peer_id = peer_id.to_string();
    record
}

/// A throwaway content id (resource granularity) for tests. Its generation `root` is `[0xAB; 32]`
/// (hex `"ab".repeat(32)`) so it MATCHES the root [`MockContent`] reports in each range's first
/// frame — the orchestrator cross-checks the peer-reported root against the content-id root
/// (HIGH #179), so the two must agree for an honest download to proceed.
pub fn mock_content_id() -> ContentId {
    ContentId::resource([1; 32], [0xAB; 32], [3; 32])
}

// ===========================================================================
// Whole-`.dig`-module pull doubles (#1576) — drive a `ModuleDownloader` with NO real network.
// ===========================================================================

/// An in-memory [`ModuleTransport`](crate::module::ModuleTransport) over a known "true" module blob:
/// it answers `dig.getModuleInfo` with the blob's descriptor and `dig.fetchModuleRange` with the
/// requested window — with configurable per-holder misbehaviour (a holder that TAMPERS a chunk, a
/// success BUDGET that starves the pull mid-way to model an interrupt, and a corrupted whole-blob
/// `module_hash`) so a test can exercise the fail-closed + resume paths. Every fetch is recorded as
/// `(peer_id, offset)` so a test can assert the pull was MULTI-SOURCE and did not re-fetch a resumed
/// chunk.
pub struct MockModuleTransport {
    store_id: String,
    root: String,
    blob: Vec<u8>,
    chunk_size: usize,
    tamper_peer: Option<String>,
    corrupt_module_hash: bool,
    overserve: bool,
    declared_total_size: Option<u64>,
    inflating_peer: Option<(String, u64)>,
    wrong_descriptor_for: Option<String>,
    alternate_module_for: Option<(String, Vec<u8>)>,
    fabricated_chunk_hashes_for: Option<String>,
    one_byte_liar: Option<String>,
    budget: Option<Arc<AtomicUsize>>,
    fetches: Mutex<Vec<(String, u64)>>,
    info_calls: Mutex<Vec<String>>,
}

impl MockModuleTransport {
    /// A transport serving `blob` for `(store_id, root)` split into `chunk_size`-byte chunks, with no
    /// misbehaviour.
    pub fn serving(store_id: &str, root: &str, blob: Vec<u8>, chunk_size: usize) -> Self {
        MockModuleTransport {
            store_id: store_id.to_string(),
            root: root.to_string(),
            blob,
            chunk_size,
            tamper_peer: None,
            corrupt_module_hash: false,
            overserve: false,
            declared_total_size: None,
            inflating_peer: None,
            wrong_descriptor_for: None,
            alternate_module_for: None,
            fabricated_chunk_hashes_for: None,
            one_byte_liar: None,
            budget: None,
            fetches: Mutex::new(Vec::new()),
            info_calls: Mutex::new(Vec::new()),
        }
    }

    /// Every `fetchModuleRange` answers with MORE bytes than the requested window (the whole enclosing
    /// chunk plus the following one, where the blob allows it) — the legitimate chunk-granular server
    /// of the §2.2 clip contract, NOT a liar. A puller must CLIP to the requested window and keep
    /// using this holder (#836 / dig-download 0.7.4).
    pub fn overserving(mut self) -> Self {
        self.overserve = true;
        self
    }

    /// `getModuleInfo` declares `total_size` (and a matching final `chunk_lens` entry) far larger than
    /// the bytes actually served — models a hostile descriptor whose declared size would drive the
    /// puller's assembly buffer allocation.
    pub fn declaring_total_size(mut self, total_size: u64) -> Self {
        self.declared_total_size = Some(total_size);
        self
    }

    /// ONLY `peer_id` declares `total_size` (with a matching inflated FINAL `chunk_len`, so the
    /// descriptor stays self-consistent) while every other holder answers honestly.
    ///
    /// The per-peer version of [`declaring_total_size`](Self::declaring_total_size), and the double a
    /// RECOVERY test needs: with every holder inflating, a puller that dies instead of trying the next
    /// descriptor is indistinguishable from one that retries correctly. About 100 bytes on the wire buys
    /// the attack, so the puller must route around it, not surrender to it.
    pub fn inflating_total_size_from(mut self, peer_id: &str, total_size: u64) -> Self {
        self.inflating_peer = Some((peer_id.to_string(), total_size));
        self
    }

    /// This holder serves corrupted bytes for every chunk (flips the first byte) — models a lying
    /// source a puller must reject + route around.
    pub fn tampering(mut self, peer_id: &str) -> Self {
        self.tamper_peer = Some(peer_id.to_string());
        self
    }

    /// `getModuleInfo` reports a wrong whole-blob `module_hash` (per-chunk hashes stay honest) — models
    /// a descriptor that passes every per-chunk check yet fails the whole-blob gate.
    pub fn with_corrupt_module_hash(mut self) -> Self {
        self.corrupt_module_hash = true;
        self
    }

    /// ONLY `peer_id`'s `getModuleInfo` answers with a WELL-FORMED but WRONG descriptor (honest
    /// per-chunk hashes + lengths, a wrong whole-blob `module_hash`), while every other holder answers
    /// honestly — models the descriptor-source attack: one holder winning the `getModuleInfo` race can
    /// otherwise deny the pull permanently even though honest holders are present.
    pub fn lying_descriptor_from(mut self, peer_id: &str) -> Self {
        self.wrong_descriptor_for = Some(peer_id.to_string());
        self
    }

    /// ONLY `peer_id` answers BOTH module calls out of a wholly FABRICATED alternate `module` —
    /// a self-consistent descriptor (its own `total_size`, `chunk_lens`, `chunk_hashes` and
    /// `module_hash`) plus bytes that match it — while every other holder serves the real blob.
    ///
    /// This is the descriptor liar that survives every per-chunk check AND the whole-blob hash gate,
    /// dying only at the chain-anchor gate. When the fabricated module is LARGER than the real one it
    /// is also the cache-poisoning probe: the pull stages the long fabrication, then re-pulls a
    /// SHORTER honest module, so the promoted artifact must be proven equal to the verified one.
    pub fn serving_alternate_module_from(mut self, peer_id: &str, module: Vec<u8>) -> Self {
        self.alternate_module_for = Some((peer_id.to_string(), module));
        self
    }

    /// ONLY `peer_id` answers `getModuleInfo` with FABRICATED `chunk_hashes` (honest lengths + total,
    /// so the descriptor is well-formed) and then serves NO bytes at all.
    ///
    /// The cheapest reshare-denial liar: nobody can satisfy those chunk hashes, so the pull EXHAUSTS
    /// its holders on chunk 0 and never reaches a final gate — the descriptor source must still be
    /// demoted and another holder's descriptor tried.
    pub fn fabricating_chunk_hashes_from(mut self, peer_id: &str) -> Self {
        self.fabricated_chunk_hashes_for = Some(peer_id.to_string());
        self
    }

    /// ONLY `peer_id` answers `getModuleInfo` with a descriptor split as `chunk_lens = [1, rest]`
    /// whose FIRST chunk hash is honest (the blob's real first byte) and whose SECOND is fabricated,
    /// then serves that ONE byte and refuses every other window.
    ///
    /// This is the ONE-BYTE bypass of a "was any chunk verified?" bound: the liar pays a single byte to
    /// make the pull look credible, then starves it. Every other holder answers honestly, so a puller
    /// that demotes the descriptor source on exhaustion completes the pull from an honest descriptor —
    /// and one that only demotes when NO chunk verified dies with honest holders standing right there.
    pub fn serving_one_byte_then_refusing_from(mut self, peer_id: &str) -> Self {
        self.one_byte_liar = Some(peer_id.to_string());
        self
    }

    /// Only `n` `fetchModuleRange` calls succeed; the rest error — models an interrupt after partial
    /// progress so a test can assert resume re-fetches ONLY the missing chunks.
    pub fn with_success_budget(mut self, n: usize) -> Self {
        self.budget = Some(Arc::new(AtomicUsize::new(n)));
        self
    }

    /// A snapshot of every `(peer_id, offset)` served (to assert multi-source + no-refetch-on-resume).
    pub async fn fetches(&self) -> Vec<(String, u64)> {
        self.fetches.lock().await.clone()
    }

    /// The `peer_id` of every `getModuleInfo` handshake served, in order — so a test can assert a
    /// lying descriptor source was DEMOTED and a different holder re-handshaked.
    pub async fn module_info_calls(&self) -> Vec<String> {
        self.info_calls.lock().await.clone()
    }

    /// The honest, self-consistent descriptor of an arbitrary `module` blob at this transport's chunk
    /// size — no misbehaviour applied.
    fn descriptor_of(&self, module: &[u8]) -> ModuleInfo {
        let mut chunk_hashes = Vec::new();
        let mut chunk_lens = Vec::new();
        for chunk in module.chunks(self.chunk_size.max(1)) {
            chunk_hashes.push(hex_sha256(chunk));
            chunk_lens.push(chunk.len() as u64);
        }
        ModuleInfo {
            total_size: module.len() as u64,
            module_hash: hex_sha256(module),
            chunk_hashes,
            chunk_lens,
        }
    }

    /// The descriptor this transport reports for the real blob (the honest chunk layout + hashes,
    /// plus whichever descriptor misbehaviour was configured).
    fn descriptor(&self) -> ModuleInfo {
        let ModuleInfo {
            chunk_hashes,
            mut chunk_lens,
            ..
        } = self.descriptor_of(&self.blob);
        let module_hash = if self.corrupt_module_hash {
            "0".repeat(64)
        } else {
            hex_sha256(&self.blob)
        };
        // An inflated `total_size` is reported with a matching inflated FINAL chunk length, so the
        // descriptor stays internally self-consistent and the puller's size guard — not its
        // consistency check — is what has to catch it.
        let mut total_size = self.blob.len() as u64;
        if let Some(inflated) = self.declared_total_size {
            let last = chunk_lens.last_mut().expect("blob yields >= 1 chunk");
            *last += inflated.saturating_sub(total_size);
            total_size = inflated;
        }
        ModuleInfo {
            total_size,
            module_hash,
            chunk_hashes,
            chunk_lens,
        }
    }

    /// The honest descriptor with `total_size` inflated to `inflated` and the final `chunk_len` grown to
    /// match, so it stays internally self-consistent — the ~100-byte hostile descriptor whose declared
    /// size is what fails, not its shape.
    fn descriptor_inflated_to(&self, inflated: u64) -> ModuleInfo {
        let mut info = self.descriptor();
        let real_total = info.total_size;
        if let Some(last) = info.chunk_lens.last_mut() {
            *last += inflated.saturating_sub(real_total);
        }
        info.total_size = inflated;
        info
    }

    /// A self-consistent descriptor whose whole-blob `module_hash` is wrong — it plans + attributes
    /// every chunk correctly and only fails at the final whole-blob gate.
    fn lying_descriptor(&self) -> ModuleInfo {
        ModuleInfo {
            module_hash: "0".repeat(64),
            ..self.descriptor()
        }
    }

    /// A well-formed descriptor whose per-chunk hashes are FABRICATED (honest lengths, honest
    /// whole-blob hash) — no holder can ever satisfy it, so the pull exhausts its holders on the first
    /// chunk instead of reaching a final gate.
    fn fabricated_chunk_hash_descriptor(&self) -> ModuleInfo {
        let mut info = self.descriptor();
        info.chunk_hashes = info
            .chunk_hashes
            .iter()
            .enumerate()
            .map(|(i, _)| hex_sha256(format!("fabricated-chunk-{i}").as_bytes()))
            .collect();
        info
    }

    /// A descriptor split as `[1, rest]` whose first chunk hash is HONEST (so the real first byte
    /// satisfies it) and whose second is fabricated (so nothing can) — see
    /// [`serving_one_byte_then_refusing_from`](Self::serving_one_byte_then_refusing_from).
    fn one_byte_then_unsatisfiable_descriptor(&self) -> ModuleInfo {
        let rest = self.blob.len().saturating_sub(1) as u64;
        ModuleInfo {
            total_size: self.blob.len() as u64,
            module_hash: hex_sha256(&self.blob),
            chunk_hashes: vec![
                hex_sha256(&self.blob[..1]),
                hex_sha256(b"fabricated-second-chunk"),
            ],
            chunk_lens: vec![1, rest],
        }
    }

    /// The blob `provider_peer_id` serves bytes out of — the fabricated alternate module for the
    /// configured liar, the real blob for everyone else.
    fn served_blob(&self, provider_peer_id: &str) -> &[u8] {
        match &self.alternate_module_for {
            Some((peer, module)) if peer == provider_peer_id => module,
            _ => &self.blob,
        }
    }
}

#[async_trait]
impl crate::module::ModuleTransport for MockModuleTransport {
    async fn get_module_info(
        &self,
        provider_peer_id: &str,
        store_id: &str,
        root: &str,
    ) -> Result<ModuleInfo, DownloadError> {
        self.info_calls
            .lock()
            .await
            .push(provider_peer_id.to_string());
        if store_id != self.store_id || root != self.root {
            // The crate's OWN idiom stamps the raw `provider_peer_id` into the error (see
            // `source.rs`), and the real sub-family-4 adapter will mirror it — so the mock must too,
            // or the #1603 sentinel test defends nothing.
            return Err(DownloadError::transport(
                provider_peer_id,
                "unknown (store_id, root)",
            ));
        }
        if let Some(wrong) = self.wrong_descriptor_for.as_deref() {
            if wrong == provider_peer_id {
                return Ok(self.lying_descriptor());
            }
        }
        if let Some(fabricator) = self.fabricated_chunk_hashes_for.as_deref() {
            if fabricator == provider_peer_id {
                return Ok(self.fabricated_chunk_hash_descriptor());
            }
        }
        if let Some((peer, module)) = &self.alternate_module_for {
            if peer == provider_peer_id {
                return Ok(self.descriptor_of(module));
            }
        }
        if self.one_byte_liar.as_deref() == Some(provider_peer_id) {
            return Ok(self.one_byte_then_unsatisfiable_descriptor());
        }
        if let Some((peer, inflated)) = &self.inflating_peer {
            if peer == provider_peer_id {
                return Ok(self.descriptor_inflated_to(*inflated));
            }
        }
        Ok(self.descriptor())
    }

    async fn fetch_module_range(
        &self,
        provider_peer_id: &str,
        _store_id: &str,
        _root: &str,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, DownloadError> {
        if let Some(budget) = &self.budget {
            // `fetch_sub` returns the PREVIOUS value; 0 means the budget was already spent.
            if budget.fetch_sub(1, Ordering::SeqCst) == 0 {
                budget.fetch_add(1, Ordering::SeqCst); // keep it pinned at 0
                return Err(DownloadError::transport(provider_peer_id, "budget spent"));
            }
        }
        self.fetches
            .lock()
            .await
            .push((provider_peer_id.to_string(), offset));

        if self.fabricated_chunk_hashes_for.as_deref() == Some(provider_peer_id) {
            // The cheapest liar spends NO bandwidth: it publishes a descriptor nobody can satisfy and
            // then serves nothing at all.
            return Err(DownloadError::transport(
                provider_peer_id,
                "serving nothing",
            ));
        }

        if self.one_byte_liar.as_deref() == Some(provider_peer_id) {
            // It pays exactly ONE byte — the real first byte, which its own descriptor commits to —
            // and refuses every other window.
            return if offset == 0 && length == 1 {
                Ok(self.blob[..1].to_vec())
            } else {
                Err(DownloadError::transport(
                    provider_peer_id,
                    "refusing everything after the first byte",
                ))
            };
        }

        let served = self.served_blob(provider_peer_id);
        let start = (offset as usize).min(served.len());
        let mut window = length as usize;
        if self.overserve {
            // Answer at chunk granularity beyond the request — the legitimate over-long frame.
            window += self.chunk_size.max(1);
        }
        let end = (start + window).min(served.len());
        let mut bytes = served[start..end].to_vec();
        if self.tamper_peer.as_deref() == Some(provider_peer_id) && !bytes.is_empty() {
            bytes[0] ^= 0xFF;
        }
        Ok(bytes)
    }
}

/// The 64-hex SHA-256 of `bytes` (test-side mirror of the puller's chunk/module content-id).
fn hex_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    out
}

/// A [`ModuleAnchorVerifier`](crate::module::ModuleAnchorVerifier) that REJECTS every blob — models
/// content that assembles + whole-blob-hashes cleanly yet is not the chain-anchored module.
#[derive(Debug, Clone, Copy, Default)]
pub struct RejectAllModuleAnchor;

impl crate::module::ModuleAnchorVerifier for RejectAllModuleAnchor {
    fn verify_module_anchor(
        &self,
        _module: &[u8],
        _store_id: &str,
        _root: &str,
    ) -> crate::module::ModuleAnchor {
        crate::module::ModuleAnchor::NotAnchored
    }
}

/// A [`ModuleAnchorVerifier`](crate::module::ModuleAnchorVerifier) that can never REACH an answer —
/// the chain source is down.
///
/// This is the double for the distinction a `bool` return could not express: an honest holder serving a
/// correct blob during a chain-source outage must NOT be branded a liar, because a durable verdict then
/// inverts the node's descriptor preference toward unremembered (sybil) peers for the whole reputation
/// TTL.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnreachableChainAnchor;

impl crate::module::ModuleAnchorVerifier for UnreachableChainAnchor {
    fn verify_module_anchor(
        &self,
        _module: &[u8],
        _store_id: &str,
        _root: &str,
    ) -> crate::module::ModuleAnchor {
        crate::module::ModuleAnchor::Unavailable("chain source unreachable".into())
    }
}

/// A [`ModuleAnchorVerifier`](crate::module::ModuleAnchorVerifier) that accepts EXACTLY one blob —
/// the genuine, chain-anchored module — and rejects every other, however self-consistent.
///
/// This is what the real chain-anchor gate does, so it is the double a test needs whenever a holder
/// fabricates a WHOLE module (a self-consistent descriptor plus matching bytes): such a fabrication
/// passes the per-chunk and whole-blob-hash checks and can only be caught here.
#[derive(Debug, Clone)]
pub struct OnlyThisModuleAnchor(Vec<u8>);

impl OnlyThisModuleAnchor {
    /// An anchor gate that accepts only `module`.
    pub fn new(module: Vec<u8>) -> Self {
        OnlyThisModuleAnchor(module)
    }
}

impl crate::module::ModuleAnchorVerifier for OnlyThisModuleAnchor {
    fn verify_module_anchor(
        &self,
        module: &[u8],
        _store_id: &str,
        _root: &str,
    ) -> crate::module::ModuleAnchor {
        if module == self.0.as_slice() {
            crate::module::ModuleAnchor::Anchored
        } else {
            crate::module::ModuleAnchor::NotAnchored
        }
    }
}

/// Build `n` mock holders (peers `1..=n`) of `content` — the multi-source holder set for a module pull.
pub fn mock_providers(n: u8, content: &ContentId) -> Vec<ProviderRecord> {
    (1..=n).map(|i| mock_provider(i, content)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn honest_transport_serves_correct_slice() {
        let content = MockContent::even(30, 3);
        let t = MockRangeTransport::new(content.clone());
        let cid = mock_content_id();
        let p = mock_provider(1, &cid);
        let req = dig_nat::RangeRequest::resource("s", "r", 10, 10);
        let got = t.fetch_range(&p, &req).await.unwrap();
        assert_eq!(got.bytes, content.bytes[10..20]);
        assert_eq!(got.meta.chunk_lens, Some(content.chunk_lens.clone()));
        assert_eq!(t.attempts_at(10).await, 1);
        assert_eq!(t.attempts_for(&mock_peer_hex(1)).await, 1);
    }

    #[tokio::test]
    async fn behaviors_corrupt_and_truncate() {
        let content = MockContent::even(30, 3);
        let cid = mock_content_id();
        let p = mock_provider(2, &cid);
        let hex = mock_peer_hex(2);

        let t = MockRangeTransport::new(content.clone());
        t.set_behavior(&hex, Behavior::Truncate).await;
        let req = dig_nat::RangeRequest::resource("s", "r", 0, 10);
        let got = t.fetch_range(&p, &req).await.unwrap();
        assert_eq!(got.bytes.len(), 9);

        let t2 = MockRangeTransport::new(content.clone());
        t2.set_behavior(&hex, Behavior::Corrupt).await;
        let got2 = t2.fetch_range(&p, &req).await.unwrap();
        assert_eq!(got2.bytes.len(), 10);
        assert_ne!(got2.bytes, content.bytes[0..10]);
    }

    #[tokio::test]
    async fn drop_after_fails_late() {
        let content = MockContent::even(30, 3);
        let cid = mock_content_id();
        let p = mock_provider(3, &cid);
        let hex = mock_peer_hex(3);
        let t = MockRangeTransport::new(content);
        t.set_behavior(&hex, Behavior::DropAfter(1)).await;
        let req = dig_nat::RangeRequest::resource("s", "r", 0, 10);
        assert!(t.fetch_range(&p, &req).await.is_ok()); // 1st ok
        assert!(t.fetch_range(&p, &req).await.is_err()); // 2nd drops
    }

    #[tokio::test]
    async fn unavailable_source_reports_not_held() {
        let content = MockContent::even(30, 3);
        let cid = mock_content_id();
        let p = mock_provider(4, &cid);
        let hex = mock_peer_hex(4);
        let t = MockRangeTransport::new(content);
        t.set_behavior(&hex, Behavior::Unavailable).await;
        let resp = t
            .query_availability(
                &p,
                vec![AvailabilityItem {
                    store_id: "s".into(),
                    root: None,
                    retrieval_key: None,
                }],
            )
            .await
            .unwrap();
        assert!(!resp.items[0].available);
    }

    #[tokio::test]
    async fn scripted_locator_advances_batches() {
        let cid = mock_content_id();
        let loc = MockProviderLocator::scripted(vec![
            vec![mock_provider(1, &cid)],
            vec![mock_provider(1, &cid), mock_provider(2, &cid)],
        ]);
        assert_eq!(loc.find_providers(&cid).await.unwrap().len(), 1);
        assert_eq!(loc.find_providers(&cid).await.unwrap().len(), 2);
        assert_eq!(loc.find_providers(&cid).await.unwrap().len(), 2); // last repeats
        assert_eq!(loc.call_count().await, 3);
    }
}
