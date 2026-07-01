//! [`Downloader`] + [`DownloadHandle`] — the public entry point and the concurrent scheduler that
//! turns "get me this content" into verified bytes in the node's store.
//!
//! Given a [`ContentId`], a download runs the normative multi-source flow (L7 §9):
//!
//! 1. **DISCOVER** — [`ProviderLocator::find_providers`](crate::locate::ProviderLocator) locates the
//!    holders.
//! 2. **AVAILABILITY** — `dig.getAvailability` confirms which holders actually have it (and seeds the
//!    total length); a meta-probe reads the whole-resource `chunk_lens` to establish the
//!    [`ResourceCommitment`].
//! 3. **PLAN** — the resource is partitioned into chunk-aligned [`Range`]s.
//! 4. **FAN OUT** — different ranges are fetched from different holders CONCURRENTLY over
//!    [`RangeTransport::fetch_range`](crate::source::RangeTransport), N in flight per source, topped
//!    up as sources finish.
//! 5. **VERIFY** — each range is verified independently as it arrives; a bad/short range is discarded
//!    and its source penalized.
//! 6. **RETRY / REBALANCE** — a failed, dropped, or unverifiable range is re-queued to another holder
//!    (bounded backoff via [`SourceTracker`]); when a still-needed range runs out of live holders the
//!    provider set is refreshed (`find_providers` again).
//! 7. **REASSEMBLE** — verified ranges are written to the [`Sink`] by offset; once whole + verified,
//!    the sink is finalized (a [`FileSink`](crate::sink::FileSink) atomically renames its
//!    `.download.tmp` onto the final path).
//!
//! Progress is a live [`DownloadEvent`] stream on the handle; [`pause`](DownloadHandle::pause) /
//! [`resume`](DownloadHandle::resume) / [`cancel`](DownloadHandle::cancel) drive it. Per-range
//! progress is checkpointed to a [`StateStore`], so a paused OR crashed download resumes and re-fetches
//! ONLY the still-missing ranges.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dig_dht::{ContentId, ProviderRecord};
use dig_nat::{AvailabilityItem, RangeRequest};
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::mpsc;

use crate::error::DownloadError;
use crate::gc::ActiveDownloads;
use crate::locate::ProviderLocator;
use crate::plan::{plan_ranges, Range, RangeState};
use crate::progress::{DownloadEvent, DownloadProgress, DownloadState, StateStore};
use crate::sink::Sink;
use crate::source::{FetchedRange, RangeTransport, SourceTracker};
use crate::verify::{ResourceCommitment, Verifier};

/// Tuning for a download's scheduler + integrity + backoff.
#[derive(Debug, Clone)]
pub struct DownloadConfig {
    /// Target range size in bytes (a range packs whole chunks up to this; the node fetch window). A
    /// range is always ≥ one whole chunk. Default 3 MiB (the L7 node window).
    pub window: u64,
    /// Max range fetches in flight across all sources.
    pub max_concurrency: usize,
    /// Max range fetches in flight to a single source (spread load; avoid head-of-line on one peer).
    pub max_inflight_per_source: usize,
    /// Base backoff after a source failure (doubles per consecutive failure, capped).
    pub base_backoff: Duration,
    /// Maximum backoff a source can accrue.
    pub max_backoff: Duration,
    /// Max `find_providers` refreshes before giving up when sources are exhausted.
    pub max_relocate_attempts: usize,
    /// Per-range attempt budget (× ranges) that bounds total retries before terminal
    /// [`DownloadError::NoProviders`], guaranteeing termination against an all-bad provider set.
    pub max_range_attempts: usize,
    /// Whether to verify the whole reassembled resource against the chain-anchored root at the end
    /// (retains verified bytes in memory to do so). Disable for large streaming downloads whose store
    /// verifies on install; keep on for standalone integrity. Default `true`.
    pub verify_whole_resource: bool,
}

impl Default for DownloadConfig {
    fn default() -> Self {
        DownloadConfig {
            window: 3 * 1024 * 1024,
            max_concurrency: 8,
            max_inflight_per_source: 4,
            base_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(10),
            max_relocate_attempts: 4,
            max_range_attempts: 6,
            verify_whole_resource: true,
        }
    }
}

/// Per-download options (distinct from the [`Downloader`]-wide [`DownloadConfig`]).
#[derive(Debug, Clone, Default)]
pub struct DownloadOptions {
    /// Start the download paused (no fetches issued until [`DownloadHandle::resume`]).
    pub start_paused: bool,
    /// Override the resume key (default: the content id's DHT key hex). Two downloads sharing a key
    /// share resume state — use distinct keys for distinct targets.
    pub resume_key: Option<String>,
}

/// A control message to a running download task.
#[derive(Debug)]
enum Control {
    Pause,
    Resume,
    Cancel,
}

/// The stable resume key for a content id: the 64-hex of its DHT content key.
pub fn download_key(content: &ContentId) -> String {
    content.to_key().to_hex()
}

/// The multi-source download engine. Constructed once with the injected locator + transport +
/// verifier + state store (real impls over dig-dht / dig-nat, or the in-memory
/// [`testkit`](crate::testkit)), then [`download`](Self::download)ed against many content ids.
pub struct Downloader {
    locator: Arc<dyn ProviderLocator>,
    transport: Arc<dyn RangeTransport>,
    verifier: Arc<dyn Verifier>,
    state_store: Arc<dyn StateStore>,
    registry: Arc<ActiveDownloads>,
    config: DownloadConfig,
}

impl Downloader {
    /// Build a downloader from the injected dependencies + config.
    pub fn new(
        locator: Arc<dyn ProviderLocator>,
        transport: Arc<dyn RangeTransport>,
        verifier: Arc<dyn Verifier>,
        state_store: Arc<dyn StateStore>,
        config: DownloadConfig,
    ) -> Self {
        Downloader {
            locator,
            transport,
            verifier,
            state_store,
            registry: Arc::new(ActiveDownloads::new()),
            config,
        }
    }

    /// The active-download registry (staging files GC must not reap). Shared with a
    /// [`TmpGc`](crate::gc::TmpGc) sweep so paused-resumable downloads are protected.
    pub fn active_downloads(&self) -> Arc<ActiveDownloads> {
        self.registry.clone()
    }

    /// Start downloading `content` into `sink`. Returns immediately with a [`DownloadHandle`]; the
    /// transfer runs on a spawned task. Poll [`DownloadHandle::next_event`] for progress and
    /// [`DownloadHandle::join`] for the final result.
    pub fn download(
        &self,
        content: ContentId,
        sink: Arc<dyn Sink>,
        opts: DownloadOptions,
    ) -> DownloadHandle {
        let key = opts
            .resume_key
            .clone()
            .unwrap_or_else(|| download_key(&content));
        let (control_tx, control_rx) = mpsc::channel(16);
        let (events_tx, events_rx) = mpsc::channel(256);

        let job = Job {
            content,
            key,
            sink,
            verifier: self.verifier.clone(),
            transport: self.transport.clone(),
            locator: self.locator.clone(),
            state_store: self.state_store.clone(),
            registry: self.registry.clone(),
            config: self.config.clone(),
            events: events_tx,
            control: control_rx,
            providers: Vec::new(),
            commitment: None,
            ranges: Vec::new(),
            range_state: Vec::new(),
            tracker: SourceTracker::new(self.config.base_backoff, self.config.max_backoff),
            inflight_per_source: HashMap::new(),
            resume: DownloadState::new(String::new()),
            paused: opts.start_paused,
            bytes_done: 0,
            retained: BTreeMap::new(),
            relocate_attempts: 0,
            relocated_since_progress: false,
            total_failures: 0,
        };

        let task = tokio::spawn(job.run());
        DownloadHandle {
            control: control_tx,
            events: events_rx,
            task,
        }
    }

    /// Run one staging-file GC sweep now over `dir` with `ttl` (mirrors dig-dht's provider `gc()`).
    /// Protected (live/paused-resumable) staging files are never reaped. Returns the number removed.
    pub async fn gc(
        &self,
        dir: impl Into<std::path::PathBuf>,
        ttl: Duration,
    ) -> Result<usize, DownloadError> {
        crate::gc::TmpGc::new(dir, ttl, self.registry.clone())
            .sweep()
            .await
    }
}

/// A handle to a running download: the progress event stream + pause/resume/cancel control + the
/// terminal result via [`join`](Self::join).
pub struct DownloadHandle {
    control: mpsc::Sender<Control>,
    events: mpsc::Receiver<DownloadEvent>,
    task: tokio::task::JoinHandle<Result<u64, DownloadError>>,
}

impl DownloadHandle {
    /// Pause the download — no new range fetches are issued until [`resume`](Self::resume); in-flight
    /// fetches finish and progress is checkpointed. The staging file stays protected from GC.
    pub fn pause(&self) {
        let _ = self.control.try_send(Control::Pause);
    }

    /// Resume a paused download — fetching of the still-missing ranges continues (verified ranges are
    /// never re-fetched).
    pub fn resume(&self) {
        let _ = self.control.try_send(Control::Resume);
    }

    /// Cancel the download — it ends with [`DownloadError::Cancelled`]; its staging file is left for
    /// GC to reap once stale.
    pub fn cancel(&self) {
        let _ = self.control.try_send(Control::Cancel);
    }

    /// Await the next progress [`DownloadEvent`], or `None` once the stream closes (task ended).
    pub async fn next_event(&mut self) -> Option<DownloadEvent> {
        self.events.recv().await
    }

    /// The raw event stream, for a caller that wants to drive it directly.
    pub fn events(&mut self) -> &mut mpsc::Receiver<DownloadEvent> {
        &mut self.events
    }

    /// Await the terminal result: `Ok(total_length)` on success, or the terminal
    /// [`DownloadError`].
    pub async fn join(self) -> Result<u64, DownloadError> {
        match self.task.await {
            Ok(res) => res,
            Err(_) => Err(DownloadError::TaskEnded),
        }
    }
}

/// The output of one range fetch: `(range index, provider peer_id, result)`.
type FetchOutput = (usize, String, Result<FetchedRange, DownloadError>);

/// A single running download's mutable state + the scheduler loop.
struct Job {
    content: ContentId,
    key: String,
    sink: Arc<dyn Sink>,
    verifier: Arc<dyn Verifier>,
    transport: Arc<dyn RangeTransport>,
    locator: Arc<dyn ProviderLocator>,
    state_store: Arc<dyn StateStore>,
    registry: Arc<ActiveDownloads>,
    config: DownloadConfig,
    events: mpsc::Sender<DownloadEvent>,
    control: mpsc::Receiver<Control>,

    providers: Vec<ProviderRecord>,
    commitment: Option<ResourceCommitment>,
    ranges: Vec<Range>,
    range_state: Vec<RangeState>,
    tracker: SourceTracker,
    inflight_per_source: HashMap<String, usize>,
    resume: DownloadState,
    paused: bool,
    bytes_done: u64,
    retained: BTreeMap<u64, Vec<u8>>,
    relocate_attempts: usize,
    relocated_since_progress: bool,
    total_failures: usize,
}

impl Job {
    /// Top-level task body: set up resume state + staging registration, run the download, and always
    /// release the staging registration on a terminal outcome.
    async fn run(mut self) -> Result<u64, DownloadError> {
        self.resume = match self.state_store.load(&self.key).await {
            Ok(Some(state)) => state,
            Ok(None) => DownloadState::new(self.key.clone()),
            Err(e) => {
                self.emit(DownloadEvent::Failed {
                    reason: e.to_string(),
                })
                .await;
                return Err(e);
            }
        };
        // A persisted commitment lets a crash-resume skip the meta-probe.
        if !self.resume.chunk_lens.is_empty() {
            match ResourceCommitment::from_first_frame(
                self.resume.total_length,
                self.resume.chunk_lens.clone(),
                self.resume.root.clone(),
                self.resume.inclusion_proof.clone(),
            ) {
                Ok(c) => self.commitment = Some(c),
                Err(_) => self.commitment = None,
            }
        }

        // Protect the staging file from GC while this download is live/paused-resumable.
        let staging = self.sink.staging_path().map(|p| p.to_path_buf());
        if let Some(path) = &staging {
            self.registry.register(path.clone()).await;
        }

        let result = self.run_inner().await;

        // Terminal outcome → release the staging registration (success already renamed it away;
        // failure/cancel leaves the .download.tmp for GC to reap once stale).
        if let Some(path) = &staging {
            self.registry.unregister(path).await;
        }
        result
    }

    async fn run_inner(&mut self) -> Result<u64, DownloadError> {
        // Guard: a bare store id is not a downloadable byte stream.
        self.availability_item()?;

        // 1–2. Discover + confirm holders.
        self.providers = self.locate_and_confirm().await?;
        if self.providers.is_empty() {
            let reason = format!("{:?}", self.content);
            self.emit(DownloadEvent::Failed {
                reason: format!("no providers for {reason}"),
            })
            .await;
            return Err(DownloadError::NotFound { content: reason });
        }

        // 3. Establish the resource commitment (unless resumed from persisted state).
        if self.commitment.is_none() {
            self.establish_commitment().await?;
        }
        self.persist_commitment().await?;

        // 4. Plan the chunk-aligned ranges; mark the already-verified ones done (resume).
        let commitment = self.commitment.clone().expect("commitment established");
        self.ranges = plan_ranges(&commitment.layout, self.config.window);
        self.range_state = self
            .ranges
            .iter()
            .map(|r| {
                if self.resume.is_done(r.index) {
                    RangeState::Done
                } else {
                    RangeState::Pending
                }
            })
            .collect();
        self.bytes_done = self
            .ranges
            .iter()
            .filter(|r| self.resume.is_done(r.index))
            .map(|r| r.length)
            .sum();
        self.emit(DownloadEvent::Planned {
            ranges_total: self.ranges.len(),
            total_length: commitment.total_length,
        })
        .await;

        // 5–7. Schedule, verify, reassemble.
        self.schedule_loop().await?;

        // Whole-resource integrity backstop (bind to the chain-anchored root).
        if self.config.verify_whole_resource {
            let full = self.assemble_retained();
            if full.len() as u64 == commitment.total_length {
                if let Err(e) = self.verifier.verify_resource(&commitment, &full) {
                    self.emit(DownloadEvent::Failed {
                        reason: e.to_string(),
                    })
                    .await;
                    return Err(e.into());
                }
            }
        }

        // Finalize (a file sink atomically renames its .download.tmp onto the final path).
        self.sink.finalize().await?;
        // Download complete → drop the resume checkpoint.
        let _ = self.state_store.clear(&self.key).await;
        self.emit(DownloadEvent::Completed {
            total_length: commitment.total_length,
        })
        .await;
        Ok(commitment.total_length)
    }

    /// The concurrent scheduler: keep ranges in flight across healthy sources until every range is
    /// done, handling completions, failures, backoff, provider refresh, and pause/resume/cancel.
    async fn schedule_loop(&mut self) -> Result<(), DownloadError> {
        let mut inflight: FuturesUnordered<Pin<Box<dyn Future<Output = FetchOutput> + Send>>> =
            FuturesUnordered::new();

        loop {
            if !self.paused {
                self.fill(&mut inflight);
            }

            if self.all_done() && inflight.is_empty() {
                return Ok(());
            }

            // Guaranteed termination: an all-bad provider set eventually exhausts the budget.
            let budget = self
                .ranges
                .len()
                .saturating_mul(self.config.max_range_attempts)
                .max(self.config.max_range_attempts);
            if self.total_failures > budget {
                let needed = self.pending_count();
                self.emit(DownloadEvent::Failed {
                    reason: format!("provider set exhausted ({needed} range(s) unmet)"),
                })
                .await;
                return Err(DownloadError::NoProviders { needed });
            }

            // If we cannot make progress right now (nothing in flight, nothing scheduled), try to
            // discover more providers, then wait out the earliest backoff, else give up.
            let mut wakeup: Option<Instant> = None;
            if !self.paused && inflight.is_empty() && !self.all_done() {
                if !self.relocated_since_progress
                    && self.relocate_attempts < self.config.max_relocate_attempts
                {
                    let added = self.relocate().await?;
                    self.relocated_since_progress = true;
                    if added > 0 {
                        continue; // new sources — try to schedule them
                    }
                }
                match self.earliest_backoff() {
                    Some(t) => wakeup = Some(t),
                    None => {
                        let needed = self.pending_count();
                        self.emit(DownloadEvent::Failed {
                            reason: format!("no live providers ({needed} range(s) unmet)"),
                        })
                        .await;
                        return Err(DownloadError::NoProviders { needed });
                    }
                }
            }

            let sleep = wakeup.map(|t| {
                let now = Instant::now();
                tokio::time::sleep(t.saturating_duration_since(now))
            });

            tokio::select! {
                ctrl = self.control.recv() => {
                    match ctrl {
                        Some(Control::Pause) => {
                            if !self.paused {
                                self.paused = true;
                                let _ = self.checkpoint().await;
                                self.emit(DownloadEvent::Paused).await;
                            }
                        }
                        Some(Control::Resume) => {
                            if self.paused {
                                self.paused = false;
                                self.emit(DownloadEvent::Resumed).await;
                            }
                        }
                        Some(Control::Cancel) | None => {
                            let _ = self.checkpoint().await;
                            self.emit(DownloadEvent::Failed { reason: "cancelled".into() }).await;
                            return Err(DownloadError::Cancelled);
                        }
                    }
                }
                Some((idx, peer, res)) = inflight.next(), if !inflight.is_empty() => {
                    self.handle_result(idx, peer, res).await?;
                }
                _ = async { sleep.unwrap().await }, if wakeup.is_some() => {
                    // Backoff elapsed — loop to re-attempt scheduling.
                }
            }
        }
    }

    /// Assign pending ranges to available sources, up to the concurrency + per-source caps.
    fn fill(
        &mut self,
        inflight: &mut FuturesUnordered<Pin<Box<dyn Future<Output = FetchOutput> + Send>>>,
    ) {
        let now = Instant::now();
        loop {
            if inflight.len() >= self.config.max_concurrency {
                break;
            }
            let Some(range_idx) = self.next_pending() else {
                break;
            };
            let Some(peer) = self.pick_source(now) else {
                break; // no schedulable source right now
            };
            self.range_state[range_idx] = RangeState::InFlight(peer.clone());
            *self.inflight_per_source.entry(peer.clone()).or_insert(0) += 1;
            inflight.push(self.fetch_future(range_idx, peer));
        }
    }

    /// Build the boxed fetch future for `range_idx` from `peer`.
    fn fetch_future(
        &self,
        range_idx: usize,
        peer: String,
    ) -> Pin<Box<dyn Future<Output = FetchOutput> + Send>> {
        let range = self.ranges[range_idx];
        let provider = self
            .providers
            .iter()
            .find(|p| p.provider_peer_id == peer)
            .cloned();
        let transport = self.transport.clone();
        let req = self.range_request(range.offset, range.length);
        Box::pin(async move {
            let provider = match provider {
                Some(p) => p,
                None => {
                    return (
                        range_idx,
                        peer.clone(),
                        Err(DownloadError::transport(&peer, "provider vanished")),
                    )
                }
            };
            let req = match req {
                Ok(r) => r,
                Err(e) => return (range_idx, peer, Err(e)),
            };
            let res = transport.fetch_range(&provider, &req).await;
            (range_idx, peer, res)
        })
    }

    /// Handle a completed range fetch: verify + write + mark done, or penalize the source + re-queue.
    async fn handle_result(
        &mut self,
        idx: usize,
        peer: String,
        res: Result<FetchedRange, DownloadError>,
    ) -> Result<(), DownloadError> {
        if let Some(n) = self.inflight_per_source.get_mut(&peer) {
            *n = n.saturating_sub(1);
        }

        let commitment = self.commitment.clone().expect("commitment established");
        let range = self.ranges[idx];

        let outcome = match res {
            Ok(fetched) => self.verify_fetched(&commitment, &range, fetched),
            Err(e) => Err(e),
        };

        match outcome {
            Ok(bytes) => {
                self.sink.write_at(range.offset, &bytes).await?;
                if self.config.verify_whole_resource {
                    self.retained.insert(range.offset, bytes);
                }
                self.range_state[idx] = RangeState::Done;
                self.resume.mark_done(idx);
                self.bytes_done = self.bytes_done.saturating_add(range.length);
                self.tracker.record_success(&peer);
                self.relocated_since_progress = false;
                self.checkpoint().await?;
                let progress = self.snapshot();
                self.emit(DownloadEvent::RangeCompleted {
                    range: idx,
                    provider: peer,
                    progress,
                })
                .await;
            }
            Err(e) => {
                // Sink/state errors are terminal; transport/verify are recoverable (retry elsewhere).
                if !e.is_recoverable() {
                    self.emit(DownloadEvent::Failed {
                        reason: e.to_string(),
                    })
                    .await;
                    return Err(e);
                }
                self.range_state[idx] = RangeState::Pending;
                self.tracker.record_failure(&peer, Instant::now());
                self.total_failures = self.total_failures.saturating_add(1);
                self.emit(DownloadEvent::RangeFailed {
                    range: idx,
                    provider: peer,
                    reason: e.to_string(),
                })
                .await;
            }
        }
        Ok(())
    }

    /// Verify a fetched range against the commitment, returning its verified bytes or a
    /// [`DownloadError`]. Checks first-frame metadata consistency + per-range length/alignment.
    fn verify_fetched(
        &self,
        commitment: &ResourceCommitment,
        range: &Range,
        fetched: FetchedRange,
    ) -> Result<Vec<u8>, DownloadError> {
        commitment.check_consistent(
            fetched.meta.total_length,
            fetched.meta.chunk_lens.as_deref(),
            fetched.meta.root.as_deref(),
        )?;
        self.verifier
            .verify_range(commitment, range.chunk_start as u64, &fetched.bytes)?;
        Ok(fetched.bytes)
    }

    // ---- discovery + commitment --------------------------------------------------------------

    /// Locate holders and keep only those that confirm they hold the content (`dig.getAvailability`).
    async fn locate_and_confirm(&self) -> Result<Vec<ProviderRecord>, DownloadError> {
        let found = self.locator.find_providers(&self.content).await?;
        let item = self.availability_item()?;
        let mut confirmed = Vec::new();
        for p in found {
            match self
                .transport
                .query_availability(&p, vec![item.clone()])
                .await
            {
                Ok(resp) if resp.items.first().map(|a| a.available).unwrap_or(false) => {
                    confirmed.push(p)
                }
                _ => {}
            }
        }
        Ok(confirmed)
    }

    /// Re-run discovery to find MORE providers when the known set is exhausted; merge the new ones.
    /// Returns how many new providers were added.
    async fn relocate(&mut self) -> Result<usize, DownloadError> {
        self.relocate_attempts += 1;
        let more = self.locate_and_confirm().await?;
        let known: HashSet<String> = self
            .providers
            .iter()
            .map(|p| p.provider_peer_id.clone())
            .collect();
        let mut added = 0;
        for p in more {
            if !known.contains(&p.provider_peer_id) {
                self.providers.push(p);
                added += 1;
            }
        }
        if added > 0 {
            self.emit(DownloadEvent::ProvidersRefreshed {
                providers: self.providers.len(),
            })
            .await;
        }
        Ok(added)
    }

    /// Establish the [`ResourceCommitment`] via a meta-probe: fetch a tiny range from a holder and
    /// read the whole-resource `chunk_lens` / `total_length` / `root` from its first frame.
    async fn establish_commitment(&mut self) -> Result<(), DownloadError> {
        let providers = self.providers.clone();
        for provider in &providers {
            let req = self.range_request(0, 1)?;
            if let Ok(f) = self.transport.fetch_range(provider, &req).await {
                if let (Some(tl), Some(cl)) = (f.meta.total_length, f.meta.chunk_lens.clone()) {
                    match ResourceCommitment::from_first_frame(
                        tl,
                        cl,
                        f.meta.root.clone(),
                        f.meta.inclusion_proof.clone(),
                    ) {
                        Ok(c) => {
                            self.commitment = Some(c);
                            return Ok(());
                        }
                        Err(_) => continue,
                    }
                }
            }
        }
        let reason = format!("{:?}", self.content);
        self.emit(DownloadEvent::Failed {
            reason: format!("could not read resource metadata for {reason}"),
        })
        .await;
        Err(DownloadError::NotFound { content: reason })
    }

    /// Persist the established commitment into the resume checkpoint (so a crash-resume skips the
    /// probe + re-plans identically).
    async fn persist_commitment(&mut self) -> Result<(), DownloadError> {
        if let Some(c) = &self.commitment {
            self.resume.total_length = c.total_length;
            self.resume.chunk_lens = c.layout.chunk_lens().to_vec();
            self.resume.root = c.root.clone();
            self.resume.inclusion_proof = c.inclusion_proof.clone();
            self.checkpoint().await?;
        }
        Ok(())
    }

    // ---- scheduling helpers ------------------------------------------------------------------

    /// The index of the first range still needing work and not already in flight.
    fn next_pending(&self) -> Option<usize> {
        self.range_state
            .iter()
            .position(|s| matches!(s, RangeState::Pending))
    }

    /// Pick the healthiest schedulable source at `now`: available (not in backoff), under the
    /// per-source in-flight cap, preferring the least-loaded.
    fn pick_source(&self, now: Instant) -> Option<String> {
        self.providers
            .iter()
            .map(|p| p.provider_peer_id.clone())
            .filter(|peer| self.tracker.is_available(peer, now))
            .filter(|peer| {
                self.inflight_per_source.get(peer).copied().unwrap_or(0)
                    < self.config.max_inflight_per_source
            })
            .min_by_key(|peer| self.inflight_per_source.get(peer).copied().unwrap_or(0))
    }

    /// The earliest backoff-expiry among sources that hold the content but are currently backed off
    /// (the next moment scheduling could resume), if any.
    fn earliest_backoff(&self) -> Option<Instant> {
        let now = Instant::now();
        self.providers
            .iter()
            .filter_map(|p| {
                if self.tracker.is_available(&p.provider_peer_id, now) {
                    None
                } else {
                    // Not available now → in a backoff window; probe forward to find when.
                    self.next_available_at(&p.provider_peer_id, now)
                }
            })
            .min()
    }

    /// The next instant `peer` becomes schedulable (a coarse forward scan of the backoff window).
    fn next_available_at(&self, peer: &str, now: Instant) -> Option<Instant> {
        // The tracker exposes availability; find the boundary by checking the configured max window.
        // A simple, allocation-free probe: step by base_backoff up to max_backoff.
        let step = self.config.base_backoff.max(Duration::from_millis(1));
        let mut t = now;
        let limit = now + self.config.max_backoff + step;
        while t <= limit {
            if self.tracker.is_available(peer, t) {
                return Some(t);
            }
            t += step;
        }
        Some(limit)
    }

    /// Whether every planned range is done.
    fn all_done(&self) -> bool {
        !self.range_state.is_empty()
            && self
                .range_state
                .iter()
                .all(|s| matches!(s, RangeState::Done))
    }

    /// The number of ranges not yet done.
    fn pending_count(&self) -> usize {
        self.range_state
            .iter()
            .filter(|s| s.is_incomplete())
            .count()
    }

    /// A coalesced progress snapshot.
    fn snapshot(&self) -> DownloadProgress {
        let ranges_done = self
            .range_state
            .iter()
            .filter(|s| matches!(s, RangeState::Done))
            .count();
        let active_sources = self
            .inflight_per_source
            .values()
            .filter(|&&n| n > 0)
            .count();
        DownloadProgress {
            bytes_done: self.bytes_done,
            total_length: self
                .commitment
                .as_ref()
                .map(|c| c.total_length)
                .unwrap_or(0),
            ranges_done,
            ranges_total: self.ranges.len(),
            active_sources,
        }
    }

    /// Concatenate the retained verified range bytes in offset order (for the whole-resource verify).
    fn assemble_retained(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.retained.values().map(|b| b.len()).sum());
        for bytes in self.retained.values() {
            out.extend_from_slice(bytes);
        }
        out
    }

    /// Persist the current resume checkpoint.
    async fn checkpoint(&self) -> Result<(), DownloadError> {
        self.state_store.save(&self.resume).await
    }

    async fn emit(&self, event: DownloadEvent) {
        let _ = self.events.send(event).await;
    }

    // ---- content-id → wire mapping -----------------------------------------------------------

    /// The `dig.getAvailability` item for this content id (errors for a bare store id).
    fn availability_item(&self) -> Result<AvailabilityItem, DownloadError> {
        match &self.content {
            ContentId::Store { .. } => Err(DownloadError::NotDownloadable),
            ContentId::Root { store_id, root } => Ok(AvailabilityItem {
                store_id: hex32(store_id),
                root: Some(hex32(root)),
                retrieval_key: None,
            }),
            ContentId::Resource {
                store_id,
                root,
                retrieval_key,
            } => Ok(AvailabilityItem {
                store_id: hex32(store_id),
                root: Some(hex32(root)),
                retrieval_key: Some(hex32(retrieval_key)),
            }),
        }
    }

    /// The `dig.fetchRange` request for `[offset, offset+length)` of this content id.
    fn range_request(&self, offset: u64, length: u64) -> Result<RangeRequest, DownloadError> {
        match &self.content {
            ContentId::Store { .. } => Err(DownloadError::NotDownloadable),
            ContentId::Root { store_id, root } => Ok(RangeRequest {
                store_id: hex32(store_id),
                retrieval_key: None,
                root: Some(hex32(root)),
                capsule: true,
                offset,
                length,
            }),
            ContentId::Resource {
                store_id,
                root,
                retrieval_key,
            } => Ok(RangeRequest {
                store_id: hex32(store_id),
                retrieval_key: Some(hex32(retrieval_key)),
                root: Some(hex32(root)),
                capsule: false,
                offset,
                length,
            }),
        }
    }
}

/// Lowercase-hex a 32-byte id (store_id / root / retrieval_key) for the wire.
fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for x in b {
        s.push(char::from_digit((x >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((x & 0x0f) as u32, 16).unwrap());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_key_is_content_key_hex() {
        let c = ContentId::resource([1; 32], [2; 32], [3; 32]);
        assert_eq!(download_key(&c), c.to_key().to_hex());
        assert_eq!(download_key(&c).len(), 64);
    }

    #[test]
    fn hex32_round_trips_length() {
        assert_eq!(hex32(&[0xAB; 32]), "ab".repeat(32));
    }
}
