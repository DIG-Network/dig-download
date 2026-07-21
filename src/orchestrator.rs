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

use std::collections::{HashMap, HashSet};
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
use crate::select::{
    CandidateRef, NullSelector, RangeOutcome, RangeResult, SelectPlan, SelectRequest,
    SourceSelector,
};
use crate::sink::Sink;
use crate::source::{FetchedRange, RangeTransport, SourceTracker};
use crate::verify::{ResourceCommitment, ResourceHasher, Verifier};

/// The default per-range fetch timeout: a range that takes longer than this is abandoned and
/// re-queued to another holder (its source is backed off + reported `TimedOut` to the selector).
pub const DEFAULT_RANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// The default interval between background `find_providers` refreshes during a download: new holders
/// discovered mid-download are merged into the candidate set so the selector can rebalance onto them
/// (the "live upgrade" of #1435).
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(15);

/// Tuning for a download's scheduler + integrity + backoff.
///
/// `Clone` is derived; `Debug` is hand-written to skip the non-`Debug` [`selector`](Self::selector)
/// trait object. This struct is built via `..Default::default()`, so adding fields is a
/// non-breaking (minor) change for the only in-tree consumer (dig-node) — an exhaustive struct
/// literal elsewhere would break, but there is none.
#[derive(Clone)]
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
    /// The **selection brain**: which candidate peers to fetch from, and in what order. `None` uses a
    /// fair round-robin [`NullSelector`], keeping dig-download fully usable standalone. dig-node
    /// injects an adapter over `dig-peer-selector` here so ONE self-tuning brain informs every
    /// transfer — dig-download itself owns no ranking model (see the [`select`](crate::select) module).
    pub selector: Option<Arc<dyn SourceSelector>>,
    /// Per-range fetch timeout: a range fetch exceeding this is abandoned + re-queued elsewhere and
    /// its source backed off. `None` disables the timeout. Default [`DEFAULT_RANGE_TIMEOUT`] (30s).
    pub range_timeout: Option<Duration>,
    /// How often to re-run `find_providers` DURING a download to discover new holders (merged into the
    /// candidate set for the selector to rebalance onto — the live upgrade). `None` disables periodic
    /// refresh (the exhaustion-triggered relocate still runs). Default [`DEFAULT_REFRESH_INTERVAL`].
    pub refresh_interval: Option<Duration>,
}

impl std::fmt::Debug for DownloadConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DownloadConfig")
            .field("window", &self.window)
            .field("max_concurrency", &self.max_concurrency)
            .field("max_inflight_per_source", &self.max_inflight_per_source)
            .field("base_backoff", &self.base_backoff)
            .field("max_backoff", &self.max_backoff)
            .field("max_relocate_attempts", &self.max_relocate_attempts)
            .field("max_range_attempts", &self.max_range_attempts)
            .field("verify_whole_resource", &self.verify_whole_resource)
            .field("selector", &self.selector.as_ref().map(|_| "<injected>"))
            .field("range_timeout", &self.range_timeout)
            .field("refresh_interval", &self.refresh_interval)
            .finish()
    }
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
            selector: None,
            range_timeout: Some(DEFAULT_RANGE_TIMEOUT),
            refresh_interval: Some(DEFAULT_REFRESH_INTERVAL),
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

        // Resolve the selection brain: the injected one, or the standalone round-robin default.
        let selector = self
            .config
            .selector
            .clone()
            .unwrap_or_else(|| Arc::new(NullSelector::new()));

        let job = Job {
            content,
            key,
            sink,
            verifier: self.verifier.clone(),
            transport: self.transport.clone(),
            locator: self.locator.clone(),
            state_store: self.state_store.clone(),
            registry: self.registry.clone(),
            selector,
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
            hasher: None,
            relocate_attempts: 0,
            relocated_since_progress: false,
            total_failures: 0,
            last_refresh: Instant::now(),
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

/// The output of one range fetch: `(range index, provider peer_id, elapsed, result)`. `elapsed` is
/// the measured wall-clock of the attempt, reported to the selector as part of the [`RangeOutcome`].
type FetchOutput = (usize, String, Duration, Result<FetchedRange, DownloadError>);

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
    /// The injected (or default round-robin) selection brain. dig-download DELEGATES all peer choice
    /// here and reports every range outcome back — it keeps no ranking model of its own.
    selector: Arc<dyn SourceSelector>,
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
    /// Streaming SHA-256 of the resource ciphertext for the whole-resource backstop, fed one verified
    /// range at a time in offset order (only present when `verify_whole_resource` and no ranges were
    /// resumed from a prior process). Replaces retaining every range + a full concat copy (~2N RAM).
    hasher: Option<ResourceHasher>,
    relocate_attempts: usize,
    relocated_since_progress: bool,
    total_failures: usize,
    /// When the last background `find_providers` refresh ran (for the periodic live-upgrade refresh).
    last_refresh: Instant,
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
        // Ranges carried over as already-done from persisted resume state: their verified bytes were
        // written to the sink in a PRIOR process and are NOT in this run's in-RAM `retained` map, so
        // the whole-resource in-RAM assembly is intentionally partial and the backstop can't run over
        // it (see below). A range is only ever marked done after passing the per-range length +
        // alignment check, so a resumed-done range is still known-good.
        let resumed_ranges = self
            .ranges
            .iter()
            .filter(|r| self.resume.is_done(r.index))
            .count();
        // The whole-resource backstop hashes ranges incrementally in offset order (O(window) RAM
        // instead of retaining ~2N bytes — MEDIUM #179). It is only usable on a FRESH download where
        // every range flows through this process; on a crash-resume the earlier ranges are only in
        // the sink, so no hasher is created and the backstop is skipped (each range was still
        // per-range verified).
        self.hasher = if self.config.verify_whole_resource && resumed_ranges == 0 {
            Some(ResourceHasher::new())
        } else {
            None
        };
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

        // Whole-resource integrity backstop (bind to the chain-anchored root). Fail-closed: on a
        // fresh (non-resumed) download every verified range was fed to the incremental `hasher`, so
        // its contiguous hashed length MUST equal the committed total_length — `verify_resource_leaf`
        // returns VerifyError::Length for a short/incomplete assembly rather than being silently
        // skipped, so a short download can never fall through to a successful finalize (CRITICAL
        // #179). On a crash-RESUME the earlier ranges live only in the sink's staging file (no hasher
        // was created), so this backstop is skipped; every range — resumed or freshly fetched — still
        // passed the per-range length + alignment check, so integrity is not silently lost. The
        // incremental hash avoids retaining every range + a full concat copy (~2N RAM — MEDIUM #179).
        if let Some(hasher) = self.hasher.take() {
            let hashed_len = hasher.hashed_len();
            let leaf = hasher.finalize();
            if let Err(e) = self
                .verifier
                .verify_resource_leaf(&commitment, &leaf, hashed_len)
            {
                self.emit(DownloadEvent::Failed {
                    reason: e.to_string(),
                })
                .await;
                return Err(e.into());
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

            // Live upgrade: periodically re-run find_providers so a new/faster holder discovered
            // mid-download joins the candidate set and the selector can rebalance onto it. Disabled
            // while paused (no scheduling happening) or when unmet ranges remain zero.
            let refresh_sleep = self
                .config
                .refresh_interval
                .filter(|_| !self.paused)
                .map(|iv| {
                    let due = self.last_refresh + iv;
                    tokio::time::sleep(due.saturating_duration_since(Instant::now()))
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
                Some((idx, peer, elapsed, res)) = inflight.next(), if !inflight.is_empty() => {
                    self.handle_result(idx, peer, elapsed, res).await?;
                }
                _ = async { sleep.unwrap().await }, if wakeup.is_some() => {
                    // Backoff elapsed — loop to re-attempt scheduling.
                }
                _ = async { refresh_sleep.unwrap().await }, if refresh_sleep.is_some() => {
                    // Periodic live-upgrade refresh: merge any newly-discovered holders so the next
                    // fill's selector.select sees them (no attempt-budget cost — that guards the
                    // exhaustion path only).
                    self.last_refresh = Instant::now();
                    let _ = self.discover_more().await;
                }
            }
        }
    }

    /// Assign pending ranges to sources, up to the concurrency + per-source caps.
    ///
    /// Peer CHOICE + ORDER is delegated to the injected [`SourceSelector`]: one `select` per fill pass
    /// yields the preference order (and any explicit per-range pins) over the currently-live
    /// candidates, and this loop assigns each pending range to the first ordered peer under its
    /// in-flight cap. dig-download applies no ranking of its own — it only enforces the mechanical
    /// concurrency/per-source caps and liveness backoff around the selector's decision.
    fn fill(
        &mut self,
        inflight: &mut FuturesUnordered<Pin<Box<dyn Future<Output = FetchOutput> + Send>>>,
    ) {
        let now = Instant::now();
        let plan = self.select_plan(now);
        loop {
            if inflight.len() >= self.config.max_concurrency {
                break;
            }
            let Some(range_idx) = self.next_pending() else {
                break;
            };
            let Some(peer) = self.pick_from_plan(&plan, range_idx) else {
                break; // the selector offered no schedulable source right now
            };
            self.range_state[range_idx] = RangeState::InFlight(peer.clone());
            *self.inflight_per_source.entry(peer.clone()).or_insert(0) += 1;
            inflight.push(self.fetch_future(range_idx, peer));
        }
    }

    /// Ask the selector which live candidates to use for this fill pass, and in what order.
    ///
    /// The candidate set is pre-filtered to holders that are schedulable NOW (not inside a
    /// liveness/backoff window — dig-download's mechanical debounce, NOT a throughput judgement), so
    /// the selector reasons purely about speed/preference, never about liveness.
    fn select_plan(&self, now: Instant) -> SelectPlan {
        let candidates: Vec<CandidateRef> = self
            .providers
            .iter()
            .filter(|p| self.tracker.is_available(&p.provider_peer_id, now))
            .map(|p| {
                let addrs = p
                    .addresses
                    .iter()
                    .map(|a| format!("{}:{}", a.host, a.port))
                    .collect();
                CandidateRef::new(p.provider_peer_id.clone(), addrs)
            })
            .collect();
        let req = SelectRequest {
            content_key: &self.key,
            candidates: &candidates,
            ranges_needed: self.pending_count(),
            inflight: self.inflight_per_source.values().sum(),
        };
        self.selector.select(&req)
    }

    /// Resolve `range_idx` to a peer using the selector's [`SelectPlan`]: honor an explicit per-range
    /// pin if the pinned peer is schedulable, else take the first peer in preference order that is
    /// under its per-source in-flight cap.
    fn pick_from_plan(&self, plan: &SelectPlan, range_idx: usize) -> Option<String> {
        let under_cap = |peer: &str| {
            self.inflight_per_source.get(peer).copied().unwrap_or(0)
                < self.config.max_inflight_per_source
        };
        // An explicit pin wins when its peer still has capacity.
        if let Some((_, peer)) = plan.assignments.iter().find(|(r, _)| *r == range_idx) {
            if under_cap(peer) {
                return Some(peer.clone());
            }
        }
        plan.ordered.iter().find(|p| under_cap(p)).cloned()
    }

    /// Build the boxed fetch future for `range_idx` from `peer`, timing the attempt and enforcing the
    /// per-range timeout. A fetch that exceeds [`DownloadConfig::range_timeout`] resolves to a
    /// recoverable [`DownloadError::Timeout`] so the range re-queues elsewhere and the slow source is
    /// backed off + reported `TimedOut` to the selector.
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
        let timeout = self.config.range_timeout;
        Box::pin(async move {
            let started = Instant::now();
            let provider = match provider {
                Some(p) => p,
                None => {
                    return (
                        range_idx,
                        peer.clone(),
                        started.elapsed(),
                        Err(DownloadError::transport(&peer, "provider vanished")),
                    )
                }
            };
            let req = match req {
                Ok(r) => r,
                Err(e) => return (range_idx, peer, started.elapsed(), Err(e)),
            };
            let fetch = transport.fetch_range(&provider, &req);
            let res = match timeout {
                Some(limit) => match tokio::time::timeout(limit, fetch).await {
                    Ok(res) => res,
                    Err(_) => Err(DownloadError::Timeout {
                        provider: peer.clone(),
                    }),
                },
                None => fetch.await,
            };
            (range_idx, peer, started.elapsed(), res)
        })
    }

    /// Handle a completed range fetch: verify + write + mark done, or penalize the source + re-queue.
    /// Every outcome — success, failure, or timeout — is reported to the selector via
    /// [`SourceSelector::record`] so its learning loop sees the real measured result (`elapsed` is the
    /// attempt's wall-clock).
    async fn handle_result(
        &mut self,
        idx: usize,
        peer: String,
        elapsed: Duration,
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
                let served = bytes.len() as u64;
                self.sink.write_at(range.offset, &bytes).await?;
                if let Some(hasher) = self.hasher.as_mut() {
                    hasher.feed(range.offset, bytes);
                }
                self.range_state[idx] = RangeState::Done;
                self.resume.mark_done(idx);
                self.bytes_done = self.bytes_done.saturating_add(range.length);
                self.tracker.record_success(&peer);
                self.report_outcome(&peer, served, elapsed, RangeResult::Ok);
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
                // Sink/state errors are terminal; transport/verify/timeout are recoverable (retry
                // elsewhere). A timeout is reported distinctly so the selector can down-rank a
                // too-slow peer differently from a hard failure.
                if !e.is_recoverable() {
                    self.emit(DownloadEvent::Failed {
                        reason: e.to_string(),
                    })
                    .await;
                    return Err(e);
                }
                let result = if matches!(e, DownloadError::Timeout { .. }) {
                    RangeResult::TimedOut
                } else {
                    RangeResult::Failed
                };
                self.range_state[idx] = RangeState::Pending;
                self.tracker.record_failure(&peer, Instant::now());
                self.total_failures = self.total_failures.saturating_add(1);
                self.report_outcome(&peer, 0, elapsed, result);
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

    /// Report one range fetch's measured outcome to the selector's learning loop.
    fn report_outcome(&self, peer: &str, bytes: u64, elapsed: Duration, result: RangeResult) {
        self.selector.record(&RangeOutcome {
            peer_id: peer.to_string(),
            bytes,
            elapsed,
            result,
        });
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
        // Pass the planned range length so a boundary-aligned SHORT range (fewer whole chunks than
        // requested) is rejected as a recoverable VerifyError::Length and re-fetched elsewhere,
        // rather than silently written as a hole (CRITICAL #179).
        self.verifier.verify_range(
            commitment,
            range.chunk_start as u64,
            range.length,
            &fetched.bytes,
        )?;
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

    /// Re-run discovery to find MORE providers when the known set is exhausted, consuming one relocate
    /// attempt from the budget. Delegates the merge to [`discover_more`](Self::discover_more).
    async fn relocate(&mut self) -> Result<usize, DownloadError> {
        self.relocate_attempts += 1;
        self.discover_more().await
    }

    /// Re-run `find_providers` and merge any NEW holders into the candidate set (deduped by
    /// `peer_id`), returning how many were added. Used both by the exhaustion-triggered
    /// [`relocate`](Self::relocate) and by the periodic live-upgrade refresh — the latter does NOT
    /// consume the relocate budget, so a healthy download keeps discovering faster peers indefinitely.
    async fn discover_more(&mut self) -> Result<usize, DownloadError> {
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
        let want_root = self.content_root_hex();
        for provider in &providers {
            let req = self.range_request(0, 1)?;
            if let Ok(f) = self.transport.fetch_range(provider, &req).await {
                // Bind the ground truth to the CALLER's request, not to whichever peer answers
                // first: reject a peer whose reported generation root differs from the content-id's
                // root before adopting anything it says (HIGH #179). Without this, a single peer
                // winning the meta-probe race could shape the whole plan to an attacker-chosen
                // generation, and check_consistent would then discard the honest providers.
                if let (Some(want), Some(got)) = (&want_root, &f.meta.root) {
                    if got != want {
                        continue;
                    }
                }
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

    /// The content-id's generation `root` as lowercase 64-hex (the ground truth every peer-reported
    /// root is cross-checked against), or `None` for a bare store id (which carries no root).
    fn content_root_hex(&self) -> Option<String> {
        match &self.content {
            ContentId::Store { .. } => None,
            ContentId::Root { root, .. } | ContentId::Resource { root, .. } => Some(hex32(root)),
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
