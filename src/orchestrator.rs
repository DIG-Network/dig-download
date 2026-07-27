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
/// trait object.
///
/// `#[non_exhaustive]`: this struct was already documented as "built via `..Default::default()`, so
/// adding fields is non-breaking" — a claim that held only for as long as nobody wrote an exhaustive
/// literal. The attribute makes the documented intent MECHANICAL, so every future field really is a minor
/// change instead of relying on a convention. Applied in the same breaking window as the attribute on
/// [`RangeMeta`](crate::RangeMeta) and
/// [`ResourceCommitment`](crate::verify::ResourceCommitment), rather than costing a second one.
/// Construct with `DownloadConfig { window: …, ..Default::default() }`.
#[derive(Clone)]
#[non_exhaustive]
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
    /// The ceiling on a peer-DECLARED resource `total_length`. The first frame's declared length sizes
    /// the plan and the range assembler's buffer, and it comes from a peer that has proven nothing yet,
    /// so a commitment above this bound is REFUSED before any layout exists (#1608). Default
    /// [`DEFAULT_MAX_RESOURCE_SIZE`](crate::verify::DEFAULT_MAX_RESOURCE_SIZE) (512 MiB); raise it
    /// explicitly on a host sized for larger resources.
    pub max_resource_size: u64,
    /// Whether to bind the whole reassembled resource to the chain-anchored root before promoting it.
    /// Default `true`; keep it on for standalone integrity.
    ///
    /// **Exactly what disabling it subtracts.** It removes the ONLY check that binds assembled CONTENT to
    /// the commitment: the per-range checks are structural (length + alignment), so right-length wrong
    /// bytes from any source pass them. Two consequences follow, and neither is obvious from the name:
    ///
    /// - freshly-fetched bytes are accepted on their shape alone, so this is only safe when something
    ///   downstream verifies the artifact (a store that verifies on install);
    /// - a RESUMED range's staged bytes cannot be bound to anything either, so they are NOT trusted —
    ///   they are re-fetched. Disabling this therefore costs the resume optimization across a process
    ///   restart, deliberately: trusting them promoted arbitrary bytes as a verified success.
    ///
    /// It does NOT remove the promotion length proof — an incomplete artifact is still refused
    /// (see [`crate::sink`]) — and it does not disable the per-range structural checks.
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
            .field("max_resource_size", &self.max_resource_size)
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
            max_resource_size: crate::verify::DEFAULT_MAX_RESOURCE_SIZE,
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
    /// range at a time in offset order. Present whenever [`DownloadConfig::verify_whole_resource`] is
    /// set — INCLUDING on a crash-resume, where the ranges a prior process completed are read back from
    /// staging and fed in before scheduling (#1605), so the backstop is never skipped. Replaces
    /// retaining every range + a full concat copy (~2N RAM).
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
            match ResourceCommitment::from_first_frame_bounded(
                self.resume.total_length,
                self.resume.chunk_lens.clone(),
                self.resume.root.clone(),
                self.resume.inclusion_proof.clone(),
                self.config.max_resource_size,
            ) {
                Ok(c) => self.commitment = Some(c),
                Err(_) => self.commitment = None,
            }
        }

        // CLAIM the staging file: it is protected from GC while this download is live/paused-resumable,
        // and — since a staging area is shared by nothing — held EXCLUSIVELY. A second download of the
        // same target would write over this one by offset, share its checkpoint, and be able to
        // `truncate` its bytes away, which per-range structural verification cannot detect. Refusing to
        // start is the only outcome that keeps "the promoted artifact is the verified artifact" true.
        //
        // The claim is an RAII guard, so it is released on EVERY exit from this function — including an
        // unwinding panic, which `tokio::spawn` absorbs. A leaked claim would make its staging path both
        // permanently GC-exempt and permanently un-downloadable, turning this guard into the very denial
        // primitive it exists to prevent.
        let _claim = match self.sink.staging_path().map(|p| p.to_path_buf()) {
            None => None, // an in-memory sink stages nothing on disk
            Some(path) => match self.registry.claim(path.clone()) {
                Some(claim) => Some(claim),
                None => {
                    let reason = format!(
                        "another download is already staging into {}; refusing to share a staging area",
                        path.display()
                    );
                    self.emit(DownloadEvent::Failed {
                        reason: reason.clone(),
                    })
                    .await;
                    // The claim belongs to the download that holds it — this one releases nothing.
                    return Err(DownloadError::sink(reason));
                }
            },
        };

        // Success renamed the staging file away; failure/cancel leaves the `.download.tmp` for GC to reap
        // once stale. Either way the claim drops here.
        self.run_inner().await
    }

    /// Drive the download: discover, establish the layout, plan, fetch, verify, promote.
    ///
    /// # A whole-resource refutation is TERMINAL and blames nobody
    ///
    /// When the chain-anchored check rejects the assembly, this download ends. It does not exclude the holder
    /// that supplied the layout and does not re-adopt from another, because deciding whether the SHAPE or the
    /// BYTES were wrong is not possible here: per-range verification is length and alignment only, with no
    /// per-chunk hash, so nothing identifies which holder served bad bytes.
    ///
    /// A retry bounded by an attributability heuristic was built and REMOVED. Every version of that heuristic
    /// had to vote over peer DECLARATIONS (`total_length` / `chunk_count` from `dig.getAvailability`), and
    /// those are optional wire fields: an attacker forges one for the price of a keypair and an announce,
    /// while honest holders legitimately omit them — production dig-node sends neither at capsule
    /// granularity. Each version therefore produced a NEW denial cheaper than the one it fixed, and the last
    /// bounded at three whole transfers out of honest peers — measured as 5 range fetches becoming 15 on one
    /// fixture and 19 on another, the excess over 3x being ranges the lying record served and had refused —
    /// plus a terminal error naming honest peers as
    /// culprits, from a single anonymous record. Not shipping it is strictly not-worse-than-baseline; #1670 is
    /// re-scoped onto per-chunk attribution, the only evidence that can name a holder.
    ///
    /// # The three rejected designs, recorded so #1670 does not rediscover them
    ///
    /// All three tried to decide, from what peers SAY, whether a refutation was the layout's fault. Each was
    /// defeated by a cheaper attack than the one it fixed, and the progression is the useful part:
    ///
    /// - REJECTED-DESIGN: order candidates by the MODAL declared shape, so a sybil must carry the majority
    ///   shape to keep an early position. Fabricating provider records costs no content, no keys and no race
    ///   for position, so the majority shape is simply the attacker's and the retry budget is spent inside
    ///   the colluding group. Measured: lying in the cheap answer PROMOTED the sybil.
    /// - REJECTED-DESIGN: group by declared shape + demote refuted shapes + rank by size + interleave groups.
    ///   Two bypasses: N sybils declaring N DISTINCT shapes make every group a singleton, so the key
    ///   tiebreak decides the order and the attacker picks its key; and
    ///   holders that declare NOTHING sit at the minimum key while being the one group a refuted-shape
    ///   demotion can never act on. Silence beat lying.
    /// - REJECTED-DESIGN: retry only when the refuted shape is a strict MINORITY of declared shapes. Honest
    ///   holders are SILENT at capsule granularity, so the honest population declares nothing, one anonymous
    ///   record becomes the only "rival" shape, and the refutation is attributed against honest peers.
    ///
    /// The invariant behind all three failures: **an ordering or attribution over free-to-forge OPTIONAL
    /// declarations cannot stand in for evidence.** An ordering may DEMOTE on evidence and must never PROMOTE
    /// on a declaration — and there is no evidence here, so there is no ordering: candidates are probed in
    /// the order discovery produced.
    async fn run_inner(&mut self) -> Result<u64, DownloadError> {
        // Guard: a bare store id is not a downloadable byte stream.
        self.availability_item()?;

        // 1–2. Discover + confirm holders.
        self.providers = self.locate_and_confirm().await?;
        if self.providers.is_empty() {
            let reason = format!("no providers located for {:?}", self.content);
            self.emit(DownloadEvent::Failed {
                reason: reason.clone(),
            })
            .await;
            return Err(DownloadError::NotFound { content: reason });
        }

        // 3. Establish the resource commitment (unless resumed from persisted state).
        if self.commitment.is_none() {
            self.establish_commitment().await?;
        }
        self.discard_bytes_staged_for_another_plan().await;
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
        // The whole-resource backstop hashes ranges incrementally in offset order (O(window) RAM
        // instead of retaining ~2N bytes — MEDIUM #179). It is created whenever the check is enabled —
        // including on a crash-RESUME, where the earlier ranges live only in the staging area and are
        // read back into it below (#1605). A resumed download that skipped this check would be
        // structurally verified ONLY: nothing would bind the assembled bytes to the chain-anchored
        // root, which is the fail-OPEN window the whole verify-then-decrypt read guarantee rests on.
        self.hasher = self.config.verify_whole_resource.then(ResourceHasher::new);
        self.bytes_done = self
            .ranges
            .iter()
            .filter(|r| self.resume.is_done(r.index))
            .map(|r| r.length)
            .sum();
        self.rehydrate_resumed_ranges(&commitment).await;
        self.emit(DownloadEvent::Planned {
            ranges_total: self.ranges.len(),
            total_length: commitment.total_length,
        })
        .await;

        // 5–7. Schedule, verify, reassemble.
        self.schedule_loop().await?;

        // Whole-resource integrity backstop (bind to the chain-anchored root). Fail-closed: EVERY
        // range that makes up the assembled resource was fed to the incremental `hasher` — freshly
        // fetched ones as they verified, resumed ones read back from staging before scheduling
        // (#1605) — so its contiguous hashed length MUST equal the committed total_length.
        // `verify_resource_leaf` returns VerifyError::Length for a short/incomplete assembly rather
        // than being silently skipped, so a short download can never fall through to a successful
        // finalize (CRITICAL #179). The incremental hash avoids retaining every range + a full concat
        // copy (~2N RAM — MEDIUM #179).
        if let Some(hasher) = self.hasher.take() {
            let hashed_len = hasher.hashed_len();
            let leaf = hasher.finalize();
            if let Err(e) = self
                .verifier
                .verify_resource_leaf(&commitment, &leaf, hashed_len)
            {
                self.discard_unverifiable_assembly().await;
                self.emit(DownloadEvent::Failed {
                    reason: e.to_string(),
                })
                .await;
                return Err(e.into());
            }
        }

        // Promote through the ONE proven-promotion seam: the artifact promoted must be exactly the
        // artifact verified above, never a longer or shorter staged one (#1612).
        //
        // A refusal here is fail-closed AND recoverable: the checkpoint that led to it is discarded with
        // the bytes it describes, exactly as a failed backstop does. Otherwise a checkpoint that outlived
        // its staging file (GC reaps `.download.tmp` + its sidecar while the `StateStore` keeps its
        // checkpoint elsewhere) would make every later fetch of this content fail identically, forever —
        // fail-closed must never mean permanently DENIED.
        if let Err(e) = crate::sink::promote_verified(&*self.sink, commitment.total_length).await {
            self.discard_unverifiable_assembly().await;
            self.emit(DownloadEvent::Failed {
                reason: e.to_string(),
            })
            .await;
            return Err(e);
        }
        // Download complete → drop the resume checkpoint.
        let _ = self.state_store.clear(&self.key).await;
        self.emit(DownloadEvent::Completed {
            total_length: commitment.total_length,
        })
        .await;
        Ok(commitment.total_length)
    }

    /// Abandon a checkpoint (and the bytes it staged) that belongs to a DIFFERENT chunk layout than
    /// the one just planned.
    ///
    /// `done_ranges` are range INDICES, so inheriting them across a re-shaped plan would mark
    /// arbitrary byte spans "done and verified". The staging area is equally suspect: no write ever
    /// shortens it, so the abandoned plan's tail would otherwise ride out inside this plan's promotion
    /// (the module path's analogous reset — #1612). Best-effort: the promotion seam's truncate +
    /// confirm probe is the enforcement, this only avoids pointless re-verification work.
    async fn discard_bytes_staged_for_another_plan(&mut self) {
        let Some(planned) = self.commitment.as_ref().map(|c| c.layout.chunk_lens()) else {
            return;
        };
        if self.resume.chunk_lens.is_empty() || self.resume.chunk_lens == planned {
            return; // nothing checkpointed, or checkpointed for exactly this plan
        }
        tracing::warn!(
            key = %self.key,
            "resume checkpoint describes a different chunk layout; discarding it and the bytes it \
             staged rather than mixing two plans"
        );
        self.resume.done_ranges.clear();
        let _ = self.state_store.clear(&self.key).await;
        let _ = self.sink.truncate(0).await;
    }

    /// Feed every range a PRIOR process already completed into this run's whole-resource hasher, by
    /// reading its bytes back out of the staging area — so a crash-resume ends in the SAME
    /// chain-binding backstop as a fresh download (#1605).
    ///
    /// A resumed range's bytes are not in this process's memory, only in the staging area, and the
    /// staging area is not a trusted input (it survives a crash, another process, and bit-rot). Each
    /// range read back is therefore re-checked against the commitment exactly like a freshly-fetched
    /// one, and the whole-resource hash it feeds is what finally binds it to the chain-anchored root.
    ///
    /// A range that cannot be read back (a sink with no read-back support), reads short, or fails its
    /// per-range check is simply returned to `Pending` and RE-FETCHED — resume is an optimization,
    /// never a correctness dependency. The consequence is the invariant that matters: when this
    /// returns, the hasher will see every byte of the resource, so the backstop can never be skipped.
    async fn rehydrate_resumed_ranges(&mut self, commitment: &ResourceCommitment) {
        let resumed: Vec<Range> = self
            .ranges
            .iter()
            .filter(|r| matches!(self.range_state[r.index], RangeState::Done))
            .copied()
            .collect();
        for range in resumed {
            // With no hasher there is NO way to bind these staged bytes to any commitment — the
            // per-range check below is structural (length + alignment), so right-length garbage passes
            // it. Trusting staging in that state promoted arbitrary bytes as a verified success, so a
            // resumed range is instead RE-FETCHED. Staging is never a trusted source of content; whether
            // the whole-resource backstop is enabled changes the strength of the check, never whether
            // one happens.
            let staged = match self.hasher {
                Some(_) => self.sink.read_at(range.offset, range.length).await,
                None => Err(DownloadError::sink(
                    "the whole-resource check is disabled, so staged bytes cannot be bound to the \
                     commitment; re-fetching this range instead of trusting it",
                )),
            };
            let verified = staged.and_then(|bytes| {
                self.verifier
                    .verify_range(commitment, range.chunk_start as u64, range.length, &bytes)
                    .map(|()| bytes)
                    .map_err(DownloadError::from)
            });
            match verified {
                Ok(bytes) => {
                    if let Some(hasher) = self.hasher.as_mut() {
                        hasher.feed(range.offset, bytes);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        range = range.index,
                        offset = range.offset,
                        error = %e,
                        "resumed range could not be re-verified from staging; re-fetching it so the \
                         whole-resource check still runs"
                    );
                    self.range_state[range.index] = RangeState::Pending;
                    self.resume.done_ranges.remove(&range.index);
                    self.bytes_done = self.bytes_done.saturating_sub(range.length);
                }
            }
        }
    }

    /// Discard the checkpoint + staging bytes of an assembly that failed the whole-resource backstop.
    ///
    /// Fail-closed must not mean permanently DENIED: the assembled bytes did not bind to the chain
    /// root, so keeping them would make every later attempt read the same poisoned prefix back and
    /// fail identically. Dropping both lets the next attempt re-fetch from scratch. Best-effort by
    /// design — the verify failure is the outcome the caller must see, so a sink that cannot shorten
    /// its staging area does not get to mask it.
    async fn discard_unverifiable_assembly(&self) {
        let _ = self.state_store.clear(&self.key).await;
        let _ = self.sink.truncate(0).await;
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
                let addrs = p.addresses.iter().map(crate::addr::display).collect();
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
    ///
    /// The answer's `total_length` / `chunk_count` are deliberately NOT retained. They were, to feed a vote
    /// on whether a refutation should be blamed on a holder; both fields are OPTIONAL on the wire and
    /// production dig-node omits them entirely at capsule granularity, so honest holders are routinely
    /// silent and any vote over them is decided by whoever bothers to declare. Reading only `.available`
    /// keeps this leg free of a signal that cannot support a decision.
    async fn locate_and_confirm(&self) -> Result<Vec<ProviderRecord>, DownloadError> {
        let found = self.locator.find_providers(&self.content).await?;
        let item = self.availability_item()?;
        let mut confirmed = Vec::new();
        for p in found.iter().cloned() {
            let answered = self
                .transport
                .query_availability(&p, vec![item.clone()])
                .await;
            let Ok(resp) = answered else { continue };
            let Some(answer) = resp.items.first() else {
                continue;
            };
            if !answer.available {
                continue;
            }
            confirmed.push(p);
        }
        // The provider-index key the locate actually queried, beside what came back. A read that ends
        // with an empty candidate set is otherwise indistinguishable from one whose holders were all
        // dropped at the confirm step — the ambiguity that repeatedly sent #1586 hunting a phantom
        // key mismatch. Printing the key makes a real key divergence visible at a glance.
        tracing::debug!(
            content = ?self.content,
            content_key = %self.content.to_key().to_hex(),
            located = found.len(),
            confirmed = confirmed.len(),
            providers = ?confirmed
                .iter()
                .map(|p| p.provider_peer_id.as_str())
                .collect::<Vec<_>>(),
            "locate_and_confirm: holders for this content key"
        );
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

    /// Establish the [`ResourceCommitment`] via a meta-probe: fetch a tiny range from a holder and read
    /// the whole-resource `chunk_lens` / `total_length` / `root` from its first frame.
    ///
    /// Holders are probed in the order DISCOVERY produced, and the FIRST holder whose declaration survives
    /// every available gate wins. Nothing about which holder supplied the layout is retained, because none of those
    /// gates can distinguish a truthful holder from a consistent liar and nothing later can either — a
    /// whole-resource refutation is terminal and attributes to nobody (see
    /// [`run_inner`](Self::run_inner) for why, and
    /// [`ResourceCommitment`](crate::verify::ResourceCommitment) for what adoption does and does not prove).
    async fn establish_commitment(&mut self) -> Result<(), DownloadError> {
        let candidates = self.providers.clone();
        // One line per holder, so the terminal error can say what each one actually did. Previously these
        // went to `tracing::debug!` and were dropped, so the only fact that identified the fault survived
        // only when debug logging happened to be enabled.
        let mut reasons: Vec<String> = Vec::with_capacity(candidates.len());
        let mut note = |provider: &ProviderRecord, reason: String| {
            let peer = crate::error::hex64_or_sentinel(&provider.provider_peer_id, "peer-id");
            tracing::debug!(
                peer = %peer,
                reason = %reason,
                "establish_commitment: this holder could not seed the resource layout"
            );
            reasons.push(format!("{peer}: {reason}"));
        };

        for provider in &candidates {
            let req = self.range_request(0, 1)?;
            let fetched = match self.probe_metadata(provider, &req).await {
                Ok(fetched) => fetched,
                Err(e) => {
                    // The meta-probe is where a reachable, CONFIRMED holder still fails to seed the
                    // download (a wire/format mismatch, a truncated frame, a refused dial). Naming the
                    // provider + reason is what keeps that from surfacing as a discovery miss (#1586).
                    note(provider, format!("metadata probe failed: {e}"));
                    continue;
                }
            };
            match self.adopt_layout(provider, fetched) {
                Ok(commitment) => {
                    self.commitment = Some(commitment);
                    return Ok(());
                }
                Err(reason) => note(provider, reason),
            }
        }

        // Say WHICH step failed. Holders WERE located and confirmed; not one could seed the layout. A
        // bare content id here reads as "discovery found nobody" and cost four separate #1586
        // investigations, which is why this is its own named error rather than a `NotFound`.
        let error = DownloadError::MetadataProbeFailed {
            content: format!("{:?}", self.content),
            holders: candidates.len(),
            reasons,
        };
        self.emit(DownloadEvent::Failed {
            reason: error.to_string(),
        })
        .await;
        Err(error)
    }

    /// Fetch one holder's metadata probe under [`DownloadConfig::range_timeout`].
    ///
    /// # The timeout is the only thing that bounds this call
    ///
    /// Every ordinary range fetch is already wrapped in this timeout; the metadata probe was not, and it is
    /// the one fetch that runs BEFORE the scheduler exists — so nothing else could interrupt it. It also
    /// never polls the control channel, so `cancel()` cannot reach it either. A holder that accepts the
    /// stream and then trickles frames forever therefore pinned the job indefinitely while it still held
    /// the [`ActiveDownloads`] claim, which makes the staging path both permanently GC-exempt and
    /// permanently un-downloadable — the exact denial the claim exists to prevent.
    ///
    /// The reassembler's own termination guard closes the no-progress variant of that. This closes the
    /// variant where every frame DOES progress, just arbitrarily slowly, which no amount of per-frame
    /// checking can distinguish from a genuinely slow link.
    async fn probe_metadata(
        &self,
        provider: &ProviderRecord,
        req: &RangeRequest,
    ) -> Result<FetchedRange, DownloadError> {
        let fetch = self.transport.fetch_range(provider, req);
        match self.config.range_timeout {
            None => fetch.await,
            Some(limit) => tokio::time::timeout(limit, fetch)
                .await
                .unwrap_or_else(|_| {
                    Err(DownloadError::Timeout {
                        provider: provider.provider_peer_id.clone(),
                    })
                }),
        }
    }

    /// Decide whether `fetched`'s declared metadata may become this download's resource layout, returning
    /// the commitment or the reason to try the next holder.
    ///
    /// Every gate here compares fields the SAME holder supplied, except the root match, which binds to the
    /// CALLER's content id — so this establishes internal consistency and correct generation, never
    /// truthfulness — see [`ResourceCommitment`](crate::verify::ResourceCommitment) for why that gap cannot
    /// be closed from here.
    fn adopt_layout(
        &self,
        provider: &ProviderRecord,
        fetched: FetchedRange,
    ) -> Result<ResourceCommitment, String> {
        let meta = fetched.meta;

        // Bind the ground truth to the CALLER's request, not to whichever peer answers first: a peer
        // whose reported generation root differs from the content-id's root is rejected before anything
        // it says is adopted (HIGH #179). Without this, one peer winning the meta-probe race could shape
        // the whole plan to an attacker-chosen generation, and `check_consistent` would then discard the
        // honest providers.
        if let Some(want) = self.content_root_hex() {
            // `Some(want)` and a MISSING `root` used to fall through this guard, because it only fired when
            // BOTH were present. A layout with no stated generation was therefore adopted and only rejected
            // after the whole resource had been fetched — the same denial as #1670, reached by omitting a
            // field rather than by lying in it. A holder that will not say which generation it serves
            // cannot be checked against the request at all, so it is skipped here.
            match &meta.root {
                Some(got) if got == &want => {}
                Some(got) => {
                    // SANITIZED, not interpolated. `got` is a peer-supplied `Option<String>` with no hex
                    // check on this path, and the caller writes this reason into a `tracing` field as a raw
                    // `String` rather than through `DownloadError`'s sanitizing `Display` — so a holder could
                    // otherwise inject newlines, ANSI or bidi overrides into debug output, up to the frame
                    // ceiling (#1603). `hex64_or_sentinel` renders a well-formed 64-hex root verbatim and
                    // everything else as a fixed sentinel.
                    return Err(format!(
                        "serves generation root {}, not the requested {want}",
                        crate::error::hex64_or_sentinel(got, "root")
                    ));
                }
                None => {
                    return Err(format!(
                        "states no generation root, so it cannot be checked against the requested {want}"
                    ))
                }
            }
        }

        let (Some(total_length), Some(chunk_lens)) = (meta.total_length, meta.chunk_lens) else {
            return Err("first frame declared no total_length/chunk_lens".into());
        };

        // A layout too large to state on one frame is served as a paged prologue, so a first frame can
        // legitimately carry only the FIRST page while declaring the whole array's `chunk_count`. This
        // reader does not reassemble pages yet, so such a holder is one it cannot use.
        //
        // The metadata probe asks for a 1-byte range and therefore stops after the first frame, which is
        // exactly why this is NOT reported as the holder failing to page: from here, a conforming pager
        // and a holder that would never have paged look identical, and guessing would blame a peer that
        // did nothing wrong.
        if let Some(declared) = meta.chunk_count {
            let delivered = chunk_lens.len() as u64;
            if declared != delivered {
                return Err(DownloadError::PagedPrologueUnsupported {
                    provider: provider.provider_peer_id.clone(),
                    chunk_count: declared,
                    delivered,
                }
                .to_string());
            }
        }

        ResourceCommitment::from_first_frame_bounded(
            total_length,
            chunk_lens,
            meta.root,
            meta.inclusion_proof,
            self.config.max_resource_size,
        )
        .map_err(|e| e.to_string())
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
            ContentId::Root { store_id, root } => {
                Ok(AvailabilityItem::store(hex32(store_id)).with_root(hex32(root)))
            }
            ContentId::Resource {
                store_id,
                root,
                retrieval_key,
            } => Ok(AvailabilityItem::store(hex32(store_id))
                .with_root(hex32(root))
                .with_retrieval_key(hex32(retrieval_key))),
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
    ///
    /// `skip_layout` is deliberately left UNSET, which asks every holder for the layout metadata on
    /// every stream — the pre-0.13.0 behaviour. Suppressing it is only correct once the orchestrator
    /// tracks "I already hold a complete `chunk_lens` for this root", and `chunk_lens` is a DECRYPT
    /// input: per-chunk AES-GCM-SIV needs the WHOLE array, so a fan-out that suppressed it before the
    /// first stream had paged in a complete set would produce undecryptable bytes. Asking for
    /// redundant metadata costs bandwidth; asking for none too early costs correctness.
    fn range_request(&self, offset: u64, length: u64) -> Result<RangeRequest, DownloadError> {
        match &self.content {
            ContentId::Store { .. } => Err(DownloadError::NotDownloadable),
            ContentId::Root { store_id, root } => {
                Ok(RangeRequest::capsule(hex32(store_id), offset, length).with_root(hex32(root)))
            }
            ContentId::Resource {
                store_id,
                root,
                retrieval_key,
            } => Ok(
                RangeRequest::resource(hex32(store_id), hex32(retrieval_key), offset, length)
                    .with_root(hex32(root)),
            ),
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
