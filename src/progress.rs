//! Progress reporting + resume state.
//!
//! Two things a caller / a crash-restart needs to see:
//!
//! - **Progress** — a live [`DownloadEvent`] stream (bytes done, per-range completions, source
//!   health, pause/resume, terminal outcome) plus a coalesced [`DownloadProgress`] snapshot, so a UI
//!   or an agent can watch a download without polling.
//! - **Resume state** — a durable [`DownloadState`] (which ranges are complete + verified, and the
//!   resource commitment) written to a [`StateStore`] as the download makes progress, so
//!   [`resume`](crate::DownloadHandle) — after a pause OR a crash — re-fetches only the still-missing
//!   ranges and NEVER a completed+verified one.

use std::collections::BTreeSet;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::DownloadError;

/// A coalesced snapshot of a download's progress — the "how far along" view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DownloadProgress {
    /// Verified bytes written to the sink so far.
    pub bytes_done: u64,
    /// Total resource ciphertext length (0 until the commitment is established).
    pub total_length: u64,
    /// Ranges completed + verified.
    pub ranges_done: usize,
    /// Total ranges in the plan (0 until planned).
    pub ranges_total: usize,
    /// Distinct providers with a range currently in flight.
    pub active_sources: usize,
}

impl DownloadProgress {
    /// Fraction complete in `[0.0, 1.0]` by bytes (0 until the total length is known).
    pub fn fraction(&self) -> f64 {
        if self.total_length == 0 {
            0.0
        } else {
            self.bytes_done as f64 / self.total_length as f64
        }
    }

    /// Whether every planned range is done (and the plan is non-trivial).
    pub fn is_complete(&self) -> bool {
        self.ranges_total > 0 && self.ranges_done == self.ranges_total
    }
}

/// A live event emitted as a download progresses. Delivered on the handle's event stream.
#[derive(Debug, Clone)]
pub enum DownloadEvent {
    /// The resource was located + planned: this many ranges over this total length.
    Planned {
        /// Total ranges in the plan.
        ranges_total: usize,
        /// Total resource ciphertext length.
        total_length: u64,
    },
    /// A range was fetched, verified, and written. Carries the updated coalesced snapshot.
    RangeCompleted {
        /// The range index that completed.
        range: usize,
        /// The provider (64-hex `peer_id`) that served it.
        provider: String,
        /// The progress snapshot after this completion.
        progress: DownloadProgress,
    },
    /// A range fetch from a provider failed (transport or verify) and will be retried elsewhere.
    RangeFailed {
        /// The range index that failed.
        range: usize,
        /// The provider that failed to serve it.
        provider: String,
        /// A short reason (stable text).
        reason: String,
    },
    /// The provider set was refreshed (a `find_providers` re-run) because ranges were running out of
    /// live sources.
    ProvidersRefreshed {
        /// The number of providers now known.
        providers: usize,
    },
    /// The download was paused (no new range fetches will be issued until resumed).
    Paused,
    /// The download was resumed after a pause.
    Resumed,
    /// The download finished successfully — every range verified + written + finalized.
    Completed {
        /// The total verified bytes written.
        total_length: u64,
    },
    /// The download ended in failure (terminal). Carries the reason text.
    Failed {
        /// The terminal failure reason.
        reason: String,
    },
}

/// Durable resume state for one download: the resource commitment metadata + the set of ranges
/// already completed + verified. Serialized to a [`StateStore`] so a paused OR crashed download
/// resumes without re-fetching a verified range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadState {
    /// The download key (a stable id for this content target — see
    /// [`crate::orchestrator::download_key`]).
    pub key: String,
    /// Total resource ciphertext length (once the commitment is established; 0 before).
    pub total_length: u64,
    /// The per-chunk lengths (the commitment's `chunk_lens`), so a resume re-plans identically.
    pub chunk_lens: Vec<u64>,
    /// The chain-anchored generation root (64-hex), if known.
    pub root: Option<String>,
    /// The whole-resource inclusion proof (base64), if known.
    pub inclusion_proof: Option<String>,
    /// Range indices already completed + verified (never re-fetched on resume).
    pub done_ranges: BTreeSet<usize>,
}

impl DownloadState {
    /// A fresh, empty state for `key` (nothing planned or done yet).
    pub fn new(key: impl Into<String>) -> Self {
        DownloadState {
            key: key.into(),
            total_length: 0,
            chunk_lens: Vec::new(),
            root: None,
            inclusion_proof: None,
            done_ranges: BTreeSet::new(),
        }
    }

    /// Whether the resource commitment has been established (chunk layout known).
    pub fn has_commitment(&self) -> bool {
        !self.chunk_lens.is_empty()
    }

    /// Mark range `index` complete.
    pub fn mark_done(&mut self, index: usize) {
        self.done_ranges.insert(index);
    }

    /// Whether range `index` is already complete (and must not be re-fetched).
    pub fn is_done(&self, index: usize) -> bool {
        self.done_ranges.contains(&index)
    }
}

/// How long a persisted bad-descriptor verdict keeps a holder out of the DESCRIPTOR role.
///
/// Reputation decays because a verdict is evidence about a moment, not a permanent label: a holder can
/// be reinstalled, fixed, or have served a stale generation. A verdict that never expired would turn
/// one bad answer into permanent exclusion — and, aggregated, into a denial primitive.
pub const BAD_DESCRIPTOR_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// The most bad-descriptor verdicts retained per target.
///
/// Reputation is written in response to peer behaviour, so it must not itself be a growth vector: the
/// oldest verdict is evicted once the cap is reached. A capsule with more than this many distinct
/// lying holders is not a case reputation can help with.
pub const MAX_BAD_DESCRIPTOR_PEERS: usize = 32;

/// One persisted "this peer served a bad module descriptor" verdict, with when it was recorded (unix
/// seconds) so it can decay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BadDescriptorVerdict {
    /// The 64-hex `peer_id` of the holder whose descriptor failed a final gate.
    pub peer_id: String,
    /// When the verdict was recorded, in unix seconds.
    pub recorded_at_unix: u64,
}

/// The current unix time in seconds (0 if the clock is before the epoch — a clock that absurd only
/// costs the caller a prematurely-expired verdict).
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether `peer_id` is a well-formed 64-hex holder id.
///
/// A `peer_id` arrives off the wire as free-form text, and reputation is the one place where such a
/// string would be PERSISTED and later matched against. Only ids of the canonical shape are stored, so
/// no peer-supplied text can shape a stored key (#1603/#1609).
fn is_hex_peer_id(peer_id: &str) -> bool {
    peer_id.len() == 64 && peer_id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Record `peer_id`'s verdict in `verdicts`, dropping expired ones, de-duplicating (a repeat verdict
/// refreshes the timestamp), and evicting the oldest once [`MAX_BAD_DESCRIPTOR_PEERS`] is reached.
///
/// A malformed (non-64-hex) id is IGNORED rather than stored — see [`is_hex_peer_id`].
fn record_verdict(verdicts: &mut Vec<BadDescriptorVerdict>, peer_id: &str, now: u64) {
    if !is_hex_peer_id(peer_id) {
        return;
    }
    verdicts.retain(|v| !is_expired(v, now) && v.peer_id != peer_id);
    verdicts.push(BadDescriptorVerdict {
        peer_id: peer_id.to_string(),
        recorded_at_unix: now,
    });
    while verdicts.len() > MAX_BAD_DESCRIPTOR_PEERS {
        verdicts.remove(0); // oldest first — the vec stays in insertion order
    }
}

/// The still-live verdicts' peer ids, expired ones dropped.
fn live_peers(verdicts: &[BadDescriptorVerdict], now: u64) -> Vec<String> {
    verdicts
        .iter()
        .filter(|v| !is_expired(v, now))
        .map(|v| v.peer_id.clone())
        .collect()
}

/// Whether a verdict has aged past [`BAD_DESCRIPTOR_TTL`] (a verdict timestamped in the future — a
/// clock step — is treated as current, never as eternally valid).
fn is_expired(verdict: &BadDescriptorVerdict, now: u64) -> bool {
    now.saturating_sub(verdict.recorded_at_unix) > BAD_DESCRIPTOR_TTL.as_secs()
}

/// Persists [`DownloadState`] so a download resumes across pause + process restart.
///
/// The orchestrator checkpoints after each range completes and on pause. A resume loads the state and
/// re-plans; only the ranges NOT in `done_ranges` are fetched. The trait abstracts the medium so
/// tests use an [`InMemoryStateStore`] and a node uses [`FileStateStore`] (or a store-backed one).
#[async_trait]
pub trait StateStore: Send + Sync {
    /// Load the persisted state for `key`, or `None` if there is no checkpoint yet.
    async fn load(&self, key: &str) -> Result<Option<DownloadState>, DownloadError>;

    /// Persist `state` (overwriting any prior checkpoint for its key).
    async fn save(&self, state: &DownloadState) -> Result<(), DownloadError>;

    /// Delete the checkpoint for `key` (called after a successful, finalized download).
    async fn clear(&self, key: &str) -> Result<(), DownloadError>;

    /// Remember that `peer_id` supplied a descriptor for `target_key` that failed a final integrity
    /// gate, so a later call — or a later PROCESS — does not pay for the same lie again.
    ///
    /// Demotion within one pull is not enough: the holder order is deterministic, so a fresh call, a
    /// retry, or a restart re-asks the same liars from scratch, each paying up to
    /// `MAX_DESCRIPTOR_ATTEMPTS` full pull attempts in bandwidth and staging disk (#1611).
    ///
    /// A verdict is advisory and decays ([`BAD_DESCRIPTOR_TTL`]); it must never become a denial
    /// primitive, so a caller consults it to ORDER/FILTER descriptor sources and falls back to the
    /// full holder set rather than giving up. Demoted holders stay fully usable for CHUNK fetches —
    /// chunk bytes are independently hash-attributed, so excluding them would cost availability for no
    /// integrity gain.
    ///
    /// The default is a no-op, so an existing [`StateStore`] keeps compiling and simply forgets
    /// reputation between calls (the pre-#1611 behaviour — an efficiency loss, never a correctness one).
    async fn record_bad_descriptor(
        &self,
        target_key: &str,
        peer_id: &str,
    ) -> Result<(), DownloadError> {
        let _ = (target_key, peer_id);
        Ok(())
    }

    /// The peers with a still-live [`record_bad_descriptor`](Self::record_bad_descriptor) verdict for
    /// `target_key`. The default returns none (this store keeps no reputation).
    async fn bad_descriptor_peers(&self, target_key: &str) -> Result<Vec<String>, DownloadError> {
        let _ = target_key;
        Ok(Vec::new())
    }
}

/// An in-memory [`StateStore`] — the test store, and the default when no persistence is wanted (a
/// pause+resume within one process still works; a crash loses it). Thread-safe.
#[derive(Debug, Default)]
pub struct InMemoryStateStore {
    inner: tokio::sync::Mutex<std::collections::HashMap<String, DownloadState>>,
    /// Bad-descriptor verdicts per target key — reputation that survives a repeat CALL, though not (by
    /// construction) a process restart. [`FileStateStore`] is the durable one.
    reputation: tokio::sync::Mutex<std::collections::HashMap<String, Vec<BadDescriptorVerdict>>>,
}

impl InMemoryStateStore {
    /// A new, empty in-memory state store.
    pub fn new() -> Self {
        InMemoryStateStore::default()
    }
}

#[async_trait]
impl StateStore for InMemoryStateStore {
    async fn load(&self, key: &str) -> Result<Option<DownloadState>, DownloadError> {
        Ok(self.inner.lock().await.get(key).cloned())
    }

    async fn save(&self, state: &DownloadState) -> Result<(), DownloadError> {
        self.inner
            .lock()
            .await
            .insert(state.key.clone(), state.clone());
        Ok(())
    }

    async fn clear(&self, key: &str) -> Result<(), DownloadError> {
        self.inner.lock().await.remove(key);
        Ok(())
    }

    async fn record_bad_descriptor(
        &self,
        target_key: &str,
        peer_id: &str,
    ) -> Result<(), DownloadError> {
        let mut reputation = self.reputation.lock().await;
        let verdicts = reputation.entry(target_key.to_string()).or_default();
        record_verdict(verdicts, peer_id, unix_now());
        Ok(())
    }

    async fn bad_descriptor_peers(&self, target_key: &str) -> Result<Vec<String>, DownloadError> {
        let reputation = self.reputation.lock().await;
        Ok(reputation
            .get(target_key)
            .map(|v| live_peers(v, unix_now()))
            .unwrap_or_default())
    }
}

/// A file-backed [`StateStore`]: one JSON checkpoint file per download key, under a directory. A
/// crashed download resumes by re-reading its checkpoint. The filename is a hex encoding of the key so
/// it is filesystem-safe.
#[derive(Debug, Clone)]
pub struct FileStateStore {
    dir: std::path::PathBuf,
}

impl FileStateStore {
    /// A file state store writing checkpoints under `dir` (created on first save if missing).
    pub fn new(dir: impl Into<std::path::PathBuf>) -> Self {
        FileStateStore { dir: dir.into() }
    }

    fn path_for(&self, key: &str) -> std::path::PathBuf {
        self.file_for(key, ".json")
    }

    /// The reputation sidecar beside a target's checkpoint. Kept SEPARATE from the checkpoint because
    /// the two have different lifetimes: a checkpoint is cleared the moment a download completes, while
    /// what a holder did must outlive that success.
    fn reputation_path_for(&self, key: &str) -> std::path::PathBuf {
        self.file_for(key, ".holders.json")
    }

    /// `<hex(key)><suffix>` under this store's directory — the key is hex-encoded so no key text can
    /// shape a path.
    fn file_for(&self, key: &str, suffix: &str) -> std::path::PathBuf {
        let mut name = String::with_capacity(key.len() * 2 + suffix.len());
        for b in key.as_bytes() {
            name.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            name.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
        }
        name.push_str(suffix);
        self.dir.join(name)
    }

    /// The verdicts persisted for `key` (an absent or unreadable sidecar reads as none — reputation is
    /// advisory, so it must never fail a download).
    fn read_verdicts(&self, key: &str) -> Vec<BadDescriptorVerdict> {
        std::fs::read(self.reputation_path_for(key))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }
}

#[async_trait]
impl StateStore for FileStateStore {
    async fn load(&self, key: &str) -> Result<Option<DownloadState>, DownloadError> {
        let path = self.path_for(key);
        match std::fs::read(&path) {
            Ok(bytes) => {
                let state = serde_json::from_slice(&bytes).map_err(DownloadError::state)?;
                Ok(Some(state))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(DownloadError::state(e)),
        }
    }

    async fn save(&self, state: &DownloadState) -> Result<(), DownloadError> {
        std::fs::create_dir_all(&self.dir).map_err(DownloadError::state)?;
        let bytes = serde_json::to_vec(state).map_err(DownloadError::state)?;
        std::fs::write(self.path_for(&state.key), bytes).map_err(DownloadError::state)
    }

    async fn clear(&self, key: &str) -> Result<(), DownloadError> {
        match std::fs::remove_file(self.path_for(key)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(DownloadError::state(e)),
        }
    }

    async fn record_bad_descriptor(
        &self,
        target_key: &str,
        peer_id: &str,
    ) -> Result<(), DownloadError> {
        let mut verdicts = self.read_verdicts(target_key);
        record_verdict(&mut verdicts, peer_id, unix_now());
        std::fs::create_dir_all(&self.dir).map_err(DownloadError::state)?;
        let bytes = serde_json::to_vec(&verdicts).map_err(DownloadError::state)?;
        std::fs::write(self.reputation_path_for(target_key), bytes).map_err(DownloadError::state)
    }

    async fn bad_descriptor_peers(&self, target_key: &str) -> Result<Vec<String>, DownloadError> {
        Ok(live_peers(&self.read_verdicts(target_key), unix_now()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_fraction_and_complete() {
        let mut p = DownloadProgress {
            total_length: 100,
            bytes_done: 25,
            ranges_total: 4,
            ranges_done: 1,
            active_sources: 2,
        };
        assert!((p.fraction() - 0.25).abs() < 1e-9);
        assert!(!p.is_complete());
        p.ranges_done = 4;
        p.bytes_done = 100;
        assert!(p.is_complete());
        assert_eq!(DownloadProgress::default().fraction(), 0.0);
    }

    #[test]
    fn state_marks_and_queries_done() {
        let mut s = DownloadState::new("k");
        assert!(!s.is_done(2));
        s.mark_done(2);
        assert!(s.is_done(2));
        assert_eq!(s.done_ranges.len(), 1);
    }

    #[tokio::test]
    async fn in_memory_store_round_trips() {
        let store = InMemoryStateStore::new();
        assert!(store.load("k").await.unwrap().is_none());
        let mut s = DownloadState::new("k");
        s.mark_done(1);
        s.total_length = 42;
        store.save(&s).await.unwrap();
        assert_eq!(store.load("k").await.unwrap().unwrap(), s);
        store.clear("k").await.unwrap();
        assert!(store.load("k").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn file_store_round_trips_and_survives_reload() {
        let dir = std::env::temp_dir().join(format!(
            "dig-download-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = FileStateStore::new(&dir);
        assert!(store.load("abc").await.unwrap().is_none());

        let mut s = DownloadState::new("abc");
        s.total_length = 100;
        s.chunk_lens = vec![10, 20];
        s.root = Some("aa".repeat(32));
        s.mark_done(0);
        store.save(&s).await.unwrap();

        // A brand-new store instance (simulating a process restart) reads the same checkpoint.
        let reloaded = FileStateStore::new(&dir);
        assert_eq!(reloaded.load("abc").await.unwrap().unwrap(), s);

        store.clear("abc").await.unwrap();
        assert!(store.load("abc").await.unwrap().is_none());
        // clear on a missing key is a no-op.
        store.clear("abc").await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn download_event_variants_construct() {
        // Smoke: the event shapes build (exercised richly in the orchestrator tests).
        let _ = DownloadEvent::Planned {
            ranges_total: 3,
            total_length: 30,
        };
        let _ = DownloadEvent::Paused;
        let _ = DownloadEvent::Resumed;
        let _ = DownloadEvent::ProvidersRefreshed { providers: 2 };
        let _ = DownloadEvent::Completed { total_length: 30 };
        let _ = DownloadEvent::Failed { reason: "x".into() };
    }

    #[tokio::test]
    async fn in_memory_store_remembers_a_bad_descriptor_verdict() {
        let store = InMemoryStateStore::new();
        let peer = "ab".repeat(32);
        assert!(store.bad_descriptor_peers("k").await.unwrap().is_empty());
        store.record_bad_descriptor("k", &peer).await.unwrap();
        assert_eq!(store.bad_descriptor_peers("k").await.unwrap(), vec![peer]);
        // Reputation is per TARGET: another capsule's holders are unaffected.
        assert!(store
            .bad_descriptor_peers("other")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn file_store_reputation_survives_a_process_restart_and_outlives_the_checkpoint() {
        let dir = std::env::temp_dir().join(format!(
            "dig-download-rep-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = FileStateStore::new(&dir);
        let peer = "cd".repeat(32);
        store
            .record_bad_descriptor("module:x", &peer)
            .await
            .unwrap();

        // A brand-new instance (a restarted process) still sees the verdict — the durability the
        // in-call `demoted` vec never had.
        let restarted = FileStateStore::new(&dir);
        assert_eq!(
            restarted.bad_descriptor_peers("module:x").await.unwrap(),
            vec![peer.clone()]
        );

        // Clearing the CHECKPOINT must not forget what a holder did: the two have different lifetimes.
        restarted.clear("module:x").await.unwrap();
        assert_eq!(
            restarted.bad_descriptor_peers("module:x").await.unwrap(),
            vec![peer]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A verdict DECAYS: one bad answer must not exclude a holder forever (holders get fixed, and a
    /// verdict can be the record of a stale generation).
    #[test]
    fn a_verdict_expires_after_its_ttl() {
        let now = 10_000_000u64;
        let fresh = BadDescriptorVerdict {
            peer_id: "ab".repeat(32),
            recorded_at_unix: now - 60,
        };
        let stale = BadDescriptorVerdict {
            peer_id: "cd".repeat(32),
            recorded_at_unix: now - BAD_DESCRIPTOR_TTL.as_secs() - 1,
        };
        assert_eq!(
            live_peers(&[fresh.clone(), stale], now),
            vec![fresh.peer_id],
            "only the un-expired verdict is live"
        );
    }

    /// Reputation is written in response to peer behaviour, so it must not itself grow without bound:
    /// the record is capped and a repeat verdict refreshes rather than duplicates.
    #[test]
    fn the_verdict_record_is_bounded_and_deduplicated() {
        let now = 10_000_000u64;
        let mut verdicts = Vec::new();
        for i in 0..(MAX_BAD_DESCRIPTOR_PEERS + 10) {
            record_verdict(&mut verdicts, &format!("{i:064x}"), now);
        }
        assert_eq!(verdicts.len(), MAX_BAD_DESCRIPTOR_PEERS, "capped");
        assert!(
            !verdicts.iter().any(|v| v.peer_id == format!("{:064x}", 0)),
            "the oldest verdicts were evicted first"
        );

        let repeat = format!("{:064x}", MAX_BAD_DESCRIPTOR_PEERS + 9);
        record_verdict(&mut verdicts, &repeat, now + 5);
        assert_eq!(
            verdicts.iter().filter(|v| v.peer_id == repeat).count(),
            1,
            "a repeat verdict refreshes the entry instead of duplicating it"
        );
    }

    /// A `peer_id` is free-form text off the wire, and reputation is the one place it would be
    /// PERSISTED and later matched: a malformed id is dropped, never stored.
    #[test]
    fn a_malformed_peer_id_is_never_recorded() {
        let mut verdicts = Vec::new();
        record_verdict(&mut verdicts, "../../etc/passwd", 1);
        record_verdict(&mut verdicts, "not-hex", 1);
        record_verdict(&mut verdicts, &"ab".repeat(31), 1); // too short
        assert!(
            verdicts.is_empty(),
            "only 64-hex ids are stored: {verdicts:?}"
        );
    }
}
