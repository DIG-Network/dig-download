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
}

/// An in-memory [`StateStore`] — the test store, and the default when no persistence is wanted (a
/// pause+resume within one process still works; a crash loses it). Thread-safe.
#[derive(Debug, Default)]
pub struct InMemoryStateStore {
    inner: tokio::sync::Mutex<std::collections::HashMap<String, DownloadState>>,
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
        let mut name = String::with_capacity(key.len() * 2 + 5);
        for b in key.as_bytes() {
            name.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            name.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
        }
        name.push_str(".json");
        self.dir.join(name)
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
}
