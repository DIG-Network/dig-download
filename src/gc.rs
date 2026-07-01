//! Garbage-collection of stale `.download.tmp` staging files.
//!
//! A file-backed download stages into `<target>.download.tmp` and only atomically renames it onto the
//! final path once complete ([`crate::sink::FileSink`]). A download that is **cancelled, abandoned, or
//! killed by a crash** leaves its `.download.tmp` (and any sidecar `.download.tmp.state`) behind. This
//! module reaps those — but **never** a staging file belonging to a live or paused-resumable download.
//!
//! The distinction is an [`ActiveDownloads`] registry: the orchestrator **registers** a staging path
//! while its download is running or paused-resumable and **unregisters** it on successful finalize (or
//! deliberate abandonment). [`TmpGc::sweep`] removes only staging files that are (a) NOT in the
//! registry AND (b) older than a staleness `ttl` — so a paused download's file (registered) is kept,
//! and a crashed process's orphan (registry lost, file old) is reaped. Run it on an interval, the way
//! dig-dht runs its provider-record `gc()`/republish loop.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::Mutex;

use crate::error::DownloadError;
use crate::sink::{STATE_SUFFIX, TMP_SUFFIX};

/// A registry of `.download.tmp` staging paths that belong to **live or paused-resumable** downloads,
/// so [`TmpGc`] leaves them alone. Presence == protected. Shared (`Arc`) between the [`Downloader`] and
/// its GC sweep.
///
/// [`Downloader`]: crate::Downloader
#[derive(Debug, Default)]
pub struct ActiveDownloads {
    protected: Mutex<HashSet<PathBuf>>,
}

impl ActiveDownloads {
    /// A new, empty registry.
    pub fn new() -> Self {
        ActiveDownloads::default()
    }

    /// Mark `path` as belonging to an active/paused-resumable download (GC will skip it).
    pub async fn register(&self, path: impl Into<PathBuf>) {
        self.protected.lock().await.insert(path.into());
    }

    /// Release `path` — it is no longer protected and becomes GC-eligible once stale (called on
    /// finalize or deliberate abandonment).
    pub async fn unregister(&self, path: &Path) {
        self.protected.lock().await.remove(path);
    }

    /// Whether `path` is currently protected.
    pub async fn is_protected(&self, path: &Path) -> bool {
        self.protected.lock().await.contains(path)
    }

    /// The number of currently-protected staging paths.
    pub async fn len(&self) -> usize {
        self.protected.lock().await.len()
    }

    /// Whether the registry is empty.
    pub async fn is_empty(&self) -> bool {
        self.protected.lock().await.is_empty()
    }
}

/// Configuration for the staging-file GC sweep.
#[derive(Debug, Clone)]
pub struct GcConfig {
    /// The download/cache directory holding `.download.tmp` staging files.
    pub dir: PathBuf,
    /// A staging file with no active handle is reaped once it is older than this (by mtime).
    pub ttl: Duration,
    /// How often the background loop runs the sweep.
    pub interval: Duration,
}

impl GcConfig {
    /// A config sweeping `dir` with a one-hour staleness TTL and a ten-minute sweep interval.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        GcConfig {
            dir: dir.into(),
            ttl: Duration::from_secs(3600),
            interval: Duration::from_secs(600),
        }
    }
}

/// Sweeps stale, unprotected `.download.tmp` staging files (+ their sidecar state) from a directory.
#[derive(Clone)]
pub struct TmpGc {
    dir: PathBuf,
    ttl: Duration,
    registry: Arc<ActiveDownloads>,
}

impl TmpGc {
    /// A sweeper over `dir` with staleness `ttl`, honouring `registry` (protected paths are skipped).
    pub fn new(dir: impl Into<PathBuf>, ttl: Duration, registry: Arc<ActiveDownloads>) -> Self {
        TmpGc {
            dir: dir.into(),
            ttl,
            registry,
        }
    }

    /// Run one sweep at wall-clock `now`: remove every `.download.tmp` in the directory that is NOT
    /// registered as active/paused-resumable AND whose mtime is older than `ttl`. Returns the number
    /// of staging files removed (their sidecar `.state` is removed with them).
    ///
    /// `now` is injected so a caller/test controls the staleness cutoff deterministically; use
    /// [`sweep`](Self::sweep) for the current time.
    pub async fn sweep_at(&self, now: SystemTime) -> Result<usize, DownloadError> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(DownloadError::state(e)),
        };
        let mut removed = 0usize;
        for entry in entries {
            let entry = entry.map_err(DownloadError::state)?;
            let path = entry.path();
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };
            // Only staging files (skip their .state sidecars here; they are removed alongside).
            if !name.ends_with(TMP_SUFFIX) || name.ends_with(STATE_SUFFIX) {
                continue;
            }
            if self.registry.is_protected(&path).await {
                continue; // live or paused-resumable — never reap
            }
            if !is_stale(&path, now, self.ttl) {
                continue; // recently touched — a young orphan, give it time
            }
            std::fs::remove_file(&path).map_err(DownloadError::state)?;
            removed += 1;
            // Remove the sidecar resume state, if present.
            let sidecar = sidecar_state_path(&path);
            match std::fs::remove_file(&sidecar) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(DownloadError::state(e)),
            }
        }
        Ok(removed)
    }

    /// Run one sweep at the current wall-clock time.
    pub async fn sweep(&self) -> Result<usize, DownloadError> {
        self.sweep_at(SystemTime::now()).await
    }

    /// The directory this sweeper scans.
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// The sidecar resume-state path for a staging file (`<tmp>.state`, i.e. `<target>.download.tmp.state`).
fn sidecar_state_path(tmp_path: &Path) -> PathBuf {
    // The staging file is `<target>.download.tmp`; strip the tmp suffix and append the state suffix.
    let s = tmp_path.to_string_lossy();
    let base = s.strip_suffix(TMP_SUFFIX).unwrap_or(&s);
    PathBuf::from(format!("{base}{STATE_SUFFIX}"))
}

/// Whether `path`'s mtime is older than `ttl` relative to `now` (a missing/unreadable mtime is
/// treated as stale so a broken orphan can still be reaped).
fn is_stale(path: &Path, now: SystemTime, ttl: Duration) -> bool {
    match std::fs::metadata(path).and_then(|m| m.modified()) {
        Ok(mtime) => match now.duration_since(mtime) {
            Ok(age) => age >= ttl,
            Err(_) => false, // mtime is in the future (clock skew) — treat as fresh
        },
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "dig-download-gc-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn make_tmp(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(format!("{name}{TMP_SUFFIX}"));
        std::fs::write(&p, b"partial").unwrap();
        p
    }

    #[tokio::test]
    async fn sweeps_stale_orphan_and_its_sidecar() {
        let dir = temp_dir("orphan");
        let tmp = make_tmp(&dir, "resource");
        let sidecar = sidecar_state_path(&tmp);
        std::fs::write(&sidecar, b"{}").unwrap();

        let registry = Arc::new(ActiveDownloads::new());
        let gc = TmpGc::new(&dir, Duration::from_secs(60), registry);
        // now = far in the future → the file is older than the TTL → reaped (with its sidecar).
        let removed = gc
            .sweep_at(SystemTime::now() + Duration::from_secs(3600))
            .await
            .unwrap();
        assert_eq!(removed, 1);
        assert!(!tmp.exists());
        assert!(!sidecar.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn keeps_fresh_orphan_within_ttl() {
        let dir = temp_dir("fresh");
        let tmp = make_tmp(&dir, "resource");
        let gc = TmpGc::new(
            &dir,
            Duration::from_secs(3600),
            Arc::new(ActiveDownloads::new()),
        );
        // now == build time → age ~0 < ttl → kept.
        let removed = gc.sweep_at(SystemTime::now()).await.unwrap();
        assert_eq!(removed, 0);
        assert!(tmp.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn never_reaps_a_protected_paused_download() {
        let dir = temp_dir("protected");
        let tmp = make_tmp(&dir, "resource");
        let registry = Arc::new(ActiveDownloads::new());
        registry.register(tmp.clone()).await; // paused-resumable → protected
        let gc = TmpGc::new(&dir, Duration::from_secs(60), registry.clone());
        // Even far in the future (well past TTL), a protected file is NOT reaped.
        let removed = gc
            .sweep_at(SystemTime::now() + Duration::from_secs(9999))
            .await
            .unwrap();
        assert_eq!(removed, 0);
        assert!(tmp.exists());
        assert!(registry.is_protected(&tmp).await);

        // Once unregistered (abandoned), the next stale sweep reaps it.
        registry.unregister(&tmp).await;
        let removed = gc
            .sweep_at(SystemTime::now() + Duration::from_secs(9999))
            .await
            .unwrap();
        assert_eq!(removed, 1);
        assert!(!tmp.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn sweep_missing_dir_is_ok() {
        let gc = TmpGc::new(
            std::env::temp_dir().join("dig-download-gc-does-not-exist-xyz"),
            Duration::from_secs(1),
            Arc::new(ActiveDownloads::new()),
        );
        assert_eq!(gc.sweep().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn registry_register_unregister() {
        let r = ActiveDownloads::new();
        assert!(r.is_empty().await);
        r.register("/a/b.download.tmp").await;
        assert_eq!(r.len().await, 1);
        assert!(r.is_protected(Path::new("/a/b.download.tmp")).await);
        r.unregister(Path::new("/a/b.download.tmp")).await;
        assert!(r.is_empty().await);
    }

    #[test]
    fn sidecar_path_derivation() {
        let tmp = PathBuf::from("/data/x.dig.download.tmp");
        assert_eq!(
            sidecar_state_path(&tmp),
            PathBuf::from("/data/x.dig.download.tmp.state")
        );
    }
}
