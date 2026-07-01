//! [`Sink`] — where verified bytes land: the node's store-write path.
//!
//! The orchestrator reassembles in order by writing each verified range to the sink at its byte
//! offset. The trait abstracts the destination so tests use an [`InMemorySink`] and dig-node supplies
//! the real store-backed sink (writing the capsule/resource ciphertext into digstore). A sink only
//! ever receives **verified, chunk-aligned** ranges, and each range is written exactly once (a
//! resumed download does not re-write an already-persisted range).
//!
//! ## Staging + atomic finalize
//!
//! A file-backed download streams into a **`<target>.download.tmp`** staging file, never the final
//! path, and only when every range is verified does [`Sink::finalize`] **atomically rename** the tmp
//! file onto the final path ([`FileSink`]). So a reader never sees a partial file and a crash
//! mid-download never corrupts the real one — the tmp file is either promoted whole or garbage-
//! collected ([`crate::gc`]). A sink exposes its [`staging_path`](Sink::staging_path) so the
//! orchestrator can register it with the active-download registry (GC leaves live/paused-resumable
//! staging files alone).

use std::path::Path;

use async_trait::async_trait;

use crate::error::DownloadError;

/// The destination a download writes verified bytes into. Implementations write `bytes` at byte
/// `offset` within the resource; [`finalize`](Self::finalize) is called once when every range is done
/// (e.g. to fsync / commit the store write).
#[async_trait]
pub trait Sink: Send + Sync {
    /// Write `bytes` at `offset` within the resource. Called once per verified range, in arbitrary
    /// range order (the orchestrator fans ranges out concurrently), so an implementation must place
    /// by `offset`, not assume sequential writes.
    async fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<(), DownloadError>;

    /// Called once after the last range is written + verified, to finalize the store write (for a
    /// staged file sink, the **atomic rename** of the `.download.tmp` onto the final path). The
    /// default is a no-op.
    async fn finalize(&self) -> Result<(), DownloadError> {
        Ok(())
    }

    /// The staging (`.download.tmp`) path this sink writes into before finalize, if any. The
    /// orchestrator registers it with the [`ActiveDownloads`](crate::gc::ActiveDownloads) registry so
    /// GC does not reap a live/paused-resumable download's staging file. In-memory sinks return
    /// `None` (nothing on disk to stage or GC).
    fn staging_path(&self) -> Option<&Path> {
        None
    }
}

/// An in-memory [`Sink`] that assembles the resource in a byte buffer — the test sink, and a
/// reference for the trait shape. Thread-safe (writes from concurrent range tasks).
#[derive(Debug, Default)]
pub struct InMemorySink {
    inner: tokio::sync::Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    buf: Vec<u8>,
    finalized: bool,
}

impl InMemorySink {
    /// A new, empty in-memory sink.
    pub fn new() -> Self {
        InMemorySink::default()
    }

    /// A snapshot of the assembled bytes so far.
    pub async fn contents(&self) -> Vec<u8> {
        self.inner.lock().await.buf.clone()
    }

    /// Whether [`Sink::finalize`] has been called.
    pub async fn is_finalized(&self) -> bool {
        self.inner.lock().await.finalized
    }
}

#[async_trait]
impl Sink for InMemorySink {
    async fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<(), DownloadError> {
        let mut inner = self.inner.lock().await;
        let end = offset as usize + bytes.len();
        if inner.buf.len() < end {
            inner.buf.resize(end, 0);
        }
        inner.buf[offset as usize..end].copy_from_slice(bytes);
        Ok(())
    }

    async fn finalize(&self) -> Result<(), DownloadError> {
        self.inner.lock().await.finalized = true;
        Ok(())
    }
}

/// The staging-file suffix appended to a download target: `<target>.download.tmp`. The GC sweep
/// ([`crate::gc`]) matches this suffix, and its sidecar resume state is `<target>` + [`STATE_SUFFIX`].
pub const TMP_SUFFIX: &str = ".download.tmp";

/// The sidecar resume-state suffix paired with a staging file: `<target>.download.tmp.state`.
pub const STATE_SUFFIX: &str = ".download.tmp.state";

/// The `.download.tmp` staging path for a final target path (`<target>.download.tmp`).
pub fn staging_path_for(final_path: &Path) -> std::path::PathBuf {
    let mut s = final_path.as_os_str().to_owned();
    s.push(TMP_SUFFIX);
    std::path::PathBuf::from(s)
}

/// A file-backed [`Sink`] that streams into a `<target>.download.tmp` staging file and, on
/// [`finalize`](Sink::finalize), **atomically renames** it onto the final path.
///
/// - Writes are positioned (`write_at`), so out-of-order range writes land correctly; the file is
///   opened lazily on the first write (create-or-reuse, **never truncating**, so a resumed download
///   reattaches to the same partial staging file and only fills the missing ranges).
/// - `finalize` flushes + syncs + `std::fs::rename`s the tmp onto the final path (atomic on the same
///   filesystem), so a reader never observes a partial file and a crash leaves only a `.download.tmp`
///   (reaped by [`crate::gc`]), never a corrupt final file.
#[derive(Debug)]
pub struct FileSink {
    final_path: std::path::PathBuf,
    tmp_path: std::path::PathBuf,
    file: tokio::sync::Mutex<Option<std::fs::File>>,
}

impl FileSink {
    /// A file sink that finalizes onto `final_path`, staging in `<final_path>.download.tmp`.
    pub fn new(final_path: impl Into<std::path::PathBuf>) -> Self {
        let final_path = final_path.into();
        let tmp_path = staging_path_for(&final_path);
        FileSink {
            final_path,
            tmp_path,
            file: tokio::sync::Mutex::new(None),
        }
    }

    /// The final path this sink promotes to on finalize.
    pub fn final_path(&self) -> &Path {
        &self.final_path
    }

    /// The `.download.tmp` staging path this sink writes into before finalize.
    pub fn tmp_path(&self) -> &Path {
        &self.tmp_path
    }
}

#[async_trait]
impl Sink for FileSink {
    async fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<(), DownloadError> {
        use std::io::{Seek, SeekFrom, Write};
        let mut guard = self.file.lock().await;
        if guard.is_none() {
            if let Some(parent) = self.tmp_path.parent() {
                std::fs::create_dir_all(parent).map_err(DownloadError::sink)?;
            }
            // Create-or-reuse WITHOUT truncating, so a resume reattaches to the existing partial file.
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&self.tmp_path)
                .map_err(DownloadError::sink)?;
            *guard = Some(f);
        }
        let f = guard.as_mut().expect("file opened above");
        f.seek(SeekFrom::Start(offset))
            .map_err(DownloadError::sink)?;
        f.write_all(bytes).map_err(DownloadError::sink)?;
        Ok(())
    }

    async fn finalize(&self) -> Result<(), DownloadError> {
        {
            let mut guard = self.file.lock().await;
            if let Some(f) = guard.as_mut() {
                f.sync_all().map_err(DownloadError::sink)?;
            }
            *guard = None; // close the handle before renaming (Windows requires the handle closed)
        }
        std::fs::rename(&self.tmp_path, &self.final_path).map_err(DownloadError::sink)?;
        Ok(())
    }

    fn staging_path(&self) -> Option<&Path> {
        Some(&self.tmp_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn writes_placed_by_offset_out_of_order() {
        let sink = InMemorySink::new();
        // Write the second half first, then the first — placement is by offset, not order.
        sink.write_at(3, b"DEF").await.unwrap();
        sink.write_at(0, b"ABC").await.unwrap();
        assert_eq!(sink.contents().await, b"ABCDEF");
        assert!(!sink.is_finalized().await);
        sink.finalize().await.unwrap();
        assert!(sink.is_finalized().await);
    }

    #[tokio::test]
    async fn overlapping_write_overwrites() {
        let sink = InMemorySink::new();
        sink.write_at(0, b"ABCDEF").await.unwrap();
        sink.write_at(2, b"xy").await.unwrap();
        assert_eq!(sink.contents().await, b"ABxyEF");
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "dig-download-sink-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn file_sink_stages_then_atomically_finalizes() {
        let dir = temp_dir("finalize");
        let final_path = dir.join("resource.dig");
        let sink = FileSink::new(&final_path);

        // Before finalize: only the .download.tmp exists, the final path does not.
        sink.write_at(3, b"DEF").await.unwrap();
        sink.write_at(0, b"ABC").await.unwrap();
        assert!(sink.tmp_path().exists());
        assert!(!final_path.exists());
        assert_eq!(sink.tmp_path(), staging_path_for(&final_path));

        // Finalize: atomic rename → the final file appears, the tmp is gone.
        sink.finalize().await.unwrap();
        assert!(final_path.exists());
        assert!(!sink.tmp_path().exists());
        assert_eq!(std::fs::read(&final_path).unwrap(), b"ABCDEF");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn file_sink_resume_reattaches_without_truncating() {
        let dir = temp_dir("resume");
        let final_path = dir.join("resource.dig");

        // First sink writes the tail, then is dropped WITHOUT finalizing (a "crash").
        {
            let sink = FileSink::new(&final_path);
            sink.write_at(3, b"DEF").await.unwrap();
        }
        assert!(staging_path_for(&final_path).exists());

        // A new sink for the same target reattaches to the existing tmp and fills the head; the
        // tail written before is preserved (open did not truncate).
        let sink2 = FileSink::new(&final_path);
        sink2.write_at(0, b"ABC").await.unwrap();
        sink2.finalize().await.unwrap();
        assert_eq!(std::fs::read(&final_path).unwrap(), b"ABCDEF");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staging_path_appends_suffix() {
        let p = staging_path_for(Path::new("/data/x.dig"));
        assert!(p.to_string_lossy().ends_with(".dig.download.tmp"));
    }
}
