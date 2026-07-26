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

use crate::error::{DownloadError, VerifyError};

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

    /// Reduce the staging area to exactly `len` bytes, discarding anything beyond it.
    ///
    /// A staging area is APPEND-OR-OVERWRITE by offset and is never shortened by writing, so bytes
    /// from a LONGER earlier attempt — a demoted descriptor's fabrication, or a leftover file from a
    /// differently-shaped pull — outlive the attempt that wrote them. Promotion is only meaningful if
    /// the promoted artifact IS the verified one, so the module puller shortens the staging area to the
    /// verified length before finalizing, and resets it to 0 when it abandons a plan.
    ///
    /// Only ever SHRINKS: a `len` at or beyond the staged end is a no-op (never zero-extends).
    ///
    /// The default is **fail-closed**: an implementation that does not override this returns
    /// [`DownloadError::Sink`]. A silent no-op default here used to combine with `read_at`'s default to
    /// fail OPEN — `truncate` claimed success without shortening anything, so the "bytes past the
    /// verified end" promotion probe read `read_at`'s "unsupported" as "nothing past the end" and
    /// promoted whatever longer, un-truncated bytes were staged.
    ///
    /// A sink with genuinely no staging area to shorten — a store-write sink that commits the WHOLE
    /// resource in one shot and can never hold a partially-overwritten tail — MUST opt IN explicitly:
    ///
    /// ```ignore
    /// async fn truncate(&self, _len: u64) -> Result<(), DownloadError> {
    ///     Ok(()) // asserts: this sink commits whole, so there is never a tail to shrink
    /// }
    ///
    /// // …and it MUST also make its staged length OBSERVABLE, or it can never be promoted — reading
    /// // THE ARTIFACT `finalize` promotes, never a cache or shadow buffer of it:
    /// fn supports_read_back(&self) -> bool { true }
    /// async fn read_at(&self, offset: u64, len: u64) -> Result<Vec<u8>, DownloadError> { … }
    /// ```
    ///
    /// **`truncate` alone is not enough.** Overriding it while leaving `read_at` on its default used to
    /// be the recipe this doc gave, and it fails OPEN: nothing is shortened, the probe's "unsupported"
    /// reads as "nothing there", and an unproven artifact is promoted. Promotion therefore requires
    /// [`supports_read_back`](Self::supports_read_back), and a sink that cannot expose its staged bytes
    /// is refused promotion rather than trusted.
    async fn truncate(&self, _len: u64) -> Result<(), DownloadError> {
        Err(DownloadError::sink("truncation unsupported by this sink"))
    }

    /// Whether this sink can [`read_at`](Self::read_at) its own staged bytes — i.e. whether its staged
    /// LENGTH is observable, which is what makes a promotion provable.
    ///
    /// The default is **`false`**, and a sink that reports `false` is REFUSED promotion. This is the one
    /// distinction that keeps "read-back unsupported" from being read as "nothing is staged there":
    /// both surface as an `Err` from `read_at`, and conflating them is precisely how a longer
    /// un-truncated artifact used to be promoted (and how a SHORTER one would be). An implementation
    /// that overrides `read_at` MUST override this too.
    fn supports_read_back(&self) -> bool {
        false
    }

    /// Read back `len` bytes previously [`write_at`](Self::write_at)-ten at `offset` from the staging
    /// area, if this sink supports it (see [`supports_read_back`](Self::supports_read_back)).
    ///
    /// Two callers need it. A whole-`.dig`-module pull ([`ModuleDownloader`](crate::ModuleDownloader))
    /// reads already-verified chunks back on **resume** rather than re-fetching them, and a resumed
    /// resource download reads its prior process's ranges back to feed the whole-resource backstop
    /// (#1605). Both degrade gracefully by RE-FETCHING what they cannot read back — never a silent
    /// partial. [`promote_verified`] additionally uses it to PROVE the staged length equals the verified
    /// one, and that use does not degrade: it fails closed.
    ///
    /// An `Err` means "these bytes are not readable" (absent, short, or unsupported); it never means
    /// "nothing is staged".
    ///
    /// **`read_at` MUST read the artifact [`finalize`](Self::finalize) will promote** — not a write-back
    /// cache, a shadow buffer, or anything else that merely mirrors it. This is the whole remaining trust
    /// assumption of [`promote_verified`]: the length proof compares what `read_at` reports against the
    /// verified length, so a sink answering from a shadow can satisfy the proof while the artifact
    /// actually promoted keeps a longer tail. Nothing in this crate can enforce that — it is the
    /// implementer's obligation.
    async fn read_at(&self, _offset: u64, _len: u64) -> Result<Vec<u8>, DownloadError> {
        Err(DownloadError::sink("read-back unsupported by this sink"))
    }

    /// The staging (`.download.tmp`) path this sink writes into before finalize, if any. The
    /// orchestrator registers it with the [`ActiveDownloads`](crate::gc::ActiveDownloads) registry so
    /// GC does not reap a live/paused-resumable download's staging file. In-memory sinks return
    /// `None` (nothing on disk to stage or GC).
    fn staging_path(&self) -> Option<&Path> {
        None
    }
}

/// The `[start, end)` usize bounds of a read-back window, or a typed error if the span cannot exist.
///
/// `offset` / `len` are derived from a peer-supplied module descriptor, so the conversion and the
/// addition must both be CHECKED: on a 32-bit target `as usize` silently truncates, and `start + len`
/// can wrap — either turning a hostile span into a read of the wrong bytes instead of a rejection.
fn read_back_bounds(offset: u64, len: u64) -> Result<(usize, usize), DownloadError> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| span_too_large(offset, len))?;
    let start = usize::try_from(offset).map_err(|_| span_too_large(offset, len))?;
    let end = usize::try_from(end).map_err(|_| span_too_large(offset, len))?;
    Ok((start, end))
}

fn span_too_large(offset: u64, len: u64) -> DownloadError {
    DownloadError::sink(format!(
        "read-back span [{offset}, +{len}) does not fit this platform's address space"
    ))
}

/// Allocate a `len`-byte read-back buffer FALLIBLY.
///
/// `len` comes from an untrusted descriptor's chunk length, and `vec![0u8; len]` aborts the process
/// via `handle_alloc_error` — an uncatchable death. `try_reserve` makes exhaustion an ordinary
/// [`DownloadError::Sink`] the puller can route around.
fn try_zeroed_read_buffer(len: u64) -> Result<Vec<u8>, DownloadError> {
    let len = usize::try_from(len).map_err(|_| span_too_large(0, len))?;
    let mut buf: Vec<u8> = Vec::new();
    buf.try_reserve_exact(len).map_err(|e| {
        DownloadError::sink(format!(
            "cannot allocate a {len}-byte read-back buffer: {e}"
        ))
    })?;
    buf.resize(len, 0); // within the reservation above — no further allocation
    Ok(buf)
}

/// Promote a sink's staging area, having PROVEN it holds exactly the `verified_len` bytes the caller's
/// integrity gates verified — the ONE promotion path for every download in this crate.
///
/// Verification runs over the bytes a download ASSEMBLED; [`Sink::finalize`] promotes the STAGING
/// AREA — and the two are the same artifact only if nothing longer was ever staged. A staging area is
/// written by offset and never shortened, so a longer earlier attempt (a demoted descriptor's
/// fabrication, another shape's partial pull, a leftover `.download.tmp`) leaves a tail the verified
/// bytes do not contain. Promoting that caches an artifact whose hash is not the verified one while
/// reporting success — the node then re-announces itself as an authoritative source of corrupt
/// content.
///
/// So the staging area is SHORTENED to the verified length and its length is then PROVEN, from BOTH
/// sides, before finalize:
///
/// 1. the sink must be able to observe its own staged bytes at all
///    ([`Sink::supports_read_back`]) — a sink that cannot is refused, never trusted;
/// 2. the last verified byte MUST be readable — otherwise the staging area is SHORTER than what was
///    verified, and promoting it renames a partial artifact onto the final path while reporting
///    success;
/// 3. the byte AT `verified_len` MUST NOT be readable — otherwise bytes past the verified end survive.
///
/// A one-sided check (3 alone) fails OPEN on the short side, with the same observable signature as the
/// long side it was written for: `Ok(verified_len)` plus a wrong artifact. `truncate` only ever shrinks,
/// so it cannot fix a short staging area — only this length proof can catch one.
///
/// # Errors
/// [`DownloadError::Verify`] when the staged length is not exactly `verified_len`, or when the sink
/// cannot prove its staged length at all; [`DownloadError::Sink`] when the sink cannot shorten its
/// staging area (a sink with nothing to shorten opts in explicitly — see [`Sink::truncate`]).
pub(crate) async fn promote_verified(
    sink: &dyn Sink,
    verified_len: u64,
) -> Result<(), DownloadError> {
    sink.truncate(verified_len).await?;

    let refuse = |reason: String| Err(DownloadError::Verify(VerifyError::Metadata(reason)));

    if !sink.supports_read_back() {
        return refuse(format!(
            "this sink cannot read back its staging area, so a promotion of {verified_len} verified \
             byte(s) cannot be proven to be the verified artifact; refusing to promote"
        ));
    }
    // The LAST verified byte must be there. `truncate` never extends, so a staging area shorter than
    // the verified length survives it untouched and would otherwise promote as a success.
    if verified_len > 0 && sink.read_at(verified_len - 1, 1).await.is_err() {
        return refuse(format!(
            "staging area is SHORTER than the verified length {verified_len}; refusing to promote a \
             partial artifact as the verified one"
        ));
    }
    // And nothing may live past it.
    if sink.read_at(verified_len, 1).await.is_ok() {
        return refuse(format!(
            "staging area holds bytes past the verified length {verified_len}; refusing to promote an \
             artifact that is not the verified one"
        ));
    }
    sink.finalize().await
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
        // Same CHECKED conversion as `read_at`: a write offset is descriptor-derived too, and one
        // unchecked `as usize` pair is all it takes to place bytes at a wrapped index.
        let (start, end) = read_back_bounds(offset, bytes.len() as u64)?;
        if inner.buf.len() < end {
            inner.buf.resize(end, 0);
        }
        inner.buf[start..end].copy_from_slice(bytes);
        Ok(())
    }

    async fn finalize(&self) -> Result<(), DownloadError> {
        self.inner.lock().await.finalized = true;
        Ok(())
    }

    fn supports_read_back(&self) -> bool {
        true // an in-memory buffer always knows its own length
    }

    async fn truncate(&self, len: u64) -> Result<(), DownloadError> {
        let mut inner = self.inner.lock().await;
        if let Ok(len) = usize::try_from(len) {
            if inner.buf.len() > len {
                inner.buf.truncate(len);
            }
        }
        Ok(())
    }

    async fn read_at(&self, offset: u64, len: u64) -> Result<Vec<u8>, DownloadError> {
        let inner = self.inner.lock().await;
        let (start, end) = read_back_bounds(offset, len)?;
        if inner.buf.len() < end {
            return Err(DownloadError::sink(format!(
                "read-back past staged end: want [{start}, {end}), have {}",
                inner.buf.len()
            )));
        }
        Ok(inner.buf[start..end].to_vec())
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

    fn supports_read_back(&self) -> bool {
        true // the staging file is readable, so its length is observable
    }

    async fn read_at(&self, offset: u64, len: u64) -> Result<Vec<u8>, DownloadError> {
        use std::io::{Read, Seek, SeekFrom};
        let mut guard = self.file.lock().await;
        // On a cross-process resume the staging file exists on disk but is not yet open in THIS
        // process — open it read/write (never truncating) so a subsequent write_at reattaches. A READ
        // never CREATES: an absent staging file must surface as "nothing staged", not as a 0-byte file
        // conjured as a side effect of reading.
        if guard.is_none() {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .truncate(false)
                .open(&self.tmp_path)
                .map_err(DownloadError::sink)?;
            *guard = Some(f);
        }
        let f = guard.as_mut().expect("file opened above");
        f.seek(SeekFrom::Start(offset))
            .map_err(DownloadError::sink)?;
        let mut buf = try_zeroed_read_buffer(len)?;
        f.read_exact(&mut buf).map_err(|e| {
            DownloadError::sink(format!("read-back of {len} bytes at {offset} failed: {e}"))
        })?;
        Ok(buf)
    }

    async fn truncate(&self, len: u64) -> Result<(), DownloadError> {
        let mut guard = self.file.lock().await;
        if guard.is_none() {
            // Nothing staged in this process. An ABSENT staging file has nothing to shorten and must
            // not be conjured (same rule as `read_at`); a present one from an earlier attempt is
            // opened WITHOUT truncating so a `set_len` below is the only length change.
            if !self.tmp_path.exists() {
                return Ok(());
            }
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .truncate(false)
                .open(&self.tmp_path)
                .map_err(DownloadError::sink)?;
            *guard = Some(f);
        }
        let f = guard.as_mut().expect("file opened above");
        let staged = f.metadata().map_err(DownloadError::sink)?.len();
        if staged > len {
            f.set_len(len).map_err(DownloadError::sink)?;
        }
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

    /// A read-back span derived from a hostile descriptor must be REJECTED, never turned into a
    /// wrapped/truncated index or an infallible 18-EiB allocation (which aborts the process).
    #[tokio::test]
    async fn an_absurd_read_back_span_is_a_typed_error_not_an_abort() {
        let sink = InMemorySink::new();
        sink.write_at(0, b"eight!!!").await.unwrap();
        let err = sink
            .read_at(1, u64::MAX)
            .await
            .expect_err("an unsatisfiable span is refused");
        assert!(matches!(err, DownloadError::Sink(_)), "typed error: {err}");
    }

    /// Reading back an ABSENT staging file must not CREATE it: a read has no business leaving a
    /// 0-byte file behind (it would also make a later GC/resume see phantom staging).
    #[tokio::test]
    async fn read_back_never_creates_the_staging_file() {
        let dir = temp_dir("no-create");
        let sink = FileSink::new(dir.join("resource.dig"));
        assert!(sink.read_at(0, 4).await.is_err());
        assert!(
            !sink.tmp_path().exists(),
            "a read did not conjure a staging file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `truncate` only ever SHRINKS the staging area — it never zero-extends a short one into a
    /// wrong-length artifact.
    #[tokio::test]
    async fn truncate_shrinks_and_never_extends() {
        let sink = InMemorySink::new();
        sink.write_at(0, b"ABCDEF").await.unwrap();
        sink.truncate(3).await.unwrap();
        assert_eq!(sink.contents().await, b"ABC");
        sink.truncate(99).await.unwrap();
        assert_eq!(sink.contents().await, b"ABC", "a longer len is a no-op");
    }

    #[tokio::test]
    async fn file_sink_truncate_shrinks_the_staging_file() {
        let dir = temp_dir("truncate");
        let final_path = dir.join("resource.dig");
        let sink = FileSink::new(&final_path);
        sink.write_at(0, b"ABCDEF").await.unwrap();
        sink.truncate(3).await.unwrap();
        sink.finalize().await.unwrap();
        assert_eq!(std::fs::read(&final_path).unwrap(), b"ABC");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Truncating an ABSENT staging file is a no-op that does not conjure one (same rule as `read_at`:
    /// a phantom 0-byte staging file would confuse GC + resume).
    #[tokio::test]
    async fn truncate_never_creates_the_staging_file() {
        let dir = temp_dir("truncate-no-create");
        let sink = FileSink::new(dir.join("resource.dig"));
        sink.truncate(0).await.unwrap();
        assert!(!sink.tmp_path().exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staging_path_appends_suffix() {
        let p = staging_path_for(Path::new("/data/x.dig"));
        assert!(p.to_string_lossy().ends_with(".dig.download.tmp"));
    }

    /// The promotion proof is TWO-SIDED, asserted at the seam that owns it.
    ///
    /// The short side is the one that fails OPEN if forgotten, with the same observable signature as the
    /// long side: `truncate` never extends, so a staging area shorter than the verified length survives
    /// it untouched, and a past-the-end probe on a short area reads EOF — which a one-sided guard treats
    /// as "clean" and promotes. The orchestrator now re-fetches rather than reaching here with a short
    /// staging area, so this asserts the seam's own contract, independently of any caller.
    #[tokio::test]
    async fn promotion_refuses_a_staging_area_that_is_shorter_than_the_verified_length() {
        let sink = InMemorySink::new();
        sink.write_at(0, b"only ten!!").await.unwrap();

        let err = promote_verified(&sink, 40)
            .await
            .expect_err("a partial artifact is never promoted as the verified one");
        assert!(
            err.to_string().contains("SHORTER than the verified length"),
            "and it names the side it refused, so this cannot silently become the long-side test: {err}"
        );
        assert!(!sink.is_finalized().await);
    }

    /// The long side, at the same seam: bytes past the verified end are refused too.
    #[tokio::test]
    async fn promotion_refuses_a_staging_area_holding_bytes_past_the_verified_length() {
        let sink = InMemorySink::new();
        sink.write_at(0, b"eight!!!").await.unwrap();
        // A sink whose `truncate` works cannot reach the long-side refusal, so drive the seam with one
        // that reports success without shortening — the shape that must not be trusted.
        struct NoOpTruncate(InMemorySink);
        #[async_trait]
        impl Sink for NoOpTruncate {
            async fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<(), DownloadError> {
                self.0.write_at(offset, bytes).await
            }
            async fn truncate(&self, _len: u64) -> Result<(), DownloadError> {
                Ok(())
            }
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
        let sink = NoOpTruncate(sink);

        let err = promote_verified(&sink, 4)
            .await
            .expect_err("a longer staged artifact is never promoted");
        assert!(
            err.to_string().contains("past the verified length"),
            "names the side it refused: {err}"
        );
        assert!(!sink.0.is_finalized().await);
    }

    /// A sink that cannot observe its staged bytes cannot PROVE a promotion, so it is refused — never
    /// trusted. "Read-back unsupported" and "nothing is staged there" are indistinguishable as errors,
    /// which is why the capability is explicit and defaults to false.
    #[tokio::test]
    async fn promotion_refuses_a_sink_that_cannot_read_its_staging_area_back() {
        struct WriteOnly;
        #[async_trait]
        impl Sink for WriteOnly {
            async fn write_at(&self, _offset: u64, _bytes: &[u8]) -> Result<(), DownloadError> {
                Ok(())
            }
            async fn truncate(&self, _len: u64) -> Result<(), DownloadError> {
                Ok(()) // the documented "I commit whole" opt-in, alone
            }
        }

        let err = promote_verified(&WriteOnly, 8)
            .await
            .expect_err("an unprovable promotion is refused");
        assert!(
            err.to_string().contains("cannot read back"),
            "names the missing capability rather than guessing: {err}"
        );
    }
}
