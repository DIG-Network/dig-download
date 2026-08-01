//! The #1610 headline property, measured rather than asserted by proxy: a whole-`.dig` module pull
//! holds ONE CHUNK, not the whole module.
//!
//! ## Why this test binary is alone
//!
//! It installs a counting [`GlobalAlloc`] and reads a process-wide peak, so any other test running
//! concurrently in the same binary would add its allocations to the measurement. This file therefore
//! contains exactly ONE test, and every allocation counted between the two probes belongs to the pull.
//!
//! ## Why the fixture is what it is
//!
//! - **A `FileSink`, not an `InMemorySink`.** The staging area is where the bytes go, and an in-memory
//!   staging area would hold the whole module by construction — the measurement would report the
//!   harness's own design, not the puller's. The real node stages on disk; so does this.
//! - **A streaming anchor gate.** The `.dig` verifier dig-node injects reads the container through the
//!   [`ModuleReader`] seam. An anchor double that slurped the module into a `Vec` to compare it would
//!   itself allocate the whole module and mask exactly the regression under test, so this one hashes
//!   window by window — the shape a real chain-anchor check has.
//! - **1 MiB in 64 KiB chunks.** The module is 16× the chunk, so a whole-module buffer cannot hide
//!   under the tolerance: the assertion below (peak < ¼ of the module) is unsatisfiable for any
//!   implementation that materializes the module, and comfortable for one that holds a chunk.
//!
//! Reverting the puller to the old whole-blob assembly fails this test on the peak, not on a proxy.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use dig_download::testkit::{mock_providers, MockModuleTransport, MockProviderLocator};
use dig_download::{
    module_content_id, FileSink, InMemoryStateStore, ModuleAnchor, ModuleAnchorVerifier,
    ModuleDownloadConfig, ModuleDownloader, ModuleReader,
};
use sha2::{Digest, Sha256};

/// Live bytes currently allocated by this process, and the high-water mark since the last reset.
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// A pass-through allocator that tracks live bytes and their high-water mark.
///
/// The peak is maintained with a compare-and-swap loop rather than a `fetch_max` on every allocation
/// so a concurrent decrease can never lower a peak another thread just published.
struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            record_growth(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            record_growth(new_size);
        }
        new_ptr
    }
}

/// Add `size` to the live total and raise the high-water mark if this allocation set a new one.
fn record_growth(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
    let mut peak = PEAK.load(Ordering::Relaxed);
    while live > peak {
        match PEAK.compare_exchange_weak(peak, live, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => peak = observed,
        }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The chain-anchor gate in the shape a real one has: it streams the module through the
/// [`ModuleReader`] seam and hashes it, holding one window at a time.
struct StreamingHashAnchor {
    expected: String,
    window: u64,
}

#[async_trait]
impl ModuleAnchorVerifier for StreamingHashAnchor {
    async fn verify_module_anchor(
        &self,
        module: &dyn ModuleReader,
        _store_id: &str,
        _root: &str,
    ) -> ModuleAnchor {
        let mut hasher = Sha256::new();
        let mut read = 0u64;
        while read < module.len() {
            let want = self.window.min(module.len() - read);
            match module.read_at(read, want).await {
                Ok(bytes) => {
                    hasher.update(&bytes);
                    read += bytes.len() as u64;
                }
                // Failing to read this node's OWN staging area is a local failure, never evidence
                // against a holder — the distinction `ModuleAnchor` exists to keep.
                Err(e) => return ModuleAnchor::Unavailable(e.to_string()),
            }
        }
        if hex(&hasher.finalize()) == self.expected {
            ModuleAnchor::Anchored
        } else {
            ModuleAnchor::NotAnchored
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_id(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

const CHUNK: usize = 64 * 1024;
const CHUNKS: usize = 16;
const MODULE_SIZE: usize = CHUNK * CHUNKS;

#[tokio::test(flavor = "current_thread")]
async fn a_module_pull_peaks_at_one_chunk_not_the_whole_module() {
    let store_id = hex_id(0xA1);
    let root = hex_id(0xA2);
    // Content that is DIFFERENT in every chunk, so a mis-ordered or duplicated chunk cannot still
    // hash to the expected module.
    let module: Vec<u8> = (0..MODULE_SIZE).map(|i| (i / 7 + i % 251) as u8).collect();
    let module_hash = hex(&Sha256::digest(&module));

    let dir = std::env::temp_dir().join(format!("dig-download-peak-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let sink = FileSink::new(dir.join("module.dig"));

    let content = module_content_id(&store_id, &root).expect("well-formed ids");
    let downloader = ModuleDownloader::new(
        Arc::new(MockProviderLocator::fixed(mock_providers(3, &content))),
        Arc::new(MockModuleTransport::serving(
            &store_id,
            &root,
            module.clone(),
            CHUNK,
        )),
        Arc::new(StreamingHashAnchor {
            expected: module_hash,
            window: CHUNK as u64,
        }),
        Arc::new(InMemoryStateStore::new()),
        ModuleDownloadConfig::default(),
    );

    // Probe AROUND the pull only: the harness above (which holds its own copy of the module to serve)
    // is charged to the baseline, so what is measured is the growth the pull itself causes.
    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);

    let len = downloader
        .download(&store_id, &root, &sink)
        .await
        .expect("the module pulls and verifies");

    let peak_growth = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(len, MODULE_SIZE as u64, "the whole module was pulled");
    assert!(
        peak_growth < MODULE_SIZE / 4,
        "peak allocation during the pull was {peak_growth} bytes for a {MODULE_SIZE}-byte module — \
         a whole-module buffer is back (#1610 regression); one chunk is {CHUNK} bytes"
    );
}
