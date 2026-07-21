//! End-to-end scenario tests for the multi-source download orchestrator over the in-memory
//! [`testkit`] harness (mock DHT providers + mock range sources + in-memory/temp sinks + state store;
//! NO real network / mainnet). These exercise the behaviours the crate exists to guarantee:
//!
//! - multi-source concurrent fan-out reassembles the whole resource,
//! - a range from a BAD source fails verification → re-fetched from another → correct result,
//! - a source dropping mid-download → its ranges rebalance to others + complete,
//! - `find_providers` is re-run when a range's sources are exhausted,
//! - the whole-resource integrity backstop rejects forged content,
//! - pause→resume fetches ONLY the missing ranges (no re-fetch of verified ranges),
//! - an interrupted download resumes from persisted state into the same `.download.tmp`,
//! - a completed file download finalizes via atomic rename (no `.download.tmp` left), a
//!   cancelled/abandoned one is reaped by GC once stale, and a paused-resumable one is NOT.

use std::sync::Arc;
use std::time::Duration;

use dig_download::testkit::{
    mock_content_id, mock_peer_hex, mock_provider, Behavior, MockContent, MockProviderLocator,
    MockRangeTransport, MockSelector,
};
use dig_download::{
    DownloadConfig, DownloadError, DownloadEvent, DownloadOptions, Downloader, FileSink,
    InMemorySink, InMemoryStateStore, MerkleVerifier, ProofVerifier, ProviderLocator, RangeResult,
    RangeTransport, Sink, SourceSelector, StateStore, Verifier,
};

/// A fast test config: tiny ranges (one chunk each) + short backoffs so retries + rebalancing run
/// quickly in real time.
fn test_config(window: u64) -> DownloadConfig {
    DownloadConfig {
        window,
        max_concurrency: 8,
        max_inflight_per_source: 1,
        base_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(20),
        max_relocate_attempts: 4,
        max_range_attempts: 8,
        verify_whole_resource: true,
        // Disable the per-range timeout + periodic refresh by default so the existing scenarios stay
        // deterministic (individual tests below opt into them). Selection uses the default
        // round-robin unless a test injects a selector.
        selector: None,
        range_timeout: None,
        refresh_interval: None,
    }
}

fn downloader(
    transport: Arc<MockRangeTransport>,
    locator: Arc<dyn ProviderLocator>,
    state: Arc<dyn StateStore>,
    verifier: Arc<dyn Verifier>,
    config: DownloadConfig,
) -> Downloader {
    Downloader::new(
        locator,
        transport as Arc<dyn RangeTransport>,
        verifier,
        state,
        config,
    )
}

async fn join_ok(handle: dig_download::DownloadHandle) -> Result<u64, DownloadError> {
    tokio::time::timeout(Duration::from_secs(10), handle.join())
        .await
        .expect("download did not finish in time")
}

#[tokio::test]
async fn multi_source_concurrent_reassembles_whole_resource() {
    let content = MockContent::even(30, 3);
    let transport = Arc::new(MockRangeTransport::new(content.clone()));
    let cid = mock_content_id();
    let providers = vec![
        mock_provider(1, &cid),
        mock_provider(2, &cid),
        mock_provider(3, &cid),
    ];
    let dl = downloader(
        transport.clone(),
        Arc::new(MockProviderLocator::fixed(providers)),
        Arc::new(InMemoryStateStore::new()),
        Arc::new(MerkleVerifier::insecure_structural_only()),
        test_config(10),
    );
    let sink = Arc::new(InMemorySink::new());
    join_ok(dl.download(cid, sink.clone(), DownloadOptions::default()))
        .await
        .unwrap();
    assert_eq!(sink.contents().await, content.bytes);

    let mut used = 0;
    for n in 1u8..=3 {
        if transport.attempts_for(&mock_peer_hex(n)).await > 0 {
            used += 1;
        }
    }
    assert!(used >= 2, "expected ≥2 sources used, got {used}");
}

#[tokio::test]
async fn bad_source_range_is_refetched_from_another() {
    let content = MockContent::even(30, 3);
    let transport = Arc::new(MockRangeTransport::new(content.clone()));
    let cid = mock_content_id();
    // p1, p3 honest; p2 truncates every range it serves (per-range length check fails).
    transport
        .set_behavior(&mock_peer_hex(2), Behavior::Truncate)
        .await;
    let providers = vec![
        mock_provider(1, &cid),
        mock_provider(2, &cid),
        mock_provider(3, &cid),
    ];
    let dl = downloader(
        transport.clone(),
        Arc::new(MockProviderLocator::fixed(providers)),
        Arc::new(InMemoryStateStore::new()),
        Arc::new(MerkleVerifier::insecure_structural_only()),
        test_config(10),
    );

    let sink = Arc::new(InMemorySink::new());
    let mut handle = dl.download(cid, sink.clone(), DownloadOptions::default());

    let mut saw_failure = false;
    let mut total = None;
    while let Some(ev) = handle.next_event().await {
        match ev {
            DownloadEvent::RangeFailed { provider, .. } => {
                assert_eq!(provider, mock_peer_hex(2));
                saw_failure = true;
            }
            DownloadEvent::Completed { total_length } => total = Some(total_length),
            _ => {}
        }
    }
    let result = handle.join().await.unwrap();

    assert_eq!(result, 30);
    assert_eq!(total, Some(30));
    assert!(
        saw_failure,
        "the truncating source should have failed a range"
    );
    // The result is correct despite the bad source — the range was refetched elsewhere.
    assert_eq!(sink.contents().await, content.bytes);
    assert!(transport.attempts_for(&mock_peer_hex(2)).await >= 1);
}

#[tokio::test]
async fn source_dropping_mid_download_rebalances() {
    let content = MockContent::even(60, 6); // 6 chunks of 10
    let transport = Arc::new(MockRangeTransport::new(content.clone()));
    let cid = mock_content_id();
    // p2 serves one range then drops (every later fetch fails); p1 must pick up the rest.
    transport
        .set_behavior(&mock_peer_hex(2), Behavior::DropAfter(1))
        .await;
    let providers = vec![mock_provider(1, &cid), mock_provider(2, &cid)];
    let mut config = test_config(10);
    config.max_inflight_per_source = 2;
    let dl = downloader(
        transport.clone(),
        Arc::new(MockProviderLocator::fixed(providers)),
        Arc::new(InMemoryStateStore::new()),
        Arc::new(MerkleVerifier::insecure_structural_only()),
        config,
    );

    let sink = Arc::new(InMemorySink::new());
    let total = join_ok(dl.download(cid, sink.clone(), DownloadOptions::default()))
        .await
        .unwrap();

    assert_eq!(total, 60);
    assert_eq!(sink.contents().await, content.bytes);
    // p2 was tried and dropped (≥2 attempts: ≥1 served, ≥1 failed after the drop).
    assert!(transport.attempts_for(&mock_peer_hex(2)).await >= 2);
    // p1 carried the bulk.
    assert!(transport.attempts_for(&mock_peer_hex(1)).await >= 4);
}

#[tokio::test]
async fn relocate_when_sources_exhausted() {
    let content = MockContent::even(20, 2); // 2 chunks of 10
    let transport = Arc::new(MockRangeTransport::new(content.clone()));
    let cid = mock_content_id();
    // Initial holder serves the meta-probe then drops every range; a re-locate finds a good one.
    transport
        .set_behavior(&mock_peer_hex(1), Behavior::DropAfter(1))
        .await;
    let locator = Arc::new(MockProviderLocator::scripted(vec![
        vec![mock_provider(1, &cid)],
        vec![mock_provider(2, &cid)], // discovered on the re-locate
    ]));
    let mut config = test_config(10);
    config.max_inflight_per_source = 2;
    let dl = downloader(
        transport.clone(),
        locator.clone(),
        Arc::new(InMemoryStateStore::new()),
        Arc::new(MerkleVerifier::insecure_structural_only()),
        config,
    );

    let sink = Arc::new(InMemorySink::new());
    let mut handle = dl.download(cid, sink.clone(), DownloadOptions::default());
    let mut refreshed = false;
    while let Some(ev) = handle.next_event().await {
        if let DownloadEvent::ProvidersRefreshed { .. } = ev {
            refreshed = true;
        }
    }
    let total = handle.join().await.unwrap();

    assert_eq!(total, 20);
    assert_eq!(sink.contents().await, content.bytes);
    assert!(refreshed, "a provider refresh should have occurred");
    assert!(
        locator.call_count().await >= 2,
        "find_providers should re-run"
    );
    assert!(transport.attempts_for(&mock_peer_hex(2)).await >= 2);
}

/// A proof verifier that only accepts the leaf of a specific known-good resource — models dig-node's
/// injected digstore proof check binding to the chain-anchored root.
struct OnlyLeaf([u8; 32]);
impl ProofVerifier for OnlyLeaf {
    fn verify_inclusion(
        &self,
        resource_leaf: &[u8; 32],
        _p: Option<&str>,
        _r: Option<&str>,
    ) -> bool {
        resource_leaf == &self.0
    }
}

#[tokio::test]
async fn whole_resource_integrity_backstop_rejects_forged_content() {
    let content = MockContent::even(20, 2);
    let transport = Arc::new(MockRangeTransport::new(content.clone()));
    let cid = mock_content_id();
    // The only holder serves right-length but corrupt bytes (passes per-range length, fails root).
    transport
        .set_behavior(&mock_peer_hex(1), Behavior::Corrupt)
        .await;
    let good_leaf = MerkleVerifier::resource_leaf(&content.bytes);
    let verifier = Arc::new(MerkleVerifier::with_proof_verifier(Arc::new(OnlyLeaf(
        good_leaf,
    ))));
    let dl = downloader(
        transport.clone(),
        Arc::new(MockProviderLocator::fixed(vec![mock_provider(1, &cid)])),
        Arc::new(InMemoryStateStore::new()),
        verifier,
        test_config(10),
    );

    let sink = Arc::new(InMemorySink::new());
    let result = join_ok(dl.download(cid, sink, DownloadOptions::default())).await;
    assert!(
        matches!(result, Err(DownloadError::Verify(_))),
        "forged content must fail the whole-resource root binding, got {result:?}"
    );
}

#[tokio::test]
async fn boundary_aligned_short_range_is_rejected_not_finalized() {
    // CRITICAL #179 regression: a range planned over MULTIPLE whole chunks, served by a peer that
    // returns only the first whole chunk. Those bytes are boundary-aligned (they start and end on a
    // chunk boundary) so a purely structural alignment check would ACCEPT them as complete — a
    // silent short/incomplete download. The per-range LENGTH check must reject the short range as a
    // recoverable failure and re-fetch it; with only a short-serving provider the download must NOT
    // finalize as success.
    //
    // 4 chunks of 10; window 20 → 2 ranges of 20 bytes (2 chunks each). ShortAligned serves 10.
    let content = MockContent::even(40, 4);
    let transport = Arc::new(MockRangeTransport::new(content.clone()));
    let cid = mock_content_id();
    transport
        .set_behavior(&mock_peer_hex(1), Behavior::ShortAligned)
        .await;
    // Small attempt budget so the all-short provider set terminates quickly.
    let mut config = test_config(20);
    config.max_range_attempts = 3;
    let dl = downloader(
        transport.clone(),
        Arc::new(MockProviderLocator::fixed(vec![mock_provider(1, &cid)])),
        Arc::new(InMemoryStateStore::new()),
        Arc::new(MerkleVerifier::insecure_structural_only()),
        config,
    );
    let sink = Arc::new(InMemorySink::new());
    let result = join_ok(dl.download(cid, sink.clone(), DownloadOptions::default())).await;

    // The download MUST NOT succeed: a boundary-aligned short range is not a complete range.
    assert!(
        matches!(result, Err(DownloadError::NoProviders { .. })),
        "a boundary-aligned short range must be rejected, not finalized as success; got {result:?}"
    );
    // And the sink must not hold a full, "complete-looking" resource.
    assert_ne!(
        sink.contents().await,
        content.bytes,
        "the short download must not have produced the whole resource"
    );
}

#[tokio::test]
async fn short_aligned_range_recovers_from_a_second_honest_source() {
    // The short-serving peer's ranges are re-fetched from an honest peer → the download completes
    // correctly (the length check discards the short range without poisoning the result).
    let content = MockContent::even(40, 4);
    let transport = Arc::new(MockRangeTransport::new(content.clone()));
    let cid = mock_content_id();
    // p1 serves boundary-aligned short ranges; p2 is honest.
    transport
        .set_behavior(&mock_peer_hex(1), Behavior::ShortAligned)
        .await;
    let providers = vec![mock_provider(1, &cid), mock_provider(2, &cid)];
    let dl = downloader(
        transport.clone(),
        Arc::new(MockProviderLocator::fixed(providers)),
        Arc::new(InMemoryStateStore::new()),
        Arc::new(MerkleVerifier::insecure_structural_only()),
        test_config(20),
    );
    let sink = Arc::new(InMemorySink::new());
    let total = join_ok(dl.download(cid, sink.clone(), DownloadOptions::default()))
        .await
        .unwrap();
    assert_eq!(total, 40);
    assert_eq!(sink.contents().await, content.bytes);
}

#[tokio::test]
async fn commitment_rejects_peer_reporting_a_wrong_root() {
    // HIGH #179 regression: establish_commitment must NOT adopt a commitment from a peer whose
    // reported generation root differs from the content-id's root. A sole peer reporting a wrong
    // root cannot seed the plan, so the download fails to establish metadata (NotFound) rather than
    // silently downloading the attacker's generation.
    let content = MockContent::even(20, 2);
    let transport = Arc::new(MockRangeTransport::new(content.clone()));
    let cid = mock_content_id();
    transport
        .set_behavior(&mock_peer_hex(1), Behavior::WrongRoot)
        .await;
    let dl = downloader(
        transport.clone(),
        Arc::new(MockProviderLocator::fixed(vec![mock_provider(1, &cid)])),
        Arc::new(InMemoryStateStore::new()),
        Arc::new(MerkleVerifier::insecure_structural_only()),
        test_config(10),
    );
    let sink = Arc::new(InMemorySink::new());
    let result = join_ok(dl.download(cid, sink.clone(), DownloadOptions::default())).await;
    assert!(
        matches!(result, Err(DownloadError::NotFound { .. })),
        "a peer reporting a wrong root must not seed the commitment; got {result:?}"
    );
    assert_ne!(sink.contents().await, content.bytes);
}

#[tokio::test]
async fn wrong_root_peer_ignored_honest_peer_completes() {
    // A wrong-root peer is skipped during commitment establishment; an honest peer establishes the
    // correct commitment and the download completes correctly.
    let content = MockContent::even(20, 2);
    let transport = Arc::new(MockRangeTransport::new(content.clone()));
    let cid = mock_content_id();
    // p1 reports a wrong root; p2 is honest.
    transport
        .set_behavior(&mock_peer_hex(1), Behavior::WrongRoot)
        .await;
    let providers = vec![mock_provider(1, &cid), mock_provider(2, &cid)];
    let dl = downloader(
        transport.clone(),
        Arc::new(MockProviderLocator::fixed(providers)),
        Arc::new(InMemoryStateStore::new()),
        Arc::new(MerkleVerifier::insecure_structural_only()),
        test_config(10),
    );
    let sink = Arc::new(InMemorySink::new());
    let total = join_ok(dl.download(cid, sink.clone(), DownloadOptions::default()))
        .await
        .unwrap();
    assert_eq!(total, 20);
    assert_eq!(sink.contents().await, content.bytes);
}

#[tokio::test]
async fn pause_then_resume_fetches_only_missing_ranges() {
    let content = MockContent::even(40, 4); // 4 chunks of 10
    let transport = Arc::new(MockRangeTransport::new(content.clone()));
    transport.set_delay(Duration::from_millis(15)).await; // so we can pause mid-flight
    let cid = mock_content_id();
    let dl = downloader(
        transport.clone(),
        Arc::new(MockProviderLocator::fixed(vec![mock_provider(1, &cid)])),
        Arc::new(InMemoryStateStore::new()),
        Arc::new(MerkleVerifier::insecure_structural_only()),
        test_config(10),
    );

    let sink = Arc::new(InMemorySink::new());
    let mut handle = dl.download(cid, sink.clone(), DownloadOptions::default());

    let mut completed_ranges: Vec<usize> = Vec::new();
    let mut paused_once = false;
    while let Some(ev) = handle.next_event().await {
        match ev {
            DownloadEvent::RangeCompleted { range, .. } => {
                completed_ranges.push(range);
                if completed_ranges.len() == 1 && !paused_once {
                    handle.pause(); // pause after the first range verifies
                }
            }
            DownloadEvent::Paused => {
                paused_once = true;
                // Resume shortly after so the download can finish.
                handle.resume();
            }
            DownloadEvent::Completed { .. } => break,
            _ => {}
        }
    }
    let total = handle.join().await.unwrap();

    assert_eq!(total, 40);
    assert_eq!(sink.contents().await, content.bytes);
    // Every range completed EXACTLY once — a verified range is never re-fetched across pause/resume.
    completed_ranges.sort_unstable();
    assert_eq!(completed_ranges, vec![0, 1, 2, 3]);
    // Ranges 1..3 (non-probe offsets) were each fetched exactly once.
    for offset in [10u64, 20, 30] {
        assert_eq!(
            transport.attempts_at(offset).await,
            1,
            "range at offset {offset} should be fetched exactly once"
        );
    }
    assert!(paused_once, "the download should have actually paused");
}

#[tokio::test]
async fn interrupted_download_resumes_from_persisted_state() {
    let content = MockContent::even(40, 4);
    let cid = mock_content_id();
    let dir = temp_dir("resume");
    let final_path = dir.join("resource.dig");
    let state: Arc<dyn StateStore> = Arc::new(InMemoryStateStore::new());

    // --- Run 1: interrupt (cancel) after some ranges are verified + written to the .download.tmp.
    let transport_a = Arc::new(MockRangeTransport::new(content.clone()));
    transport_a.set_delay(Duration::from_millis(10)).await;
    let dl_a = downloader(
        transport_a.clone(),
        Arc::new(MockProviderLocator::fixed(vec![mock_provider(1, &cid)])),
        state.clone(),
        Arc::new(MerkleVerifier::insecure_structural_only()),
        test_config(10),
    );
    let sink_a: Arc<dyn Sink> = Arc::new(FileSink::new(&final_path));
    let mut handle = dl_a.download(cid, sink_a, DownloadOptions::default());
    let mut done_in_run1: Vec<usize> = Vec::new();
    while let Some(ev) = handle.next_event().await {
        if let DownloadEvent::RangeCompleted { range, .. } = ev {
            done_in_run1.push(range);
            if done_in_run1.len() == 2 {
                handle.cancel();
                break;
            }
        }
    }
    let r1 = handle.join().await;
    assert!(matches!(r1, Err(DownloadError::Cancelled)));
    // The staging file survived the interruption; the final file does not exist yet.
    assert!(dig_download::staging_path_for(&final_path).exists());
    assert!(!final_path.exists());
    assert_eq!(done_in_run1.len(), 2);

    // --- Run 2: a fresh transport + sink for the SAME target + shared state → resume.
    let transport_b = Arc::new(MockRangeTransport::new(content.clone()));
    let dl_b = downloader(
        transport_b.clone(),
        Arc::new(MockProviderLocator::fixed(vec![mock_provider(1, &cid)])),
        state.clone(),
        Arc::new(MerkleVerifier::insecure_structural_only()),
        test_config(10),
    );
    let sink_b: Arc<dyn Sink> = Arc::new(FileSink::new(&final_path));
    let total = join_ok(dl_b.download(cid, sink_b, DownloadOptions::default()))
        .await
        .unwrap();

    assert_eq!(total, 40);
    // Atomic finalize produced the whole, correct file.
    assert_eq!(std::fs::read(&final_path).unwrap(), content.bytes);
    assert!(!dig_download::staging_path_for(&final_path).exists());

    // The already-verified ranges were NOT re-fetched in run 2; the missing ones were fetched once.
    let done_offsets: Vec<u64> = done_in_run1.iter().map(|&r| r as u64 * 10).collect();
    for off in &done_offsets {
        assert_eq!(
            transport_b.attempts_at(*off).await,
            0,
            "verified range at offset {off} must not be re-fetched on resume"
        );
    }
    for r in 0..4usize {
        let off = r as u64 * 10;
        if !done_in_run1.contains(&r) {
            assert_eq!(
                transport_b.attempts_at(off).await,
                1,
                "missing range at offset {off} should be fetched exactly once"
            );
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn file_download_finalizes_atomically_and_gc_reaps_abandoned() {
    let content = MockContent::even(30, 3);
    let cid = mock_content_id();
    let dir = temp_dir("filegc");

    // --- A completed file download: atomic rename → final file, no staging left, registry clear.
    {
        let transport = Arc::new(MockRangeTransport::new(content.clone()));
        let dl = downloader(
            transport,
            Arc::new(MockProviderLocator::fixed(vec![mock_provider(1, &cid)])),
            Arc::new(InMemoryStateStore::new()),
            Arc::new(MerkleVerifier::insecure_structural_only()),
            test_config(10),
        );
        let final_path = dir.join("done.dig");
        let sink: Arc<dyn Sink> = Arc::new(FileSink::new(&final_path));
        join_ok(dl.download(cid, sink, DownloadOptions::default()))
            .await
            .unwrap();
        assert_eq!(std::fs::read(&final_path).unwrap(), content.bytes);
        assert!(!dig_download::staging_path_for(&final_path).exists());
        assert!(dl.active_downloads().is_empty().await);
        // A GC sweep removes nothing (there is no staging file).
        assert_eq!(dl.gc(&dir, Duration::ZERO).await.unwrap(), 0);
    }

    // --- A paused-resumable download: its staging file is protected from GC; once cancelled +
    //     abandoned, a later stale sweep reaps it.
    {
        let transport = Arc::new(MockRangeTransport::new(content.clone()));
        transport.set_delay(Duration::from_millis(20)).await;
        let dl = downloader(
            transport,
            Arc::new(MockProviderLocator::fixed(vec![mock_provider(1, &cid)])),
            Arc::new(InMemoryStateStore::new()),
            Arc::new(MerkleVerifier::insecure_structural_only()),
            test_config(10),
        );
        let final_path = dir.join("paused.dig");
        let staging = dig_download::staging_path_for(&final_path);
        let sink: Arc<dyn Sink> = Arc::new(FileSink::new(&final_path));
        let mut handle = dl.download(cid, sink, DownloadOptions::default());

        // Wait for the first range to be written to the staging file, then pause.
        while let Some(ev) = handle.next_event().await {
            if let DownloadEvent::RangeCompleted { .. } = ev {
                handle.pause();
                break;
            }
        }
        // Give the pause a moment to take effect + the write to land.
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(staging.exists(), "a partial staging file should exist");
        assert!(dl.active_downloads().is_protected(&staging).await);
        // GC does NOT reap a protected (paused-resumable) staging file, even if "stale".
        assert_eq!(dl.gc(&dir, Duration::ZERO).await.unwrap(), 0);
        assert!(staging.exists());

        // Cancel → the handle terminates → the staging file is unregistered (abandoned).
        handle.cancel();
        let _ = handle.join().await;
        assert!(!dl.active_downloads().is_protected(&staging).await);
        assert!(
            staging.exists(),
            "the abandoned staging file remains on disk"
        );
        // A stale sweep now reaps it.
        assert_eq!(dl.gc(&dir, Duration::ZERO).await.unwrap(), 1);
        assert!(!staging.exists());
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Fork-C acceptance (#1426): an UNKNOWN capsule whose `find_providers` returns an EMPTY holder set
/// MUST surface as [`DownloadError::NotFound`] (not a hang, not a fail-open success). This is what lets
/// the §5.3 client read ladder fall THROUGH the local node to `rpc.dig.net` when no peer holds the
/// content — a NotFound is a clean, immediate "not here", never an indefinite stall.
#[tokio::test]
async fn no_providers_located_is_not_found() {
    let content = MockContent::even(20, 2);
    let transport = Arc::new(MockRangeTransport::new(content));
    let cid = mock_content_id();
    let dl = downloader(
        transport,
        Arc::new(MockProviderLocator::fixed(vec![])), // nobody holds it
        Arc::new(InMemoryStateStore::new()),
        Arc::new(MerkleVerifier::insecure_structural_only()),
        test_config(10),
    );
    let sink = Arc::new(InMemorySink::new());
    let result = join_ok(dl.download(cid, sink, DownloadOptions::default())).await;
    assert!(matches!(result, Err(DownloadError::NotFound { .. })));
}

#[tokio::test]
async fn exhausted_providers_yields_no_providers() {
    let content = MockContent::even(20, 2);
    let transport = Arc::new(MockRangeTransport::new(content));
    let cid = mock_content_id();
    // The sole holder answers the meta-probe, then fails every range forever; a re-locate finds
    // nobody new, so the download eventually gives up (guaranteed termination).
    transport
        .set_behavior(&mock_peer_hex(1), Behavior::DropAfter(1))
        .await;
    let mut config = test_config(10);
    config.max_inflight_per_source = 2;
    config.max_range_attempts = 3;
    let dl = downloader(
        transport,
        Arc::new(MockProviderLocator::fixed(vec![mock_provider(1, &cid)])),
        Arc::new(InMemoryStateStore::new()),
        Arc::new(MerkleVerifier::insecure_structural_only()),
        config,
    );
    let sink = Arc::new(InMemorySink::new());
    let result = join_ok(dl.download(cid, sink, DownloadOptions::default())).await;
    assert!(
        matches!(result, Err(DownloadError::NoProviders { .. })),
        "an all-failing provider set should terminate with NoProviders, got {result:?}"
    );
}

#[tokio::test]
async fn bare_store_id_is_not_downloadable() {
    let content = MockContent::even(10, 1);
    let transport = Arc::new(MockRangeTransport::new(content));
    let store_cid = dig_download::ContentId::store([9; 32]);
    let dl = downloader(
        transport,
        Arc::new(MockProviderLocator::fixed(vec![])),
        Arc::new(InMemoryStateStore::new()),
        Arc::new(MerkleVerifier::insecure_structural_only()),
        test_config(10),
    );
    let sink = Arc::new(InMemorySink::new());
    let result = join_ok(dl.download(store_cid, sink, DownloadOptions::default())).await;
    assert!(matches!(result, Err(DownloadError::NotDownloadable)));
}

// ---- #1440 selector-seam delegation (dig-download owns NO ranking brain) --------------------------

/// A downloader wired with an injected [`SourceSelector`] (else identical to `downloader`).
fn downloader_with_selector(
    transport: Arc<MockRangeTransport>,
    locator: Arc<dyn ProviderLocator>,
    selector: Arc<dyn SourceSelector>,
    mut config: DownloadConfig,
) -> Downloader {
    config.selector = Some(selector);
    Downloader::new(
        locator,
        transport as Arc<dyn RangeTransport>,
        Arc::new(MerkleVerifier::insecure_structural_only()),
        Arc::new(InMemoryStateStore::new()),
        config,
    )
}

#[tokio::test]
async fn selection_is_delegated_to_the_injected_selector() {
    // The download must consult the selector for peer choice (never rank internally) and report the
    // measured outcome of EVERY successful range back to it.
    let content = MockContent::even(30, 3);
    let transport = Arc::new(MockRangeTransport::new(content.clone()));
    let cid = mock_content_id();
    let providers = vec![
        mock_provider(1, &cid),
        mock_provider(2, &cid),
        mock_provider(3, &cid),
    ];
    let selector = MockSelector::new();
    let dl = downloader_with_selector(
        transport.clone(),
        Arc::new(MockProviderLocator::fixed(providers)),
        selector.clone(),
        test_config(10),
    );
    let sink = Arc::new(InMemorySink::new());
    join_ok(dl.download(cid, sink.clone(), DownloadOptions::default()))
        .await
        .unwrap();
    assert_eq!(sink.contents().await, content.bytes);

    // dig-download asked the selector to choose peers (proves no internal ranking).
    assert!(
        selector.select_call_count() >= 1,
        "download must delegate peer choice to selector.select"
    );
    // It reported one Ok outcome per range (3 ranges), with correct bytes + non-empty peer id.
    let outcomes = selector.outcomes();
    let ok: Vec<_> = outcomes
        .iter()
        .filter(|o| o.result == RangeResult::Ok)
        .collect();
    assert_eq!(ok.len(), 3, "one Ok outcome recorded per range");
    assert!(ok.iter().all(|o| o.bytes == 10 && !o.peer_id.is_empty()));
}

#[tokio::test]
async fn selector_preference_order_is_honored() {
    // With p1 the ONLY holder the selector prefers (and it's honest + can serve everything under a
    // generous per-source cap), all ranges should be fetched from p1 even though p2/p3 are available.
    let content = MockContent::even(30, 3);
    let transport = Arc::new(MockRangeTransport::new(content.clone()));
    let cid = mock_content_id();
    let providers = vec![
        mock_provider(1, &cid),
        mock_provider(2, &cid),
        mock_provider(3, &cid),
    ];
    // Prefer p1 first; give a per-source cap high enough that p1 alone can take every range.
    let selector = MockSelector::with_order(vec![mock_peer_hex(1)]);
    let mut cfg = test_config(10);
    cfg.max_inflight_per_source = 8;
    let dl = downloader_with_selector(
        transport.clone(),
        Arc::new(MockProviderLocator::fixed(providers)),
        selector,
        cfg,
    );
    let sink = Arc::new(InMemorySink::new());
    join_ok(dl.download(cid, sink.clone(), DownloadOptions::default()))
        .await
        .unwrap();
    assert_eq!(sink.contents().await, content.bytes);
    // p1 serves the meta-probe + all 3 ranges; the non-preferred peers are never touched.
    assert!(
        transport.attempts_for(&mock_peer_hex(1)).await >= 3,
        "the selector's preferred peer serves the ranges"
    );
    assert_eq!(transport.attempts_for(&mock_peer_hex(2)).await, 0);
    assert_eq!(transport.attempts_for(&mock_peer_hex(3)).await, 0);
}

#[tokio::test]
async fn bad_merkle_range_is_reported_failed_and_refetched() {
    // p2 corrupts (right length, wrong bytes → fails the whole-resource root binding but NOT the
    // per-range structural check; use a proof verifier that catches it). Simpler: Truncate → per-range
    // length failure. The selector must see a Failed outcome for p2 and the range must still complete.
    let content = MockContent::even(30, 3);
    let transport = Arc::new(MockRangeTransport::new(content.clone()));
    let cid = mock_content_id();
    transport
        .set_behavior(&mock_peer_hex(2), Behavior::Truncate)
        .await;
    let providers = vec![mock_provider(1, &cid), mock_provider(2, &cid)];
    let selector = MockSelector::new();
    let dl = downloader_with_selector(
        transport.clone(),
        Arc::new(MockProviderLocator::fixed(providers)),
        selector.clone(),
        test_config(10),
    );
    let sink = Arc::new(InMemorySink::new());
    join_ok(dl.download(cid, sink.clone(), DownloadOptions::default()))
        .await
        .unwrap();
    assert_eq!(sink.contents().await, content.bytes);
    let outcomes = selector.outcomes();
    assert!(
        outcomes
            .iter()
            .any(|o| o.result == RangeResult::Failed && o.peer_id == mock_peer_hex(2)),
        "the truncating peer's range must be reported Failed to the selector"
    );
}

#[tokio::test]
async fn slow_range_times_out_and_is_reported_timedout() {
    // A single holder that delays every fetch beyond the per-range timeout: the fetch must time out,
    // be reported TimedOut to the selector, and (with no other holder) the download exhausts.
    let content = MockContent::even(20, 2);
    let transport = Arc::new(MockRangeTransport::new(content.clone()));
    transport.set_delay(Duration::from_millis(200)).await;
    let cid = mock_content_id();
    let providers = vec![mock_provider(1, &cid)];
    let selector = MockSelector::new();
    let mut cfg = test_config(10);
    cfg.range_timeout = Some(Duration::from_millis(20)); // shorter than the 200ms serve delay
    cfg.max_range_attempts = 2; // keep the exhaustion bound small so the test ends quickly
    let dl = downloader_with_selector(
        transport.clone(),
        Arc::new(MockProviderLocator::fixed(providers)),
        selector.clone(),
        cfg,
    );
    let sink = Arc::new(InMemorySink::new());
    let result = join_ok(dl.download(cid, sink, DownloadOptions::default())).await;
    assert!(
        matches!(result, Err(DownloadError::NoProviders { .. })),
        "a single too-slow holder eventually exhausts the download"
    );
    let outcomes = selector.outcomes();
    assert!(
        outcomes.iter().any(|o| o.result == RangeResult::TimedOut),
        "a timed-out range must be reported TimedOut to the selector"
    );
}

#[tokio::test]
async fn empty_candidate_set_falls_through_to_not_found() {
    // #1426 fall-through preserved: no providers located → NotFound.
    let content = MockContent::even(10, 1);
    let transport = Arc::new(MockRangeTransport::new(content));
    let cid = mock_content_id();
    let selector = MockSelector::new();
    let dl = downloader_with_selector(
        transport,
        Arc::new(MockProviderLocator::fixed(vec![])),
        selector,
        test_config(10),
    );
    let sink = Arc::new(InMemorySink::new());
    let result = join_ok(dl.download(cid, sink, DownloadOptions::default())).await;
    assert!(matches!(result, Err(DownloadError::NotFound { .. })));
}

#[tokio::test]
async fn periodic_refresh_discovers_new_holders_mid_download() {
    // Start with a holder that drops after one fetch; a periodic refresh must discover a fresh holder
    // and complete the download (live upgrade). The scripted locator adds p2 on the 2nd call.
    let content = MockContent::even(30, 3);
    let transport = Arc::new(MockRangeTransport::new(content.clone()));
    let cid = mock_content_id();
    transport
        .set_behavior(&mock_peer_hex(1), Behavior::DropAfter(1))
        .await;
    let locator = MockProviderLocator::scripted(vec![
        vec![mock_provider(1, &cid)],
        vec![mock_provider(1, &cid), mock_provider(2, &cid)],
    ]);
    let selector = MockSelector::new();
    let mut cfg = test_config(10);
    cfg.refresh_interval = Some(Duration::from_millis(5)); // frequent live-upgrade refresh
    let dl = downloader_with_selector(transport.clone(), Arc::new(locator), selector, cfg);
    let sink = Arc::new(InMemorySink::new());
    join_ok(dl.download(cid, sink.clone(), DownloadOptions::default()))
        .await
        .unwrap();
    assert_eq!(sink.contents().await, content.bytes);
    assert!(
        transport.attempts_for(&mock_peer_hex(2)).await > 0,
        "the refresh-discovered holder p2 must serve at least one range"
    );
}

// ---- #1435 req.1 bounded-FCFS download queue --------------------------------------------------------

#[tokio::test]
async fn queue_completes_all_submitted_downloads() {
    use dig_download::DownloadQueue;
    let content = MockContent::even(30, 3);
    let transport = Arc::new(MockRangeTransport::new(content.clone()));
    let cid = mock_content_id();
    let dl = Arc::new(downloader(
        transport,
        Arc::new(MockProviderLocator::fixed(vec![mock_provider(1, &cid)])),
        Arc::new(InMemoryStateStore::new()),
        Arc::new(MerkleVerifier::insecure_structural_only()),
        test_config(10),
    ));
    let queue = DownloadQueue::new(dl, 2);
    let mut handles = Vec::new();
    for _ in 0..5 {
        let sink = Arc::new(InMemorySink::new());
        handles.push((
            queue.submit(cid, sink.clone(), DownloadOptions::default()),
            sink,
        ));
    }
    for (handle, sink) in handles {
        let total = tokio::time::timeout(Duration::from_secs(10), handle.join())
            .await
            .expect("queued download finished in time")
            .expect("queued download succeeded");
        assert_eq!(total, 30);
        assert_eq!(sink.contents().await, content.bytes);
    }
}

#[tokio::test]
async fn queue_with_defaults_uses_default_active_cap() {
    use dig_download::{DownloadQueue, DEFAULT_MAX_ACTIVE_DOWNLOADS};
    let content = MockContent::even(10, 1);
    let transport = Arc::new(MockRangeTransport::new(content.clone()));
    let cid = mock_content_id();
    let dl = Arc::new(downloader(
        transport,
        Arc::new(MockProviderLocator::fixed(vec![mock_provider(1, &cid)])),
        Arc::new(InMemoryStateStore::new()),
        Arc::new(MerkleVerifier::insecure_structural_only()),
        test_config(10),
    ));
    let queue = DownloadQueue::with_defaults(dl);
    assert_eq!(queue.max_active(), DEFAULT_MAX_ACTIVE_DOWNLOADS);
    let sink = Arc::new(InMemorySink::new());
    let total = tokio::time::timeout(
        Duration::from_secs(10),
        queue
            .submit(cid, sink.clone(), DownloadOptions::default())
            .join(),
    )
    .await
    .expect("finished")
    .expect("ok");
    assert_eq!(total, 10);
    assert_eq!(sink.contents().await, content.bytes);
}

#[tokio::test]
async fn queue_bounds_active_and_serves_fcfs() {
    use dig_download::DownloadQueue;
    // max_active = 1 serializes downloads; with a per-fetch delay they run strictly one at a time in
    // submission order, so their completion order equals their submission order (FCFS, no starvation).
    let content = MockContent::even(10, 1);
    let transport = Arc::new(MockRangeTransport::new(content));
    transport.set_delay(Duration::from_millis(20)).await;
    let cid = mock_content_id();
    let dl = Arc::new(downloader(
        transport,
        Arc::new(MockProviderLocator::fixed(vec![mock_provider(1, &cid)])),
        Arc::new(InMemoryStateStore::new()),
        Arc::new(MerkleVerifier::insecure_structural_only()),
        test_config(10),
    ));
    let queue = DownloadQueue::new(dl, 1);
    assert_eq!(queue.max_active(), 1);

    let order = Arc::new(tokio::sync::Mutex::new(Vec::<u32>::new()));
    let mut joins = Vec::new();
    for i in 0..3u32 {
        let sink = Arc::new(InMemorySink::new());
        let handle = queue.submit(cid, sink, DownloadOptions::default());
        let order = order.clone();
        joins.push(tokio::spawn(async move {
            handle.join().await.unwrap();
            order.lock().await.push(i);
        }));
    }
    for j in joins {
        tokio::time::timeout(Duration::from_secs(10), j)
            .await
            .expect("queued download finished")
            .unwrap();
    }
    assert_eq!(
        *order.lock().await,
        vec![0, 1, 2],
        "downloads complete in submission order under a cap of 1"
    );
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "dig-download-it-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}
