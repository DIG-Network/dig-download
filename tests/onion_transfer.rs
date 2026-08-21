//! End-to-end scenarios for **onion mode** — content that reaches the requestor only by travelling
//! back through the hops that carried the ask (#30), and the resume guarantee that must survive that
//! new delivery path (#31).
//!
//! The hop path is exercised over an in-memory [`HopChannel`] (no network, no real onion crypto — the
//! layered transport is `dig-onion`'s and arrives through the `OnionChannel` seam). What these tests
//! pin is the part this crate owns: an onion-delivered byte is trusted exactly as much as a directly
//! fetched one, which is not at all until it verifies against the chain-anchored root.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use dig_download::testkit::{
    mock_content_id, mock_provider, MockContent, MockProviderLocator, MockRangeTransport,
};
use dig_download::{
    AvailabilityItem, AvailabilityResponse, DownloadConfig, DownloadError, DownloadEvent,
    DownloadOptions, Downloader, FetchedRange, FileSink, HopPath, InMemorySink, InMemoryStateStore,
    MerkleVerifier, OnionChannel, OnionRangeTransport, ProofVerifier, ProviderRecord, RangeRequest,
    RangeTransport, StateStore, StreamRelayConfig, Verifier,
};

/// A [`ProofVerifier`] that accepts exactly one `resource_leaf` — the stand-in for the chain-anchored
/// root, so "verifies against the chain root" is a real assertion rather than a structural one.
struct OnlyLeaf([u8; 32]);

impl ProofVerifier for OnlyLeaf {
    fn verify_inclusion(
        &self,
        resource_leaf: &[u8; 32],
        _proof: Option<&str>,
        _root: Option<&str>,
    ) -> bool {
        resource_leaf == &self.0
    }
}

/// How a hop on the path misbehaves. Every variant models a hop that cannot READ the content (it is
/// capsule ciphertext under an onion layer) but can still refuse to pass it faithfully.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HopBehavior {
    /// Passes the transfer through untouched.
    Honest,
    /// Flips a byte the FIRST time it carries the transfer covering this offset, then behaves
    /// honestly. Models a hop that corrupts what it relays — the case NC-12 says must cost a retry
    /// and never a false success.
    ///
    /// Keyed on the OFFSET rather than on a call count deliberately: the download's first hop call is
    /// the 1-byte metadata probe, so a count-keyed fixture would corrupt the probe and prove nothing
    /// about a range being re-fetched.
    CorruptsRangeAt(u64),
}

/// An in-memory [`OnionChannel`]: it carries a request along `path` to an "exit" that runs the
/// ordinary fetch against the holder, then hands the answer back down the path.
///
/// The requestor in these tests has NO other transport, so anything that arrives arrived through the
/// path — there is no direct route to fall back on and nothing to confuse the evidence.
struct HopChannel {
    exit: Arc<MockRangeTransport>,
    behavior: HopBehavior,
    range_calls: AtomicUsize,
    corrupted: AtomicUsize,
    paths_seen: std::sync::Mutex<Vec<Vec<String>>>,
}

impl HopChannel {
    fn new(exit: Arc<MockRangeTransport>, behavior: HopBehavior) -> Arc<Self> {
        Arc::new(HopChannel {
            exit,
            behavior,
            range_calls: AtomicUsize::new(0),
            corrupted: AtomicUsize::new(0),
            paths_seen: std::sync::Mutex::new(Vec::new()),
        })
    }

    fn range_calls(&self) -> usize {
        self.range_calls.load(Ordering::SeqCst)
    }

    fn corrupted(&self) -> usize {
        self.corrupted.load(Ordering::SeqCst)
    }

    fn paths_seen(&self) -> Vec<Vec<String>> {
        self.paths_seen.lock().expect("paths lock").clone()
    }
}

#[async_trait]
impl OnionChannel for HopChannel {
    async fn ask_availability_through(
        &self,
        path: &HopPath,
        provider: &ProviderRecord,
        items: Vec<AvailabilityItem>,
    ) -> Result<AvailabilityResponse, DownloadError> {
        self.paths_seen
            .lock()
            .expect("paths lock")
            .push(path.hops().to_vec());
        self.exit.query_availability(provider, items).await
    }

    async fn fetch_range_through(
        &self,
        path: &HopPath,
        provider: &ProviderRecord,
        req: &RangeRequest,
    ) -> Result<FetchedRange, DownloadError> {
        self.paths_seen
            .lock()
            .expect("paths lock")
            .push(path.hops().to_vec());
        self.range_calls.fetch_add(1, Ordering::SeqCst);
        let mut fetched = self.exit.fetch_range(provider, req).await?;
        if let HopBehavior::CorruptsRangeAt(offset) = self.behavior {
            let first_time = self.corrupted.load(Ordering::SeqCst) == 0;
            if first_time && req.offset == offset {
                if let Some(byte) = fetched.bytes.first_mut() {
                    *byte ^= 0xFF;
                    self.corrupted.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        Ok(fetched)
    }
}

fn relaying_config() -> StreamRelayConfig {
    StreamRelayConfig {
        enabled: true,
        relays_asks_only: false,
        ..Default::default()
    }
}

fn three_hops() -> HopPath {
    HopPath::try_new(vec!["entry".into(), "middle".into(), "exit".into()]).expect("a valid path")
}

fn test_config(window: u64) -> DownloadConfig {
    let mut config = DownloadConfig::default();
    config.window = window;
    config.max_inflight_per_source = 1;
    config.base_backoff = Duration::from_millis(1);
    config.max_backoff = Duration::from_millis(20);
    config.max_range_attempts = 8;
    config.max_resource_size = 64 * 1024;
    config.range_timeout = None;
    config.refresh_interval = None;
    config
}

fn onion_downloader(
    channel: Arc<dyn OnionChannel>,
    locator: Arc<MockProviderLocator>,
    state: Arc<dyn StateStore>,
    verifier: Arc<dyn Verifier>,
    config: DownloadConfig,
    policy: StreamRelayConfig,
) -> Downloader {
    let transport: Arc<dyn RangeTransport> =
        Arc::new(OnionRangeTransport::new(channel, three_hops(), policy));
    Downloader::new(locator, transport, verifier, state, config)
}

fn chain_verifier(content: &MockContent) -> Arc<dyn Verifier> {
    Arc::new(MerkleVerifier::with_proof_verifier(Arc::new(OnlyLeaf(
        MerkleVerifier::resource_leaf(&content.bytes),
    ))))
}

async fn join_ok(handle: dig_download::DownloadHandle) -> Result<u64, DownloadError> {
    tokio::time::timeout(Duration::from_secs(10), handle.join())
        .await
        .expect("download did not finish in time")
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    // Keyed on the tag ITSELF, not on its length: two different tags of equal length shared one
    // directory, so concurrent tests raced over each other's staging files.
    let dir = std::env::temp_dir().join(format!("dig-download-onion-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// #30's acceptance shape at crate level: the content is reachable ONLY through the hop path, and it
/// arrives and binds to the chain-anchored root.
#[tokio::test]
async fn content_reachable_only_through_hops_arrives_and_binds_to_the_chain_root() {
    let content = MockContent::even(40, 4);
    let cid = mock_content_id();
    let channel = HopChannel::new(
        Arc::new(MockRangeTransport::new(content.clone())),
        HopBehavior::Honest,
    );
    let dl = onion_downloader(
        channel.clone(),
        Arc::new(MockProviderLocator::fixed(vec![mock_provider(1, &cid)])),
        Arc::new(InMemoryStateStore::new()),
        chain_verifier(&content),
        test_config(10),
        relaying_config(),
    );
    let sink = Arc::new(InMemorySink::new());
    let total = join_ok(dl.download(cid, sink.clone(), DownloadOptions::default()))
        .await
        .expect("the transfer completes over the hop path");

    assert_eq!(total, content.bytes.len() as u64);
    assert_eq!(
        sink.contents().await,
        content.bytes,
        "the assembled bytes are the content, delivered through the hops"
    );
    assert!(
        channel.range_calls() > 0,
        "every byte travelled the hop path — there was no direct transport to fall back on"
    );
    for path in channel.paths_seen() {
        assert_eq!(
            path,
            vec!["entry", "middle", "exit"],
            "each request travelled the full path, entry first"
        );
    }
}

/// NC-12 through a hop: a relay that corrupts what it carries is REFUSED, never believed.
///
/// Worth stating precisely, because the mechanism is not the one a reader might assume. A flipped
/// content byte is not caught by the per-range check — that check is structural (chunk length +
/// alignment + declared generation), so right-length wrong bytes survive it, which is exactly why the
/// crate has a whole-resource gate at all. The corruption dies at that gate, bound to the
/// chain-anchored root, and the transfer fails closed with nothing promoted.
///
/// The second half matters as much as the first: fail-closed must not mean permanently denied. Once
/// the hop stops corrupting, a further attempt completes, so the failure was a denial of one transfer
/// and not of the content.
#[tokio::test]
async fn a_hop_that_corrupts_what_it_carries_is_refused_and_does_not_deny_the_content_forever() {
    let content = MockContent::even(40, 4);
    let cid = mock_content_id();
    let state: Arc<dyn StateStore> = Arc::new(InMemoryStateStore::new());
    // ONE corrupted range, on one attempt, with an otherwise honest path — so the fixture keeps a
    // truthful control. A fixture where every hop corrupts every transfer could not distinguish
    // "rejected" from "never delivered".
    let hostile = HopChannel::new(
        Arc::new(MockRangeTransport::new(content.clone())),
        HopBehavior::CorruptsRangeAt(10),
    );
    let dl = onion_downloader(
        hostile.clone(),
        Arc::new(MockProviderLocator::fixed(vec![mock_provider(1, &cid)])),
        state.clone(),
        chain_verifier(&content),
        test_config(10),
        relaying_config(),
    );
    let sink = Arc::new(InMemorySink::new());
    let result = join_ok(dl.download(cid, sink.clone(), DownloadOptions::default())).await;

    assert_eq!(hostile.corrupted(), 1, "exactly one range was corrupted");
    assert!(
        matches!(result, Err(DownloadError::Verify(_))),
        "corrupted bytes from a hop are refused at the chain-anchored gate; got {result:?}"
    );
    assert_ne!(
        sink.contents().await,
        content.bytes,
        "the sink holds the unpromoted staging bytes, and they are NOT the content — nothing forged          was ever accepted as the content"
    );

    // The same requestor, the same state store, a path that has stopped corrupting: the content is
    // still obtainable. A hostile hop denies a transfer, not a capsule.
    let honest = HopChannel::new(
        Arc::new(MockRangeTransport::new(content.clone())),
        HopBehavior::Honest,
    );
    let dl_again = onion_downloader(
        honest,
        Arc::new(MockProviderLocator::fixed(vec![mock_provider(1, &cid)])),
        state,
        chain_verifier(&content),
        test_config(10),
        relaying_config(),
    );
    let clean_sink = Arc::new(InMemorySink::new());
    join_ok(dl_again.download(cid, clean_sink.clone(), DownloadOptions::default()))
        .await
        .expect("an honest path completes after a hostile one failed");
    assert_eq!(clean_sink.contents().await, content.bytes);
}

/// #31 through the new delivery path: a poisoned partial must not become a corrupt whole even when
/// every subsequent range is honest.
///
/// This is the case a length-only check passes: the tampered prefix has the right LENGTH, the honest
/// ranges verify individually, and the assembled file is wrong. It is asserted through the onion
/// transport specifically, so onion mode cannot re-open a guarantee direct mode already holds.
#[tokio::test]
async fn a_poisoned_partial_is_rejected_even_when_honest_hops_complete_the_file() {
    let content = MockContent::even(40, 4);
    let cid = mock_content_id();
    let dir = temp_dir("poisoned-partial");
    let final_path = dir.join("resource.dig");
    let state: Arc<dyn StateStore> = Arc::new(InMemoryStateStore::new());
    let verifier = chain_verifier(&content);

    // --- Run 1: two ranges arrive through the hops and are checkpointed, then the transfer is cut.
    let exit_a = Arc::new(MockRangeTransport::new(content.clone()));
    exit_a.set_delay(Duration::from_millis(10)).await;
    let dl_a = onion_downloader(
        HopChannel::new(exit_a, HopBehavior::Honest),
        Arc::new(MockProviderLocator::fixed(vec![mock_provider(1, &cid)])),
        state.clone(),
        verifier.clone(),
        test_config(10),
        relaying_config(),
    );
    let mut handle = dl_a.download(
        cid,
        Arc::new(FileSink::new(&final_path)),
        DownloadOptions::default(),
    );
    let mut done: Vec<usize> = Vec::new();
    while let Some(event) = handle.next_event().await {
        if let DownloadEvent::RangeCompleted { range, .. } = event {
            done.push(range);
            if done.len() == 2 {
                handle.cancel();
                break;
            }
        }
    }
    assert!(matches!(handle.join().await, Err(DownloadError::Cancelled)));
    assert_eq!(done.len(), 2, "two ranges were verified and checkpointed");

    // --- Poison the temp file INSIDE a range the checkpoint records as done and verified. Right
    //     length, wrong bytes: nothing about the partial's SIZE is disturbed.
    let staging = dig_download::staging_path_for(&final_path);
    let mut staged = std::fs::read(&staging).expect("the partial exists");
    let poisoned_at = done[0] * 10;
    staged[poisoned_at] ^= 0xFF;
    let poisoned_len = staged.len();
    std::fs::write(&staging, &staged).expect("poison the partial");

    // --- Run 2: honest hops complete the remaining ranges. The whole must still be REJECTED.
    let dl_b = onion_downloader(
        HopChannel::new(
            Arc::new(MockRangeTransport::new(content.clone())),
            HopBehavior::Honest,
        ),
        Arc::new(MockProviderLocator::fixed(vec![mock_provider(1, &cid)])),
        state.clone(),
        verifier.clone(),
        test_config(10),
        relaying_config(),
    );
    let resumed = join_ok(dl_b.download(
        cid,
        Arc::new(FileSink::new(&final_path)),
        DownloadOptions::default(),
    ))
    .await;
    assert!(
        matches!(resumed, Err(DownloadError::Verify(_))),
        "a poisoned partial completed by honest ranges is rejected, not promoted; got {resumed:?}"
    );
    assert!(
        !final_path.exists(),
        "nothing was promoted onto the final path"
    );
    assert_eq!(
        std::fs::read(&staging).map(|b| b.len()).unwrap_or(0),
        0,
        "the unverifiable partial was discarded rather than left to be resumed again \
         (it was {poisoned_len} bytes)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The originator is held to the same per-stream ceiling a hop would apply — and the refusal happens
/// BEFORE any hop is asked, so a request the path would refuse costs the network nothing.
#[tokio::test]
async fn a_window_above_the_per_stream_ceiling_is_refused_before_any_hop_is_asked() {
    let content = MockContent::even(40, 4);
    let cid = mock_content_id();
    let channel = HopChannel::new(
        Arc::new(MockRangeTransport::new(content.clone())),
        HopBehavior::Honest,
    );
    let policy = StreamRelayConfig {
        // Below the 10-byte range window the config plans, so every range is over the ceiling.
        max_bytes_per_stream: 4,
        ..relaying_config()
    };
    let dl = onion_downloader(
        channel.clone(),
        Arc::new(MockProviderLocator::fixed(vec![mock_provider(1, &cid)])),
        Arc::new(InMemoryStateStore::new()),
        chain_verifier(&content),
        test_config(10),
        policy,
    );
    let result = join_ok(dl.download(
        cid,
        Arc::new(InMemorySink::new()),
        DownloadOptions::default(),
    ))
    .await;
    // The specific refusal, not merely "an error": an outcome-shaped assertion would also pass if
    // the download failed for an unrelated reason (a dead hop, a verification miss) while the
    // oversized window was in fact carried.
    match result {
        Err(DownloadError::State(ref reason))
            if reason.contains("larger than this node will relay") => {}
        other => panic!("expected the per-stream-ceiling refusal to surface; got {other:?}"),
    }
    assert_eq!(
        channel.range_calls(),
        1,
        "the only thing a hop carried is the 1-byte metadata probe, which is legitimately under the ceiling; every 10-byte window was refused before it left this node"
    );
}
