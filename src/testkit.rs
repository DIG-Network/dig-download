//! In-memory test doubles for driving a [`Downloader`](crate::Downloader) with NO real network — a
//! mock [`ProviderLocator`] and a mock [`RangeTransport`] over a known "true" resource, with per-
//! provider misbehaviour (corrupt / truncated / dropping / unavailable sources).
//!
//! Used by this crate's own tests, and exported so a consumer (e.g. dig-node) can unit-test its
//! download wiring the same way. The doubles model the L7 peer network faithfully enough to exercise
//! the whole orchestrator: multi-source concurrent fan-out, per-range verification + bad-source
//! refetch, mid-download source drop + rebalance, provider-set refresh, and pause/resume.

use std::collections::HashMap;

use async_trait::async_trait;
use dig_dht::{CandidateAddr, ContentId, PeerId, ProviderRecord};
use dig_nat::{AvailabilityAnswer, AvailabilityItem, AvailabilityResponse};
use tokio::sync::Mutex;

use crate::error::DownloadError;
use crate::locate::ProviderLocator;
use crate::source::{FetchedRange, RangeMeta, RangeTransport};

/// The known "true" content the mock transport serves: the resource ciphertext + its chunk layout +
/// the chain-anchored metadata. A test builds one and asserts a download reproduces `bytes` exactly.
#[derive(Debug, Clone)]
pub struct MockContent {
    /// The full resource ciphertext an honest provider serves.
    pub bytes: Vec<u8>,
    /// The per-chunk ciphertext lengths (must sum to `bytes.len()`).
    pub chunk_lens: Vec<u64>,
    /// The chain-anchored generation root (64-hex) reported in each range's first frame.
    pub root: String,
    /// The whole-resource inclusion proof (base64), or `None` for a capsule.
    pub inclusion_proof: Option<String>,
    offsets: Vec<u64>,
}

impl MockContent {
    /// Build content from raw bytes + chunk lengths (which must sum to `bytes.len()`).
    pub fn new(bytes: Vec<u8>, chunk_lens: Vec<u64>) -> Self {
        assert_eq!(
            bytes.len() as u64,
            chunk_lens.iter().sum::<u64>(),
            "chunk_lens must sum to bytes.len()"
        );
        let mut offsets = Vec::with_capacity(chunk_lens.len() + 1);
        let mut acc = 0u64;
        offsets.push(0);
        for &l in &chunk_lens {
            acc += l;
            offsets.push(acc);
        }
        MockContent {
            bytes,
            chunk_lens,
            root: "ab".repeat(32),
            inclusion_proof: Some("mock-proof".into()),
            offsets,
        }
    }

    /// Evenly-chunked content of `n` bytes in `chunks` chunks (last chunk takes the remainder) —
    /// convenience for tests.
    pub fn even(n: usize, chunks: usize) -> Self {
        let chunks = chunks.max(1);
        let base = n / chunks;
        let mut lens = vec![base as u64; chunks];
        let assigned: u64 = lens.iter().sum();
        if let Some(last) = lens.last_mut() {
            *last += n as u64 - assigned;
        }
        let bytes: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        MockContent::new(bytes, lens)
    }

    fn chunk_index_at(&self, offset: u64) -> u64 {
        self.offsets.iter().position(|&o| o == offset).unwrap_or(0) as u64
    }

    fn meta(&self, offset: u64) -> RangeMeta {
        RangeMeta {
            total_length: Some(self.bytes.len() as u64),
            chunk_lens: Some(self.chunk_lens.clone()),
            chunk_index: Some(self.chunk_index_at(offset)),
            root: Some(self.root.clone()),
            inclusion_proof: self.inclusion_proof.clone(),
        }
    }
}

/// How one provider (mock source) behaves when asked for a range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Behavior {
    /// Serves correct bytes for every range (a good peer).
    Honest,
    /// Returns right-length but wrong (bit-flipped) bytes — passes the per-range length check but
    /// fails the whole-resource root binding (needs a real proof verifier to catch).
    Corrupt,
    /// Returns one byte short — caught immediately by the per-range length/alignment check.
    Truncate,
    /// Returns a boundary-aligned SHORT range: only the FIRST whole chunk of a multi-chunk range,
    /// so the bytes still start AND end on a chunk boundary. This defeats a purely structural
    /// alignment check (the short prefix is chunk-aligned) and is caught only by a per-range LENGTH
    /// check comparing `bytes.len()` to the requested `range.length` (the CRITICAL #179 finding).
    ShortAligned,
    /// Availability says "not held" and every fetch errors (a peer that does not have the content).
    Unavailable,
    /// Honest for the first `n` successful fetches, then every fetch errors — models a peer dropping
    /// mid-download so its ranges must rebalance to others.
    DropAfter(usize),
    /// Every fetch errors (a dead/unreachable peer).
    AlwaysFail,
    /// Serves correct-length bytes but reports a DIFFERENT generation `root` in the first-frame
    /// metadata than the content-id's root — a peer trying to shape the commitment to a different
    /// (attacker-chosen) generation. Must be rejected before the commitment is adopted ([HIGH #179]).
    WrongRoot,
}

/// A mock [`RangeTransport`] serving [`MockContent`] with per-provider [`Behavior`], recording fetch
/// attempts so tests can assert scheduling (which ranges went where, how often, and that resumed
/// ranges are not re-fetched).
pub struct MockRangeTransport {
    content: MockContent,
    behaviors: Mutex<HashMap<String, Behavior>>,
    provider_attempts: Mutex<HashMap<String, usize>>,
    offset_attempts: Mutex<HashMap<u64, usize>>,
    delay: Mutex<Option<std::time::Duration>>,
}

impl MockRangeTransport {
    /// A transport serving `content`; every provider is [`Behavior::Honest`] unless overridden.
    pub fn new(content: MockContent) -> Self {
        MockRangeTransport {
            content,
            behaviors: Mutex::new(HashMap::new()),
            provider_attempts: Mutex::new(HashMap::new()),
            offset_attempts: Mutex::new(HashMap::new()),
            delay: Mutex::new(None),
        }
    }

    /// Add an artificial per-fetch delay (so a test can reliably pause a download mid-flight).
    pub async fn set_delay(&self, delay: std::time::Duration) {
        *self.delay.lock().await = Some(delay);
    }

    /// Set `peer_id`'s behaviour (default [`Behavior::Honest`]).
    pub async fn set_behavior(&self, peer_id: &str, behavior: Behavior) {
        self.behaviors
            .lock()
            .await
            .insert(peer_id.to_string(), behavior);
    }

    /// Total fetch attempts made against `peer_id`.
    pub async fn attempts_for(&self, peer_id: &str) -> usize {
        self.provider_attempts
            .lock()
            .await
            .get(peer_id)
            .copied()
            .unwrap_or(0)
    }

    /// Total fetch attempts made for the range starting at `offset` (0 means never fetched — used to
    /// assert a resumed/verified range was NOT re-fetched).
    pub async fn attempts_at(&self, offset: u64) -> usize {
        self.offset_attempts
            .lock()
            .await
            .get(&offset)
            .copied()
            .unwrap_or(0)
    }

    async fn behavior(&self, peer_id: &str) -> Behavior {
        self.behaviors
            .lock()
            .await
            .get(peer_id)
            .cloned()
            .unwrap_or(Behavior::Honest)
    }
}

#[async_trait]
impl RangeTransport for MockRangeTransport {
    async fn query_availability(
        &self,
        provider: &ProviderRecord,
        items: Vec<AvailabilityItem>,
    ) -> Result<AvailabilityResponse, DownloadError> {
        let behavior = self.behavior(&provider.provider_peer_id).await;
        let held = !matches!(behavior, Behavior::Unavailable | Behavior::AlwaysFail);
        let answers = items
            .iter()
            .map(|_| AvailabilityAnswer {
                available: held,
                roots: Some(vec![self.content.root.clone()]),
                total_length: Some(self.content.bytes.len() as u64),
                chunk_count: Some(self.content.chunk_lens.len() as u64),
                complete: Some(true),
            })
            .collect();
        Ok(AvailabilityResponse { items: answers })
    }

    async fn fetch_range(
        &self,
        provider: &ProviderRecord,
        req: &dig_nat::RangeRequest,
    ) -> Result<FetchedRange, DownloadError> {
        let peer = provider.provider_peer_id.clone();
        let attempts = {
            let mut a = self.provider_attempts.lock().await;
            let n = a.entry(peer.clone()).or_insert(0);
            *n += 1;
            *n
        };
        *self
            .offset_attempts
            .lock()
            .await
            .entry(req.offset)
            .or_insert(0) += 1;

        if let Some(d) = *self.delay.lock().await {
            tokio::time::sleep(d).await;
        }

        let behavior = self.behavior(&peer).await;
        let fail = || DownloadError::transport(&peer, "mock: source failed");
        match behavior {
            Behavior::Unavailable | Behavior::AlwaysFail => return Err(fail()),
            Behavior::DropAfter(n) if attempts > n => return Err(fail()),
            _ => {}
        }

        let start = req.offset as usize;
        let end = (req.offset + req.length).min(self.content.bytes.len() as u64) as usize;
        let mut bytes = self.content.bytes[start..end].to_vec();
        match behavior {
            Behavior::Truncate => {
                bytes.pop(); // one byte short → per-range length check fails
            }
            Behavior::Corrupt => {
                for b in bytes.iter_mut() {
                    *b ^= 0xFF; // right length, wrong content → fails whole-resource root binding
                }
            }
            Behavior::ShortAligned => {
                // Serve only the FIRST whole chunk of the requested range. The result still starts
                // and ends on a chunk boundary (so a purely structural alignment check passes) but
                // is shorter than req.length — the CRITICAL boundary-aligned-short case.
                let first_chunk_idx = self.content.chunk_index_at(req.offset) as usize;
                if let Some(&first_len) = self.content.chunk_lens.get(first_chunk_idx) {
                    let keep = (first_len as usize).min(bytes.len());
                    if keep < bytes.len() {
                        bytes.truncate(keep);
                    }
                }
            }
            _ => {}
        }
        let mut meta = self.content.meta(req.offset);
        if matches!(behavior, Behavior::WrongRoot) {
            // Report a root that differs from both the honest content root and the content-id root.
            meta.root = Some("cd".repeat(32));
        }
        Ok(FetchedRange {
            request_offset: req.offset,
            bytes,
            meta,
        })
    }
}

/// A mock [`ProviderLocator`] returning a scripted sequence of provider batches — the first
/// `find_providers` returns batch 0, the next returns batch 1, etc. (the last batch repeats). Lets a
/// test model "the initial holders all failed; a re-locate discovers a fresh one".
pub struct MockProviderLocator {
    batches: Vec<Vec<ProviderRecord>>,
    calls: Mutex<usize>,
}

impl MockProviderLocator {
    /// A locator that always returns the same `providers`.
    pub fn fixed(providers: Vec<ProviderRecord>) -> Self {
        MockProviderLocator {
            batches: vec![providers],
            calls: Mutex::new(0),
        }
    }

    /// A locator returning `batches[0]`, then `batches[1]`, … on successive calls (last repeats).
    pub fn scripted(batches: Vec<Vec<ProviderRecord>>) -> Self {
        MockProviderLocator {
            batches: if batches.is_empty() {
                vec![vec![]]
            } else {
                batches
            },
            calls: Mutex::new(0),
        }
    }

    /// How many times `find_providers` has been called (to assert a re-locate happened).
    pub async fn call_count(&self) -> usize {
        *self.calls.lock().await
    }
}

#[async_trait]
impl ProviderLocator for MockProviderLocator {
    async fn find_providers(
        &self,
        _content: &ContentId,
    ) -> Result<Vec<ProviderRecord>, DownloadError> {
        let mut calls = self.calls.lock().await;
        let idx = (*calls).min(self.batches.len() - 1);
        *calls += 1;
        Ok(self.batches[idx].clone())
    }
}

/// Build a mock provider record for a peer numbered `n`, holding `content`, at a dummy direct address.
pub fn mock_provider(n: u8, content: &ContentId) -> ProviderRecord {
    ProviderRecord::new(
        &content.to_key(),
        &PeerId::from_bytes([n; 32]),
        vec![CandidateAddr::direct(format!("10.0.0.{n}"), 9444)],
        u64::MAX,
    )
}

/// The 64-hex `peer_id` of the mock provider numbered `n` (to key behaviours/assertions).
pub fn mock_peer_hex(n: u8) -> String {
    PeerId::from_bytes([n; 32]).to_hex()
}

/// A throwaway content id (resource granularity) for tests. Its generation `root` is `[0xAB; 32]`
/// (hex `"ab".repeat(32)`) so it MATCHES the root [`MockContent`] reports in each range's first
/// frame — the orchestrator cross-checks the peer-reported root against the content-id root
/// ([HIGH #179]), so the two must agree for an honest download to proceed.
pub fn mock_content_id() -> ContentId {
    ContentId::resource([1; 32], [0xAB; 32], [3; 32])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn honest_transport_serves_correct_slice() {
        let content = MockContent::even(30, 3);
        let t = MockRangeTransport::new(content.clone());
        let cid = mock_content_id();
        let p = mock_provider(1, &cid);
        let req = dig_nat::RangeRequest::resource("s", "r", 10, 10);
        let got = t.fetch_range(&p, &req).await.unwrap();
        assert_eq!(got.bytes, content.bytes[10..20]);
        assert_eq!(got.meta.chunk_lens, Some(content.chunk_lens.clone()));
        assert_eq!(t.attempts_at(10).await, 1);
        assert_eq!(t.attempts_for(&mock_peer_hex(1)).await, 1);
    }

    #[tokio::test]
    async fn behaviors_corrupt_and_truncate() {
        let content = MockContent::even(30, 3);
        let cid = mock_content_id();
        let p = mock_provider(2, &cid);
        let hex = mock_peer_hex(2);

        let t = MockRangeTransport::new(content.clone());
        t.set_behavior(&hex, Behavior::Truncate).await;
        let req = dig_nat::RangeRequest::resource("s", "r", 0, 10);
        let got = t.fetch_range(&p, &req).await.unwrap();
        assert_eq!(got.bytes.len(), 9);

        let t2 = MockRangeTransport::new(content.clone());
        t2.set_behavior(&hex, Behavior::Corrupt).await;
        let got2 = t2.fetch_range(&p, &req).await.unwrap();
        assert_eq!(got2.bytes.len(), 10);
        assert_ne!(got2.bytes, content.bytes[0..10]);
    }

    #[tokio::test]
    async fn drop_after_fails_late() {
        let content = MockContent::even(30, 3);
        let cid = mock_content_id();
        let p = mock_provider(3, &cid);
        let hex = mock_peer_hex(3);
        let t = MockRangeTransport::new(content);
        t.set_behavior(&hex, Behavior::DropAfter(1)).await;
        let req = dig_nat::RangeRequest::resource("s", "r", 0, 10);
        assert!(t.fetch_range(&p, &req).await.is_ok()); // 1st ok
        assert!(t.fetch_range(&p, &req).await.is_err()); // 2nd drops
    }

    #[tokio::test]
    async fn unavailable_source_reports_not_held() {
        let content = MockContent::even(30, 3);
        let cid = mock_content_id();
        let p = mock_provider(4, &cid);
        let hex = mock_peer_hex(4);
        let t = MockRangeTransport::new(content);
        t.set_behavior(&hex, Behavior::Unavailable).await;
        let resp = t
            .query_availability(
                &p,
                vec![AvailabilityItem {
                    store_id: "s".into(),
                    root: None,
                    retrieval_key: None,
                }],
            )
            .await
            .unwrap();
        assert!(!resp.items[0].available);
    }

    #[tokio::test]
    async fn scripted_locator_advances_batches() {
        let cid = mock_content_id();
        let loc = MockProviderLocator::scripted(vec![
            vec![mock_provider(1, &cid)],
            vec![mock_provider(1, &cid), mock_provider(2, &cid)],
        ]);
        assert_eq!(loc.find_providers(&cid).await.unwrap().len(), 1);
        assert_eq!(loc.find_providers(&cid).await.unwrap().len(), 2);
        assert_eq!(loc.find_providers(&cid).await.unwrap().len(), 2); // last repeats
        assert_eq!(loc.call_count().await, 3);
    }
}
