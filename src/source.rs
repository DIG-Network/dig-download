//! [`RangeTransport`] — fetch one byte range (or an availability answer) from one provider — plus
//! per-source health tracking and the real dig-nat-backed implementation.
//!
//! The orchestrator fans byte ranges across providers by calling [`RangeTransport::fetch_range`]
//! concurrently, one future per (provider, range). The trait abstracts the peer transport so the
//! scheduler is tested over an in-memory mock (see [`crate::testkit`]); the real
//! [`NatRangeTransport`] rides dig-nat (`dig.getAvailability` + `dig.fetchRange` over an mTLS mux
//! stream). A provider that fails or serves a bad range is penalized via [`SourceTracker`] so the
//! scheduler stops leaning on it.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dig_dht::ProviderRecord;
use dig_nat::{AvailabilityItem, AvailabilityResponse, RangeFrame, RangeRequest};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::DownloadError;

/// The verification metadata a range's **first frame** carries (L7 §9): the whole-resource shape a
/// downloader uses to establish or check the [`ResourceCommitment`](crate::verify::ResourceCommitment).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RangeMeta {
    /// The full resource ciphertext length.
    pub total_length: Option<u64>,
    /// Per-chunk ciphertext lengths of the whole resource, in order.
    pub chunk_lens: Option<Vec<u64>>,
    /// Index into `chunk_lens` of the first chunk in the range.
    pub chunk_index: Option<u64>,
    /// The chain-anchored generation root (64-hex).
    pub root: Option<String>,
    /// The whole-resource merkle inclusion proof (base64), or `None` for a capsule.
    pub inclusion_proof: Option<String>,
}

/// A fetched, reassembled byte range: the assembled ciphertext for the requested `[offset, offset+len)`
/// plus the first-frame verification metadata. The orchestrator verifies this against the resource
/// commitment, then writes `bytes` at `request_offset` in the sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedRange {
    /// The absolute resource offset the range was requested at (== [`RangeRequest::offset`]).
    pub request_offset: u64,
    /// The reassembled range ciphertext.
    pub bytes: Vec<u8>,
    /// The first-frame verification metadata for this range.
    pub meta: RangeMeta,
}

/// Fetch content ranges + availability from providers. The one network capability the orchestrator
/// needs, abstracted for testability (mock in [`crate::testkit`]; real [`NatRangeTransport`]).
#[async_trait]
pub trait RangeTransport: Send + Sync {
    /// Ask `provider` which of `items` it holds (`dig.getAvailability`) — the pre-check before fanning
    /// ranges. The answer's `total_length` / `chunk_count` also seed range planning.
    async fn query_availability(
        &self,
        provider: &ProviderRecord,
        items: Vec<AvailabilityItem>,
    ) -> Result<AvailabilityResponse, DownloadError>;

    /// Fetch the byte range described by `req` from `provider` (`dig.fetchRange`), streaming +
    /// reassembling the frames into a [`FetchedRange`]. A transport failure (connect/stream error) is
    /// a recoverable [`DownloadError::Transport`] — the orchestrator retries the range elsewhere.
    async fn fetch_range(
        &self,
        provider: &ProviderRecord,
        req: &RangeRequest,
    ) -> Result<FetchedRange, DownloadError>;
}

/// Health of one provider as a range source — failure count + a backoff window during which the
/// scheduler avoids it.
#[derive(Debug, Clone, Default)]
pub struct SourceHealth {
    /// Consecutive failures (reset on success).
    pub failures: u32,
    /// Total ranges this source has successfully served (for rebalancing / diagnostics).
    pub served: u64,
    /// Do not schedule this source again until this instant (set on failure, capped-exponential).
    pub backoff_until: Option<Instant>,
}

/// Tracks per-provider [`SourceHealth`] so the scheduler prefers healthy sources and backs off failed
/// ones (bounded exponential backoff), without ever permanently banning a source that might recover.
#[derive(Debug, Default)]
pub struct SourceTracker {
    health: HashMap<String, SourceHealth>,
    base_backoff: Duration,
    max_backoff: Duration,
}

impl SourceTracker {
    /// A tracker with the given base + max backoff (backoff doubles per consecutive failure, capped).
    pub fn new(base_backoff: Duration, max_backoff: Duration) -> Self {
        SourceTracker {
            health: HashMap::new(),
            base_backoff,
            max_backoff,
        }
    }

    /// Whether `peer_id` is schedulable at `now` (not inside a backoff window).
    pub fn is_available(&self, peer_id: &str, now: Instant) -> bool {
        match self.health.get(peer_id) {
            Some(h) => match h.backoff_until {
                Some(until) => now >= until,
                None => true,
            },
            None => true,
        }
    }

    /// Record a successful range served by `peer_id` (clears failures + backoff).
    pub fn record_success(&mut self, peer_id: &str) {
        let h = self.health.entry(peer_id.to_string()).or_default();
        h.failures = 0;
        h.served += 1;
        h.backoff_until = None;
    }

    /// Record a failure by `peer_id` at `now` and set its (capped-exponential) backoff window.
    pub fn record_failure(&mut self, peer_id: &str, now: Instant) {
        let base = self.base_backoff;
        let max = self.max_backoff;
        let h = self.health.entry(peer_id.to_string()).or_default();
        h.failures = h.failures.saturating_add(1);
        let shift = h.failures.saturating_sub(1).min(16);
        let backoff = base.checked_mul(1u32 << shift).unwrap_or(max).min(max);
        h.backoff_until = Some(now + backoff);
    }

    /// The number of successfully-served ranges recorded for `peer_id`.
    pub fn served(&self, peer_id: &str) -> u64 {
        self.health.get(peer_id).map(|h| h.served).unwrap_or(0)
    }

    /// The consecutive-failure count recorded for `peer_id`.
    pub fn failures(&self, peer_id: &str) -> u32 {
        self.health.get(peer_id).map(|h| h.failures).unwrap_or(0)
    }
}

/// Reassemble a `dig.fetchRange` frame stream into `(bytes, meta)`: read [`RangeFrame`]s in ascending
/// offset order, placing each frame's bytes at its (range-relative) offset and capturing the
/// first-frame verification metadata. Stops on the frame marked `complete` or clean end-of-stream.
///
/// Bounded by `max_len` (the expected range length) so a misbehaving peer cannot stream unbounded
/// bytes into memory. This is the pure, network-free core of [`NatRangeTransport::fetch_range`] and is
/// unit-tested by feeding encoded frames through an in-memory reader.
pub async fn assemble_range_stream<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_len: u64,
) -> Result<(Vec<u8>, RangeMeta), DownloadError> {
    let mut buf: Vec<u8> = Vec::new();
    let mut meta = RangeMeta::default();
    let mut first = true;
    loop {
        let frame = RangeFrame::decode(reader)
            .await
            .map_err(|e| DownloadError::Transport {
                provider: String::new(),
                reason: format!("range frame decode: {e}"),
            })?;
        let Some(frame) = frame else {
            break; // clean end-of-stream
        };
        if first {
            meta = RangeMeta {
                total_length: frame.total_length,
                chunk_lens: frame.chunk_lens.clone(),
                chunk_index: frame.chunk_index,
                root: frame.root.clone(),
                inclusion_proof: frame.inclusion_proof.clone(),
            };
            first = false;
        }
        let start = frame.offset as usize;
        let end = start + frame.bytes.len();
        if end as u64 > max_len {
            return Err(DownloadError::Transport {
                provider: String::new(),
                reason: format!("range frame overflows expected length {max_len}"),
            });
        }
        if buf.len() < end {
            buf.resize(end, 0);
        }
        buf[start..end].copy_from_slice(&frame.bytes);
        if frame.complete {
            break;
        }
    }
    Ok((buf, meta))
}

/// The real [`RangeTransport`] over dig-nat: connects to a provider with the best NAT-traversal
/// method (`dig_nat::connect`), reuses the connection via a small pool, and runs `dig.getAvailability`
/// / `dig.fetchRange` over the mux'd mTLS stream.
///
/// The network dial is the only part not exercised by the in-memory tests (it needs real sockets +
/// certs); the reassembly + provider→target mapping are pure and unit-tested. dig-node constructs one
/// of these with its [`LocalIdentity`](dig_nat::LocalIdentity) + [`NatConfig`](dig_nat::NatConfig) and
/// hands it to the [`Downloader`](crate::Downloader) — see the implementers' note in the crate docs.
pub struct NatRangeTransport {
    identity: dig_nat::LocalIdentity,
    config: dig_nat::NatConfig,
    network_id: String,
}

impl NatRangeTransport {
    /// Build a transport that dials providers on `network_id` using `identity` + `config`.
    pub fn new(
        identity: dig_nat::LocalIdentity,
        config: dig_nat::NatConfig,
        network_id: impl Into<String>,
    ) -> Self {
        NatRangeTransport {
            identity,
            config,
            network_id: network_id.into(),
        }
    }

    /// Build a [`dig_nat::PeerTarget`] from a provider record: its `peer_id` + the most-direct
    /// dialable candidate address (falling back to relay-only reachability by identity).
    pub fn provider_to_target(
        &self,
        provider: &ProviderRecord,
    ) -> Result<dig_nat::PeerTarget, DownloadError> {
        let peer_id = provider.provider_peer_id().ok_or_else(|| {
            DownloadError::transport(&provider.provider_peer_id, "malformed provider peer_id")
        })?;
        match provider.best_address() {
            Some(addr) => {
                let socket = format!("{}:{}", addr.host, addr.port)
                    .parse::<std::net::SocketAddr>()
                    .map_err(|e| {
                        DownloadError::transport(&provider.provider_peer_id, format!("addr: {e}"))
                    })?;
                Ok(dig_nat::PeerTarget::with_addr(
                    peer_id,
                    socket,
                    self.network_id.clone(),
                ))
            }
            None => Ok(dig_nat::PeerTarget::relay_only(
                peer_id,
                self.network_id.clone(),
            )),
        }
    }

    /// Connect to a provider (fresh mTLS connection via the NAT-traversal ladder).
    async fn connect(
        &self,
        provider: &ProviderRecord,
    ) -> Result<dig_nat::PeerConnection, DownloadError> {
        let target = self.provider_to_target(provider)?;
        dig_nat::connect(&target, &self.identity, &self.config)
            .await
            .map_err(|e| DownloadError::transport(&provider.provider_peer_id, e))
    }
}

#[async_trait]
impl RangeTransport for NatRangeTransport {
    async fn query_availability(
        &self,
        provider: &ProviderRecord,
        items: Vec<AvailabilityItem>,
    ) -> Result<AvailabilityResponse, DownloadError> {
        let mut conn = self.connect(provider).await?;
        conn.query_availability(items)
            .await
            .map_err(|e| DownloadError::transport(&provider.provider_peer_id, e))
    }

    async fn fetch_range(
        &self,
        provider: &ProviderRecord,
        req: &RangeRequest,
    ) -> Result<FetchedRange, DownloadError> {
        let mut conn = self.connect(provider).await?;
        let mut stream = conn
            .open_range_stream(req)
            .await
            .map_err(|e| DownloadError::transport(&provider.provider_peer_id, e))?;
        let (bytes, meta) = assemble_range_stream(&mut stream, req.length)
            .await
            .map_err(|e| {
                // Re-stamp the (empty) provider on the reassembly error with the real provider id.
                DownloadError::transport(&provider.provider_peer_id, e)
            })?;
        // Drain any trailer so the mux stream closes cleanly.
        let mut sink = Vec::new();
        let _ = stream.read_to_end(&mut sink).await;
        Ok(FetchedRange {
            request_offset: req.offset,
            bytes,
            meta,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_dht::{CandidateAddr, ProviderRecord};
    use dig_nat::PeerId;

    fn provider(peer: u8, host: &str, port: u16) -> ProviderRecord {
        ProviderRecord::new(
            &dig_dht::Key::from_bytes([0xAB; 32]),
            &PeerId::from_bytes([peer; 32]),
            vec![CandidateAddr::direct(host, port)],
            u64::MAX,
        )
    }

    #[test]
    fn provider_to_target_uses_direct_address() {
        let t = NatRangeTransport::new(
            fake_identity(),
            dig_nat::NatConfig::default(),
            "DIG_MAINNET",
        );
        let p = provider(1, "203.0.113.7", 9444);
        let target = t.provider_to_target(&p).unwrap();
        assert_eq!(target.direct_addr.unwrap().to_string(), "203.0.113.7:9444");
        assert_eq!(target.network_id, "DIG_MAINNET");
    }

    #[test]
    fn provider_to_target_relay_only_without_address() {
        let t = NatRangeTransport::new(
            fake_identity(),
            dig_nat::NatConfig::default(),
            "DIG_MAINNET",
        );
        let p = ProviderRecord::new(
            &dig_dht::Key::from_bytes([0xAB; 32]),
            &PeerId::from_bytes([2; 32]),
            vec![CandidateAddr::relay_marker()],
            u64::MAX,
        );
        let target = t.provider_to_target(&p).unwrap();
        assert!(target.direct_addr.is_none());
    }

    #[tokio::test]
    async fn assemble_reassembles_ordered_frames() {
        // Two frames tiling a 6-byte range; first frame carries the metadata.
        let f0 = RangeFrame {
            offset: 0,
            length: 3,
            bytes: b"ABC".to_vec(),
            complete: false,
            total_length: Some(6),
            chunk_lens: Some(vec![3, 3]),
            chunk_index: Some(0),
            inclusion_proof: Some("proof".into()),
            root: Some("aa".repeat(32)),
        };
        let f1 = RangeFrame {
            offset: 3,
            length: 3,
            bytes: b"DEF".to_vec(),
            complete: true,
            total_length: None,
            chunk_lens: None,
            chunk_index: None,
            inclusion_proof: None,
            root: None,
        };
        let mut wire = f0.encode();
        wire.extend_from_slice(&f1.encode());
        let mut cur = std::io::Cursor::new(wire);
        let (bytes, meta) = assemble_range_stream(&mut cur, 6).await.unwrap();
        assert_eq!(bytes, b"ABCDEF");
        assert_eq!(meta.total_length, Some(6));
        assert_eq!(meta.chunk_lens, Some(vec![3, 3]));
        assert_eq!(meta.chunk_index, Some(0));
        assert_eq!(meta.root, Some("aa".repeat(32)));
        assert_eq!(meta.inclusion_proof, Some("proof".into()));
    }

    #[tokio::test]
    async fn assemble_rejects_overflowing_frame() {
        let f = RangeFrame {
            offset: 0,
            length: 10,
            bytes: vec![0u8; 10],
            complete: true,
            total_length: None,
            chunk_lens: None,
            chunk_index: None,
            inclusion_proof: None,
            root: None,
        };
        let mut cur = std::io::Cursor::new(f.encode());
        let err = assemble_range_stream(&mut cur, 5).await;
        assert!(matches!(err, Err(DownloadError::Transport { .. })));
    }

    #[tokio::test]
    async fn assemble_stops_on_clean_eof() {
        // A single non-complete frame followed by EOF still yields the bytes.
        let f = RangeFrame {
            offset: 0,
            length: 2,
            bytes: b"hi".to_vec(),
            complete: false,
            total_length: Some(2),
            chunk_lens: Some(vec![2]),
            chunk_index: Some(0),
            inclusion_proof: None,
            root: None,
        };
        let mut cur = std::io::Cursor::new(f.encode());
        let (bytes, meta) = assemble_range_stream(&mut cur, 2).await.unwrap();
        assert_eq!(bytes, b"hi");
        assert_eq!(meta.total_length, Some(2));
    }

    #[test]
    fn source_tracker_backoff_and_recovery() {
        let mut t = SourceTracker::new(Duration::from_millis(100), Duration::from_secs(10));
        let now = Instant::now();
        assert!(t.is_available("p", now));
        t.record_failure("p", now);
        assert!(!t.is_available("p", now)); // inside backoff
        assert_eq!(t.failures("p"), 1);
        // After the backoff window it is schedulable again.
        assert!(t.is_available("p", now + Duration::from_millis(101)));
        // Success clears failures + backoff and counts a served range.
        t.record_success("p");
        assert!(t.is_available("p", now));
        assert_eq!(t.failures("p"), 0);
        assert_eq!(t.served("p"), 1);
    }

    #[test]
    fn source_tracker_backoff_is_exponential_and_capped() {
        let mut t = SourceTracker::new(Duration::from_millis(100), Duration::from_millis(250));
        let now = Instant::now();
        t.record_failure("p", now); // 100ms
        assert!(t.is_available("p", now + Duration::from_millis(150)));
        t.record_failure("p", now); // 200ms
        assert!(!t.is_available("p", now + Duration::from_millis(150)));
        t.record_failure("p", now); // 400ms → capped to 250ms
        assert!(t.is_available("p", now + Duration::from_millis(260)));
    }

    fn fake_identity() -> dig_nat::LocalIdentity {
        // A syntactically-valid but non-functional identity is fine for the pure helpers under test
        // (they never dial). We build it from a minimal self-signed-shaped DER is unnecessary — the
        // helpers only read peer_id/target fields — so construct via the public struct fields.
        dig_nat::LocalIdentity {
            cert_der: vec![],
            key_der: vec![],
            peer_id: PeerId::from_bytes([9; 32]),
        }
    }
}
