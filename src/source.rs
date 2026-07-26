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
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dig_dht::ProviderRecord;
use dig_nat::{AvailabilityItem, AvailabilityResponse, RangeFrame, RangeRequest};
use dig_peer::DigPeer;
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
/// bytes into memory: a frame that overshoots the window is CLIPPED to it (servers answer at chunk
/// granularity, so a 1-byte metadata probe is legitimately served a whole chunk), assembly stops as
/// soon as the window is full, and only a frame starting at or beyond `max_len` is an error.
///
/// This is the pure, network-free core of [`NatRangeTransport::fetch_range`] and is
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
        // A zero-length request asks for metadata ONLY (there is no window to place bytes in), so the
        // first frame's meta is all it wanted.
        if max_len == 0 {
            break;
        }
        // A frame that starts at or past the end of the requested window carries bytes that can never
        // belong to this range — a real protocol violation, not a granularity mismatch.
        if frame.offset >= max_len {
            return Err(DownloadError::Transport {
                provider: String::new(),
                reason: format!(
                    "range frame at offset {} starts beyond expected length {max_len}",
                    frame.offset
                ),
            });
        }
        // CLIP an over-long frame instead of rejecting it: a server legitimately answers at CHUNK
        // granularity, so a 1-byte metadata probe is served a whole chunk (#836). Taking only the
        // requested window keeps memory bounded by `max_len` AND keeps such a holder usable.
        let start = frame.offset as usize;
        let take = frame.bytes.len().min((max_len - frame.offset) as usize);
        let end = start + take;
        if buf.len() < end {
            buf.resize(end, 0);
        }
        buf[start..end].copy_from_slice(&frame.bytes[..take]);
        if frame.complete || buf.len() as u64 >= max_len {
            break;
        }
    }
    Ok((buf, meta))
}

/// The maximum number of trailer bytes drained from a range stream after the complete/last frame,
/// before the mux stream is closed. A well-behaved peer sends nothing (or a tiny framing tail) after
/// the last frame, so this bound is generous; it exists solely to close off a malicious peer that
/// holds the stream open and streams arbitrary filler (see [`drain_trailer_bounded`]).
const MAX_TRAILER_DRAIN: u64 = 64 * 1024;

/// Drain and DISCARD up to `cap` trailer bytes from `reader` (the leftover after a range's last
/// frame), so the mux stream closes cleanly WITHOUT buffering an unbounded trailer into memory.
///
/// A previous implementation did `stream.read_to_end(&mut Vec::new())`, which has no length bound: a
/// peer that serves a valid complete range then keeps the stream open and streams filler forces the
/// client to buffer all of it until OOM (MEDIUM #179). This reads into a small fixed scratch buffer
/// and stops once `cap` bytes have been seen (or at EOF / error), never growing an unbounded `Vec`.
/// Returns the number of trailer bytes drained (capped at `cap`).
pub async fn drain_trailer_bounded<R: AsyncRead + Unpin>(reader: &mut R, cap: u64) -> u64 {
    let mut scratch = [0u8; 4096];
    let mut drained: u64 = 0;
    while drained < cap {
        let want = ((cap - drained) as usize).min(scratch.len());
        match reader.read(&mut scratch[..want]).await {
            Ok(0) => break, // EOF — stream ended cleanly
            Ok(n) => drained += n as u64,
            Err(_) => break, // treat a read error as end-of-drain (stream will be dropped)
        }
    }
    drained
}

/// A pooled per-peer [`DigPeer`] client, shared behind a mutex so many range fetches to the SAME peer
/// reuse ONE mTLS session (opening a cheap fresh yamux stream each) instead of re-handshaking per
/// request. The `&mut self` [`DigPeer`] RPC receivers are serialized by the mutex.
type PooledConn = Arc<tokio::sync::Mutex<DigPeer>>;

/// The real [`RangeTransport`] over [`dig-peer`](dig_peer): connects to a provider as a
/// [`DigPeer`] — the one DIG Network peer client — over the FULL NAT-traversal ladder (direct →
/// UPnP/NAT-PMP/PCP → hole-punch → relay, IPv6-first), **reuses the client via a per-peer pool**, and
/// runs `dig.getAvailability` / `dig.fetchRange` over the mux'd mTLS session.
///
/// # Why DigPeer (#1283)
///
/// dig-download talks to peers through the shared [`DigPeer`] client rather than driving
/// [`dig_nat`] directly, so the whole ecosystem reaches peers ONE way. Every connection is
/// established through a [`PeerTarget`](dig_nat::PeerTarget) carrying the provider's `peer_id`, which
/// [`DigPeer::connect`] PINS the mTLS handshake to: a caller that means to reach provider X cannot be
/// answered by a different CA-valid peer (the impersonation footgun). The availability + range calls
/// are public-read (merkle-verified content), so they ride the mTLS channel unsealed (§5.4 exemption);
/// this transport therefore configures no [`SealingIdentity`](dig_peer::SealingIdentity).
///
/// # The NAT ladder on the fetch leg (#1305)
///
/// Discovery (dig-dht lookups) already rides the full ladder via a live [`dig_nat::NatRuntime`]; the
/// content byte-download must too, or a fully-NAT'd peer would DISCOVER a provider it can never FETCH
/// from (a non-Direct-reachable holder reachable only via hole-punch/relay). This transport connects
/// via [`DigPeer::connect_with_runtime`], composing exactly the tiers whose live handles the injected
/// [`NatRuntime`](dig_nat::NatRuntime) carries: an empty runtime ([`new`](Self::new)) is Direct-only; a node's real runtime
/// ([`new_with_runtime`](Self::new_with_runtime)) unlocks hole-punch + relay. dig-node builds the SAME
/// shared `NatRuntime` it uses for the DHT-side dial and hands it here.
///
/// A download fans many ranges across a few providers; without pooling every range fetch paid a full
/// NAT-traversal + mTLS handshake (LOW #179). The pool keeps one [`DigPeer`] per `peer_id` and opens a
/// new mux stream per request over the reused mTLS session; a client that errors is evicted so the
/// next request re-dials. For `fetch_range` the per-peer lock is held only while opening the (owned)
/// range stream, then released before the bytes are read, so concurrent ranges to the same peer still
/// stream in parallel.
///
/// The network dial is the only part not exercised by the in-memory tests (it needs real sockets +
/// certs); the reassembly + provider→target mapping are pure and unit-tested. dig-node constructs one
/// of these with its [`NodeCert`](dig_nat::NodeCert) (its CA-signed mTLS identity, minted by dig-tls's
/// `NodeCert::load_or_generate`) + [`NatConfig`](dig_nat::NatConfig) + its live [`NatRuntime`](dig_nat::NatRuntime) and
/// hands it to the [`Downloader`](crate::Downloader) — see the implementers' note in the crate docs.
pub struct NatRangeTransport {
    node: std::sync::Arc<dig_nat::NodeCert>,
    config: dig_nat::NatConfig,
    network_id: String,
    /// The live traversal handles (relay reservation / hole-punch coordinator / mapped port) the
    /// full-ladder dial composes each connect from. An empty runtime yields a Direct-only dial; a
    /// node's real runtime unlocks the hole-punch + relay tiers (#1305). Shared (`Arc`) so it can be
    /// the SAME runtime the node's DHT-side dial uses.
    runtime: Arc<dig_nat::NatRuntime>,
    /// Per-peer connection pool keyed by provider `peer_id` (the 64-hex string).
    pool: tokio::sync::Mutex<HashMap<String, PooledConn>>,
}

impl NatRangeTransport {
    /// Build a transport that dials providers on `network_id`, presenting `node` (this peer's
    /// CA-signed mTLS identity) and using `config` to select the traversal methods + timeouts.
    ///
    /// This uses an EMPTY [`NatRuntime`](dig_nat::NatRuntime), so the dial composes the **Direct** tier only — suitable for
    /// a fully-reachable node or a test. A NAT'd node that must reach non-Direct providers over
    /// hole-punch/relay MUST use [`new_with_runtime`](Self::new_with_runtime) with its live runtime.
    pub fn new(
        node: std::sync::Arc<dig_nat::NodeCert>,
        config: dig_nat::NatConfig,
        network_id: impl Into<String>,
    ) -> Self {
        Self::new_with_runtime(
            node,
            config,
            network_id,
            Arc::new(dig_nat::NatRuntime::default()),
        )
    }

    /// Build a transport that dials over the **FULL** NAT-traversal ladder using the live handles in
    /// `runtime` (#1305). Mirrors the node's DHT-side [`dig_nat::connect_with_runtime`] path so the
    /// content-fetch leg reaches providers via hole-punch + relay, not just direct. dig-node passes the
    /// SAME shared [`NatRuntime`](dig_nat::NatRuntime) it built for its DHT transport.
    pub fn new_with_runtime(
        node: std::sync::Arc<dig_nat::NodeCert>,
        config: dig_nat::NatConfig,
        network_id: impl Into<String>,
        runtime: Arc<dig_nat::NatRuntime>,
    ) -> Self {
        NatRangeTransport {
            node,
            config,
            network_id: network_id.into(),
            runtime,
            pool: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Every way to reach `provider`, in dial order: each resolvable candidate address as a
    /// [`dig_nat::PeerTarget`] — **IPv6 first, then IPv4** (§5.2) — followed by a relay-only target
    /// reached purely by identity.
    ///
    /// Each entry carries the candidate's rendered address so a failed dial can name WHICH address it
    /// tried. Unresolvable candidates are logged and skipped rather than aborting the provider: one
    /// malformed v6 candidate must never hide a working v4 one (#836).
    pub fn provider_dial_targets(
        &self,
        provider: &ProviderRecord,
    ) -> Result<Vec<(String, dig_nat::PeerTarget)>, DownloadError> {
        let peer_id = provider.provider_peer_id().ok_or_else(|| {
            DownloadError::transport(&provider.provider_peer_id, "malformed provider peer_id")
        })?;
        let mut targets = Vec::new();
        for candidate in crate::addr::dial_candidates(provider) {
            match crate::addr::candidate_socket(candidate) {
                Ok(socket) => targets.push((
                    socket.to_string(),
                    dig_nat::PeerTarget::with_addr(peer_id, socket, self.network_id.clone()),
                )),
                Err(e) => tracing::warn!(
                    peer = %crate::error::hex64_or_sentinel(&provider.provider_peer_id, "peer-id"),
                    candidate = %crate::addr::display(candidate),
                    error = %e,
                    "skipping unusable provider candidate address"
                ),
            }
        }
        targets.push((
            "relay-only".to_string(),
            dig_nat::PeerTarget::relay_only(peer_id, self.network_id.clone()),
        ));
        Ok(targets)
    }

    /// Build a [`dig_nat::PeerTarget`] from a provider record: its `peer_id` + the most-direct
    /// dialable candidate address (falling back to relay-only reachability by identity).
    ///
    /// This is the FIRST of [`provider_dial_targets`](Self::provider_dial_targets); dialing uses the
    /// full ordered list so a failing candidate falls through to the next.
    pub fn provider_to_target(
        &self,
        provider: &ProviderRecord,
    ) -> Result<dig_nat::PeerTarget, DownloadError> {
        let (_, target) = self
            .provider_dial_targets(provider)?
            .into_iter()
            .next()
            .expect("dial targets always include the relay-only fallback");
        Ok(target)
    }

    /// Connect to a provider as a [`DigPeer`] (fresh `peer_id`-pinned mTLS connection over the FULL
    /// NAT-traversal ladder). Composes exactly the tiers whose live handles this transport's
    /// [`NatRuntime`](dig_nat::NatRuntime) carries — Direct always, plus hole-punch/relay when the node
    /// injected them (#1305). The [`PeerTarget`](dig_nat::PeerTarget) carries the provider's `peer_id`,
    /// which [`DigPeer::connect_with_runtime`] pins so a different CA-valid peer cannot impersonate the
    /// intended provider (#1283).
    ///
    /// Every candidate address is tried in order (IPv6 first, then IPv4, then relay-only, §5.2) and
    /// each failure is logged with the address that produced it, so an unreachable v6 candidate falls
    /// through to a working v4 one instead of failing the whole holder (#836).
    async fn connect(&self, provider: &ProviderRecord) -> Result<DigPeer, DownloadError> {
        let mut last_error = None;
        for (addr, target) in self.provider_dial_targets(provider)? {
            match DigPeer::connect_with_runtime(&target, &self.node, &self.config, &self.runtime)
                .await
            {
                Ok(peer) => return Ok(peer),
                Err(e) => {
                    tracing::debug!(
                        peer = %crate::error::hex64_or_sentinel(&provider.provider_peer_id, "peer-id"),
                        candidate = %addr,
                        error = %e,
                        "provider dial candidate failed; trying the next address"
                    );
                    last_error = Some(format!("dial {addr}: {e}"));
                }
            }
        }
        Err(DownloadError::transport(
            &provider.provider_peer_id,
            last_error.unwrap_or_else(|| "no dialable candidate address".to_string()),
        ))
    }

    /// Get the pooled connection for `provider`, dialing (and caching) a fresh one if none is pooled.
    /// Reuses the existing mTLS session across requests; a broken connection is evicted via
    /// [`evict`](Self::evict) so the next call re-dials.
    async fn pooled_conn(&self, provider: &ProviderRecord) -> Result<PooledConn, DownloadError> {
        let key = provider.provider_peer_id.clone();
        if let Some(conn) = self.pool.lock().await.get(&key).cloned() {
            return Ok(conn);
        }
        // Dial OUTSIDE the pool lock (a handshake can be slow); race-insert, reusing a connection a
        // concurrent caller may have inserted first so we never hold two sessions to one peer.
        let fresh = Arc::new(tokio::sync::Mutex::new(self.connect(provider).await?));
        let mut pool = self.pool.lock().await;
        Ok(pool.entry(key).or_insert(fresh).clone())
    }

    /// Drop `provider`'s pooled connection so the next request re-dials (called after a stream error).
    async fn evict(&self, provider: &ProviderRecord) {
        self.pool.lock().await.remove(&provider.provider_peer_id);
    }
}

#[async_trait]
impl RangeTransport for NatRangeTransport {
    async fn query_availability(
        &self,
        provider: &ProviderRecord,
        items: Vec<AvailabilityItem>,
    ) -> Result<AvailabilityResponse, DownloadError> {
        let conn = self.pooled_conn(provider).await?;
        let res = {
            let mut guard = conn.lock().await;
            guard.get_availability(items).await
        };
        match res {
            Ok(resp) => Ok(resp),
            Err(e) => {
                // The pooled session is suspect — drop it so the next request re-dials.
                self.evict(provider).await;
                Err(DownloadError::transport(&provider.provider_peer_id, e))
            }
        }
    }

    async fn fetch_range(
        &self,
        provider: &ProviderRecord,
        req: &RangeRequest,
    ) -> Result<FetchedRange, DownloadError> {
        let conn = self.pooled_conn(provider).await?;
        // Hold the per-peer lock ONLY to open the (owned) range stream over the reused mTLS session;
        // release it before reading frames so concurrent ranges to the same peer stream in parallel.
        let stream = {
            let mut guard = conn.lock().await;
            guard.fetch_range(req).await
        };
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                self.evict(provider).await;
                return Err(DownloadError::transport(&provider.provider_peer_id, e));
            }
        };
        let (bytes, meta) = assemble_range_stream(&mut stream, req.length)
            .await
            .map_err(|e| {
                // Re-stamp the (empty) provider on the reassembly error with the real provider id.
                DownloadError::transport(&provider.provider_peer_id, e)
            })?;
        // Drain any trailer so the mux stream closes cleanly — BOUNDED, so a peer that keeps the
        // stream open and streams filler after the last frame cannot exhaust our memory (MEDIUM
        // #179). Never read_to_end into an unbounded Vec.
        let _ = drain_trailer_bounded(&mut stream, MAX_TRAILER_DRAIN).await;
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
            fake_node_cert(),
            dig_nat::NatConfig::default(),
            "DIG_MAINNET",
        );
        let p = provider(1, "203.0.113.7", 9444);
        let target = t.provider_to_target(&p).unwrap();
        assert_eq!(
            target.direct_addr().unwrap().to_string(),
            "203.0.113.7:9444"
        );
        assert_eq!(target.network_id, "DIG_MAINNET");
    }

    #[test]
    fn new_with_runtime_builds_a_full_ladder_transport() {
        // #1305: the fetch leg must be constructible with a live NatRuntime (the same handle carrier
        // the node's DHT dial uses) so hole-punch/relay tiers compose. The dial itself needs real
        // sockets, so here we assert the runtime-injecting constructor yields a working transport
        // whose pure provider→target mapping is identical to the Direct-only `new`.
        let runtime = std::sync::Arc::new(dig_nat::NatRuntime::default());
        let t = NatRangeTransport::new_with_runtime(
            fake_node_cert(),
            dig_nat::NatConfig::default(),
            "DIG_MAINNET",
            runtime,
        );
        let p = provider(1, "203.0.113.7", 9444);
        let target = t.provider_to_target(&p).unwrap();
        assert_eq!(
            target.direct_addr().unwrap().to_string(),
            "203.0.113.7:9444"
        );
        assert_eq!(target.network_id, "DIG_MAINNET");
    }

    #[test]
    fn provider_to_target_accepts_v4_mapped_v6_host() {
        // #836 regression: the e2e read leg died with "addr: invalid socket address syntax" because
        // the host+port were STRING-formatted before parsing, and an IPv6 literal needs brackets.
        let t = NatRangeTransport::new(
            fake_node_cert(),
            dig_nat::NatConfig::default(),
            "DIG_MAINNET",
        );
        let p = provider(1, "::ffff:172.31.79.22", 9444);
        let target = t
            .provider_to_target(&p)
            .expect("v4-mapped v6 host must resolve");
        assert_eq!(
            target.direct_addr().unwrap(),
            std::net::SocketAddr::new("::ffff:172.31.79.22".parse().unwrap(), 9444)
        );
    }

    #[test]
    fn provider_to_target_accepts_plain_v6_host() {
        let t = NatRangeTransport::new(
            fake_node_cert(),
            dig_nat::NatConfig::default(),
            "DIG_MAINNET",
        );
        let p = provider(1, "2001:db8::1", 9444);
        let target = t.provider_to_target(&p).expect("v6 host must resolve");
        assert_eq!(
            target.direct_addr().unwrap(),
            std::net::SocketAddr::new("2001:db8::1".parse().unwrap(), 9444)
        );
    }

    #[test]
    fn unusable_first_candidate_falls_through_to_the_ipv4_one() {
        // #836 / §5.2: IPv6-first with IPv4 FALLBACK. A provider whose leading candidate is unusable
        // must still be dialed on its valid v4 candidate — previously the record's FIRST address was
        // the only one considered, so one bad candidate condemned the holder.
        let t = NatRangeTransport::new(
            fake_node_cert(),
            dig_nat::NatConfig::default(),
            "DIG_MAINNET",
        );
        let p = ProviderRecord::new(
            &dig_dht::Key::from_bytes([0xAB; 32]),
            &PeerId::from_bytes([3; 32]),
            vec![
                CandidateAddr::direct("not-an-ip-literal", 9444),
                CandidateAddr::direct("10.0.0.1", 9444),
            ],
            u64::MAX,
        );
        let target = t
            .provider_to_target(&p)
            .expect("the v4 candidate is dialable");
        assert_eq!(
            target.direct_addr().unwrap(),
            "10.0.0.1:9444".parse::<std::net::SocketAddr>().unwrap()
        );
    }

    #[test]
    fn dial_targets_order_v6_then_v4_then_relay() {
        let t = NatRangeTransport::new(
            fake_node_cert(),
            dig_nat::NatConfig::default(),
            "DIG_MAINNET",
        );
        let p = ProviderRecord::new(
            &dig_dht::Key::from_bytes([0xAB; 32]),
            &PeerId::from_bytes([4; 32]),
            vec![
                CandidateAddr::direct("172.31.79.22", 9444),
                CandidateAddr::direct("::ffff:172.31.79.22", 9444),
            ],
            u64::MAX,
        );
        let addrs: Vec<String> = t
            .provider_dial_targets(&p)
            .unwrap()
            .into_iter()
            .map(|(addr, _)| addr)
            .collect();
        assert_eq!(
            addrs,
            vec![
                "[::ffff:172.31.79.22]:9444",
                "172.31.79.22:9444",
                "relay-only"
            ]
        );
    }

    #[tokio::test]
    async fn connect_tries_every_candidate_before_failing() {
        // Both candidates are closed loopback ports: the dial must walk the whole list (v6 then v4
        // then relay-only) and report the LAST attempt, proving no early give-up.
        let t = NatRangeTransport::new(
            fake_node_cert(),
            dig_nat::NatConfig::default(),
            "DIG_MAINNET",
        );
        let p = ProviderRecord::new(
            &dig_dht::Key::from_bytes([0xAB; 32]),
            &PeerId::from_bytes([5; 32]),
            vec![
                CandidateAddr::direct("::1", 1),
                CandidateAddr::direct("127.0.0.1", 1),
            ],
            u64::MAX,
        );
        let err = t.connect(&p).await.expect_err("no listener is up");
        let reason = err.to_string();
        assert!(
            reason.contains("relay-only"),
            "the last attempt must be named: {reason}"
        );
    }

    #[test]
    fn provider_to_target_relay_only_without_address() {
        let t = NatRangeTransport::new(
            fake_node_cert(),
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
        assert!(target.direct_addr().is_none());
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

    /// A frame that STARTS beyond the requested window is a real protocol violation (its bytes can
    /// never belong to the range) and stays an error.
    #[tokio::test]
    async fn assemble_rejects_frame_starting_beyond_window() {
        let f = RangeFrame {
            offset: 8,
            length: 4,
            bytes: vec![0u8; 4],
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

    /// The #836 metadata probe: `establish_commitment` asks for `length = 1` purely to obtain the
    /// first-frame metadata, and a chunk-granular server answers with a WHOLE chunk. The assembler
    /// must clip to the requested window and keep the metadata — erroring here discarded every
    /// holder and turned a healthy read into a 404.
    #[tokio::test]
    async fn assemble_clips_chunk_granular_frame_to_one_byte_probe() {
        let chunk = vec![0x5Au8; 4096];
        let f = RangeFrame {
            offset: 0,
            length: chunk.len() as u64,
            bytes: chunk,
            complete: true,
            total_length: Some(1_048_576),
            chunk_lens: Some(vec![4096; 256]),
            chunk_index: Some(0),
            inclusion_proof: Some("proof".into()),
            root: Some("aa".repeat(32)),
        };
        let mut cur = std::io::Cursor::new(f.encode());
        let (bytes, meta) = assemble_range_stream(&mut cur, 1).await.unwrap();
        assert_eq!(
            bytes,
            vec![0x5Au8],
            "clipped to exactly the requested window"
        );
        assert_eq!(meta.total_length, Some(1_048_576));
        assert_eq!(meta.chunk_lens, Some(vec![4096; 256]));
        assert_eq!(meta.chunk_index, Some(0));
        assert_eq!(meta.root, Some("aa".repeat(32)));
        assert_eq!(meta.inclusion_proof, Some("proof".into()));
    }

    /// Only the OVERSHOOTING tail is clipped: every earlier frame's bytes survive, in order.
    #[tokio::test]
    async fn assemble_clips_only_the_overshooting_last_frame() {
        let f0 = RangeFrame {
            offset: 0,
            length: 3,
            bytes: b"ABC".to_vec(),
            complete: false,
            total_length: Some(9),
            chunk_lens: Some(vec![3, 6]),
            chunk_index: Some(0),
            inclusion_proof: None,
            root: None,
        };
        let f1 = RangeFrame {
            offset: 3,
            length: 6,
            bytes: b"DEFGHI".to_vec(),
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
        let (bytes, meta) = assemble_range_stream(&mut cur, 5).await.unwrap();
        assert_eq!(bytes, b"ABCDE");
        assert_eq!(meta.total_length, Some(9));
    }

    /// Once the requested window is full the assembler stops reading, even without a `complete`
    /// frame — it never buffers past `max_len`.
    #[tokio::test]
    async fn assemble_stops_once_the_window_is_full() {
        let f0 = RangeFrame {
            offset: 0,
            length: 4,
            bytes: b"WXYZ".to_vec(),
            complete: false,
            total_length: Some(8),
            chunk_lens: Some(vec![4, 4]),
            chunk_index: Some(0),
            inclusion_proof: None,
            root: None,
        };
        let f1 = RangeFrame {
            offset: 4,
            length: 4,
            bytes: b"nope".to_vec(),
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
        let (bytes, _) = assemble_range_stream(&mut cur, 4).await.unwrap();
        assert_eq!(bytes, b"WXYZ");
    }

    #[tokio::test]
    async fn drain_trailer_is_bounded_by_cap() {
        // A "peer" that streams far more trailer than the cap: the drain must stop at the cap, never
        // buffering the whole thing (MEDIUM #179 — no unbounded read_to_end).
        let flood = vec![0u8; 1_000_000];
        let mut cur = std::io::Cursor::new(flood);
        let drained = drain_trailer_bounded(&mut cur, 64 * 1024).await;
        assert_eq!(drained, 64 * 1024, "drain must stop exactly at the cap");
        // The cursor still has bytes left (we did NOT read to end).
        assert!((cur.position() as usize) < 1_000_000);
    }

    #[tokio::test]
    async fn drain_trailer_stops_at_eof_below_cap() {
        // A well-behaved peer with a small (or empty) trailer: drain returns the actual count and
        // stops at EOF without waiting for the cap.
        let mut cur = std::io::Cursor::new(vec![0u8; 100]);
        assert_eq!(drain_trailer_bounded(&mut cur, 64 * 1024).await, 100);
        let mut empty = std::io::Cursor::new(Vec::<u8>::new());
        assert_eq!(drain_trailer_bounded(&mut empty, 64 * 1024).await, 0);
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

    /// A real (but disposable) CA-signed [`dig_nat::NodeCert`] for the pure helpers under test — they
    /// never dial, so any validly-minted cert works. `NodeCert` has no public fields (only
    /// `generate_signed`/`load_or_generate`/`from_pem`), so it is minted from a BLS secret key
    /// deterministically derived from a fixed label (never a literal keypair — keeps CodeQL's
    /// hard-coded-crypto-value scan happy, matches dig-tls's own test convention).
    fn fake_node_cert() -> std::sync::Arc<dig_nat::NodeCert> {
        use sha2::{Digest, Sha256};
        let seed: [u8; 32] = Sha256::digest(b"dig-download/tests/fake-node-cert").into();
        let bls_sk = dig_tls::bls::SecretKey::from_seed(&seed);
        std::sync::Arc::new(dig_nat::NodeCert::generate_signed(&bls_sk).unwrap())
    }
}
