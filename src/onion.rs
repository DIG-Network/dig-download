//! Onion mode — carrying a transfer back through the same layered hops that carried the ask (#30).
//!
//! In **direct mode** the requestor learns a holder's dial address and fetches from it itself. In
//! **onion mode** the bytes travel the other way: back up the hop path, each hop handing them to its
//! predecessor, so the requestor never dials the holder and the holder never sees the requestor.
//!
//! This module owns exactly two things, and deliberately not a third:
//!
//! 1. **[`decide_relay_stream`] — the admission decision a hop makes about carrying BYTES.** Relaying
//!    a question and relaying a transfer are different costs, so they are different decisions.
//! 2. **[`OnionRangeTransport`] — the seam that plugs a hop-carried transfer into this crate's
//!    existing verified-assembly engine**, unchanged, so onion-delivered bytes face exactly the same
//!    per-range and whole-resource checks as directly-fetched ones.
//!
//! It does **not** implement onion cryptography, circuit construction, cells, or relay selection.
//! Those belong to `dig-onion` and are reached through the [`OnionChannel`] seam
//! ([see below](#why-a-seam-instead-of-a-dependency)).
//!
//! # How this composes with NC-1 / §5.4 (the question #30 says to settle first)
//!
//! NC-1 requires a **directed message** to be end-to-end sealed to its recipient, so an intermediary
//! that terminates transport sees ciphertext only. Streaming content *through* intermediaries does not
//! weaken that, because the two things an intermediary could learn are separately sealed:
//!
//! - **The request and response payloads** are onion-layered: each hop can peel exactly its own
//!   layer, which tells it where to pass the cell next and nothing about the payload beneath. The
//!   innermost layer is sealed to the exit, and the exit is the only hop that learns *which content*
//!   is being fetched (`dig-onion` SPEC §6.2 calls this the disclosure radius — it is a property of
//!   onion routing, not a gap in it).
//! - **The content bytes** are `.dig` capsule ciphertext independently of any transport. A relay that
//!   peeled every onion layer it is entitled to peel still holds store ciphertext it has no
//!   retrieval key for.
//!
//! So the answer is that onion mode **satisfies** NC-1 by construction rather than trading against
//! it: no hop is a recipient, and no hop holds plaintext. What must not be inferred from that is
//! *trust*: an intermediary cannot READ the bytes, and it also cannot be prevented from CORRUPTING,
//! withholding, or truncating them. That is why every byte arriving through a hop enters the ordinary
//! verification path (NC-12) — accepted because it verifies against the chain-anchored merkle root,
//! never because of who relayed it. A hostile hop can deny a transfer; it cannot forge one.
//!
//! Two properties the composition does **not** give, stated so nobody assumes them: onion mode hides
//! the requestor from the holder, not the *fact of a transfer* from an on-path observer (padding is
//! `dig-onion`'s concern), and it makes no safety claim about the content — verified content is not
//! safe content.
//!
//! # What bounds the bandwidth a relay spends on someone else's transfer
//!
//! `dig-sex`'s ask policy bounds a forwarded *question*: a hop budget carried in the request, a
//! fan-out, a separate relay allowance, off by default, refusing rather than forwarding when the
//! budget cannot be read. Reusing that budget for a stream would be wrong by orders of magnitude — a
//! forwarded ask costs a hop a few hundred bytes, and a forwarded `.dig` transfer costs it the whole
//! capsule, twice (in and out). So a stream draws on a **byte-denominated allowance of its own**
//! ([`StreamRelayConfig`]), and:
//!
//! - **A hop may relay asks while refusing to relay streams** ([`StreamRelayConfig::relays_asks_only`]),
//!   which is the honest configuration for a node with cheap CPU and metered bandwidth. The refusal
//!   is its own named reason ([`StreamRelayRefusal::AsksOnly`]) so it can never be reported as, or
//!   mistaken for, "nobody holds this content".
//! - **A transfer whose declared length cannot be read is refused, not carried optimistically.** An
//!   unreadable length is an unbounded byte cost in the same way an unreadable hop budget is an
//!   unbounded reach, and `dig-sex` already settled that class: refuse.
//! - **A transfer that does not fit is refused whole, never silently truncated.** A truncated relay
//!   looks to the requestor exactly like a mid-stream disconnect, so it would spend the requestor's
//!   retry budget to discover a limit the relay already knew. The requestor can then ask for smaller
//!   ranges — this engine is range-based, so a smaller window is always available.
//! - **Off by default.** Enabling relay-on-behalf-of-others is an operator decision, and this module
//!   takes `enabled` as a value rather than parsing it, so a node that already parses the recursion
//!   switch fail-closed (`dig_sex::discovery::parse_enabled`) has exactly one such parser.
//!
//! # Why a seam instead of a dependency {#why-a-seam-instead-of-a-dependency}
//!
//! `dig-onion` owns the circuits, cells, ntor handshake and privacy-aware path selection, and this
//! module must not grow a second copy of any of them. It cannot simply depend on it either: both
//! crates sit at **level 30**, and the crate hierarchy forbids a same-level edge. So the layered
//! transport arrives as an injected [`OnionChannel`], implemented above both crates (dig-node) over
//! `dig_onion::Circuit`. The same seam keeps this crate testable over an in-memory hop path with no
//! network, exactly like every other boundary here.

use std::sync::Arc;

use async_trait::async_trait;
use dig_dht::ProviderRecord;
use dig_nat::{AvailabilityItem, AvailabilityResponse, RangeRequest};

use crate::error::DownloadError;
use crate::source::{FetchedRange, RangeTransport};

/// The longest hop path this crate will carry a transfer over.
///
/// A bound is needed because path length multiplies the bandwidth every relay spends: a transfer over
/// `n` hops costs the network `n` times the content. The value is deliberately generous relative to
/// `dig-onion`'s 3-hop default — this is a refusal ceiling, not a recommendation.
pub const MAX_HOP_PATH: usize = 8;

/// Why a hop will not carry a transfer, or why a requestor will not start one.
///
/// Every variant is distinguishable from "the content was not found", because conflating a refusal to
/// carry with an absence of content teaches a requestor that content does not exist when in truth
/// nobody would relay it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StreamRelayRefusal {
    /// Onion mode is switched off on this node — as originator and as relay alike.
    #[error("onion mode is disabled on this node")]
    Disabled,
    /// This node relays asks but not streams: a deliberate, legal configuration.
    #[error("this node relays asks but not streams")]
    AsksOnly,
    /// The hop budget could not be read from the request. Refused rather than carried optimistically:
    /// a transfer whose remaining path is unknown is a transfer whose cost is unknown.
    #[error("the stream's hop budget could not be read")]
    UnreadableHopBudget,
    /// The hop budget is exhausted — this node is the end of the permitted path.
    #[error("the stream's hop budget is exhausted")]
    HopBudgetSpent,
    /// The transfer declared no length, or one that could not be read. An unbounded byte cost is
    /// refused for the same reason an unbounded reach is.
    #[error("the stream declared no readable length")]
    UnreadableLength,
    /// The transfer is larger than this node will carry for anyone, however much allowance remains.
    #[error("the stream is larger than this node will relay ({declared} > {ceiling} bytes)")]
    StreamTooLarge {
        /// The length the transfer declared.
        declared: u64,
        /// This node's per-stream ceiling.
        ceiling: u64,
    },
    /// This node's allowance for bytes carried on others' behalf is spent for now.
    #[error("the relay byte allowance is spent ({declared} needed, {available} left)")]
    RelayByteBudgetSpent {
        /// The length the transfer declared.
        declared: u64,
        /// The allowance left in the current window.
        available: u64,
    },
}

/// A hop's decision about an inbound transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRelayDecision {
    /// Carry the transfer, decrementing the hop budget and holding it to `byte_ceiling` bytes.
    Carry {
        /// The budget to carry onward, already decremented.
        hops_remaining: u8,
        /// The exact number of bytes admitted. A transfer exceeding it is a protocol violation by the
        /// peer that declared a smaller length, not a limit to discover by truncation.
        byte_ceiling: u64,
    },
    /// Do not carry it, for this reason.
    Refuse(StreamRelayRefusal),
}

/// An inbound transfer as a hop received it: what it declared about itself, nothing more.
///
/// Both fields are `Option` on purpose. They come off an untrusted wire, and "the field was
/// unreadable" is a different fact from any particular value — [`decide_relay_stream`] refuses on
/// either being absent rather than substituting a default, because every plausible default is either
/// unbounded or a silent policy the operator never chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboundStream {
    /// Hops the transfer may still travel, as carried IN the request. `None` means unreadable.
    pub hops_remaining: Option<u8>,
    /// The transfer's declared total length in bytes. `None` means unreadable.
    pub declared_len: Option<u64>,
}

/// A node's policy for carrying transfers — its own and other people's.
///
/// Constructed with `StreamRelayConfig { enabled: true, ..Default::default() }`; the default is a
/// node that carries nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamRelayConfig {
    /// Whether this node participates in onion mode at all, as originator or relay. **Off by
    /// default.** Parse the switch with `dig_sex::discovery::parse_enabled` (fail-closed) rather than
    /// adding a second parser.
    pub enabled: bool,
    /// Relay asks but refuse streams. The honest setting for a node with cheap CPU and expensive
    /// bandwidth: it stays useful to discovery without underwriting other people's transfers.
    pub relays_asks_only: bool,
    /// The largest single transfer this node will carry for someone else.
    pub max_bytes_per_stream: u64,
    /// The total bytes this node will carry on others' behalf per accounting window. The window and
    /// its refill are the caller's (it owns the clock); this module only compares.
    pub relay_bytes_per_window: u64,
}

/// 16 MiB — the default per-stream ceiling, which is one range window rather than one capsule.
///
/// A relay should be able to help without underwriting an arbitrarily large `.dig`, and a requestor
/// that needs more can ask for more windows: refusing per stream costs a requestor one extra request,
/// while admitting per capsule costs a relay the whole capsule.
pub const DEFAULT_MAX_BYTES_PER_STREAM: u64 = 16 * 1024 * 1024;

/// 256 MiB per window — the default total a node carries on others' behalf.
pub const DEFAULT_RELAY_BYTES_PER_WINDOW: u64 = 256 * 1024 * 1024;

impl Default for StreamRelayConfig {
    /// A node that carries nothing: onion mode off, and if switched on, streams refused until the
    /// operator says otherwise.
    fn default() -> Self {
        StreamRelayConfig {
            enabled: false,
            relays_asks_only: true,
            max_bytes_per_stream: DEFAULT_MAX_BYTES_PER_STREAM,
            relay_bytes_per_window: DEFAULT_RELAY_BYTES_PER_WINDOW,
        }
    }
}

/// Decide whether this hop carries an inbound transfer.
///
/// `relay_bytes_available` is what remains of this node's [`StreamRelayConfig::relay_bytes_per_window`] allowance — the
/// caller owns the window and its refill. It is a separate allowance from anything this node spends on
/// its OWN transfers, for the reason `dig-sex` records for asks: billing relayed work to the victim's
/// own budget lets one admitted request spend a stranger's allowance.
///
/// The order of the checks is part of the contract. Cheap, unconditional refusals come first, so a
/// disabled node never reveals anything about its allowances by the shape of its refusal.
#[must_use]
pub fn decide_relay_stream(
    config: &StreamRelayConfig,
    inbound: &InboundStream,
    relay_bytes_available: u64,
) -> StreamRelayDecision {
    if !config.enabled {
        return StreamRelayDecision::Refuse(StreamRelayRefusal::Disabled);
    }
    if config.relays_asks_only {
        return StreamRelayDecision::Refuse(StreamRelayRefusal::AsksOnly);
    }
    let Some(hops_remaining) = inbound.hops_remaining else {
        return StreamRelayDecision::Refuse(StreamRelayRefusal::UnreadableHopBudget);
    };
    if hops_remaining == 0 {
        return StreamRelayDecision::Refuse(StreamRelayRefusal::HopBudgetSpent);
    }
    let Some(declared) = inbound.declared_len else {
        return StreamRelayDecision::Refuse(StreamRelayRefusal::UnreadableLength);
    };
    if declared > config.max_bytes_per_stream {
        return StreamRelayDecision::Refuse(StreamRelayRefusal::StreamTooLarge {
            declared,
            ceiling: config.max_bytes_per_stream,
        });
    }
    if declared > relay_bytes_available {
        return StreamRelayDecision::Refuse(StreamRelayRefusal::RelayByteBudgetSpent {
            declared,
            available: relay_bytes_available,
        });
    }
    StreamRelayDecision::Carry {
        hops_remaining: hops_remaining - 1,
        byte_ceiling: declared,
    }
}

/// Why a hop path is not usable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HopPathError {
    /// An empty path. Onion mode with no hops is direct mode wearing onion mode's name — the
    /// requestor would dial the holder itself while believing it had not, which is worse than a
    /// refusal because the privacy loss is silent.
    #[error("an onion hop path must contain at least one hop")]
    Empty,
    /// The same peer appears more than once. One peer occupying two positions is one hop presenting
    /// itself as two, which inflates the apparent path length while learning both ends of it.
    #[error("hop {0} appears more than once in the path")]
    DuplicateHop(String),
    /// Longer than [`MAX_HOP_PATH`].
    #[error("an onion hop path may not exceed {MAX_HOP_PATH} hops (got {0})")]
    TooLong(usize),
}

impl From<HopPathError> for DownloadError {
    fn from(e: HopPathError) -> Self {
        DownloadError::state(e)
    }
}

/// An ordered, validated onion hop path: entry hop first, exit hop last.
///
/// Validation is in the constructor so an invalid path cannot exist. The peers are `peer_id` strings
/// (64-hex), matching the identity every other seam in this crate names a peer by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopPath {
    hops: Vec<String>,
}

impl HopPath {
    /// Validate an ordered hop list into a path.
    ///
    /// # Errors
    /// [`HopPathError`] when the path is empty, longer than [`MAX_HOP_PATH`], or names a peer twice.
    pub fn try_new(hops: Vec<String>) -> Result<Self, HopPathError> {
        if hops.is_empty() {
            return Err(HopPathError::Empty);
        }
        if hops.len() > MAX_HOP_PATH {
            return Err(HopPathError::TooLong(hops.len()));
        }
        for (index, hop) in hops.iter().enumerate() {
            if hops[..index].contains(hop) {
                return Err(HopPathError::DuplicateHop(hop.clone()));
            }
        }
        Ok(HopPath { hops })
    }

    /// The hops in order, entry first.
    #[must_use]
    pub fn hops(&self) -> &[String] {
        &self.hops
    }

    /// How many hops the transfer travels — and therefore the multiple of the content size the
    /// network as a whole pays for it.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hops.len()
    }

    /// Whether the path is empty. Always `false`: [`try_new`](Self::try_new) refuses an empty path.
    /// Present because clippy requires it beside [`len`](Self::len).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// The layered transport an onion transfer rides — the seam over `dig-onion`'s circuits.
///
/// An implementation carries the request up the path and the answer back down it, peeling and wrapping
/// one layer per hop. It owes the caller **nothing about the bytes' truthfulness**: the answer is
/// verified by this crate's ordinary integrity path, so an implementation must never filter, repair,
/// or vouch for what a hop returned.
#[async_trait]
pub trait OnionChannel: Send + Sync {
    /// Carry a `dig.getAvailability` ask to `provider` along `path` and bring the answer back.
    ///
    /// # Errors
    /// A recoverable [`DownloadError::Transport`] when a hop drops, refuses, or times out — the
    /// caller treats it exactly as it treats a direct transport failure.
    async fn ask_availability_through(
        &self,
        path: &HopPath,
        provider: &ProviderRecord,
        items: Vec<AvailabilityItem>,
    ) -> Result<AvailabilityResponse, DownloadError>;

    /// Carry a `dig.fetchRange` request to `provider` along `path` and stream the range back down it.
    ///
    /// # Errors
    /// A recoverable [`DownloadError::Transport`] when a hop drops the transfer mid-stream. A partial
    /// transfer is a failure here, never a short success: the requestor's resume machinery re-requests
    /// the missing window, and it can only do that if the failure is reported as one.
    async fn fetch_range_through(
        &self,
        path: &HopPath,
        provider: &ProviderRecord,
        req: &RangeRequest,
    ) -> Result<FetchedRange, DownloadError>;
}

/// A [`RangeTransport`] that carries every request through a fixed onion [`HopPath`].
///
/// This is the whole of onion mode from the download engine's point of view. Swapping it in changes
/// how bytes arrive and nothing about how they are trusted: the orchestrator verifies each range
/// against the resource commitment and the whole assembly against the chain-anchored root exactly as
/// it does for a direct fetch, so a hostile hop can cost a transfer a retry and never a false success.
pub struct OnionRangeTransport {
    channel: Arc<dyn OnionChannel>,
    path: HopPath,
    config: StreamRelayConfig,
}

impl OnionRangeTransport {
    /// Build the transport over an injected channel, hop path, and policy.
    #[must_use]
    pub fn new(channel: Arc<dyn OnionChannel>, path: HopPath, config: StreamRelayConfig) -> Self {
        OnionRangeTransport {
            channel,
            path,
            config,
        }
    }

    /// The path every request on this transport travels.
    #[must_use]
    pub fn path(&self) -> &HopPath {
        &self.path
    }

    /// Refuse to originate anything while onion mode is off, so a misconfigured node fails closed
    /// rather than quietly falling back to a direct dial that would expose the requestor it was
    /// chosen to hide.
    fn require_enabled(&self) -> Result<(), DownloadError> {
        if self.config.enabled {
            Ok(())
        } else {
            Err(DownloadError::state(StreamRelayRefusal::Disabled))
        }
    }
}

#[async_trait]
impl RangeTransport for OnionRangeTransport {
    async fn query_availability(
        &self,
        provider: &ProviderRecord,
        items: Vec<AvailabilityItem>,
    ) -> Result<AvailabilityResponse, DownloadError> {
        self.require_enabled()?;
        self.channel
            .ask_availability_through(&self.path, provider, items)
            .await
    }

    async fn fetch_range(
        &self,
        provider: &ProviderRecord,
        req: &RangeRequest,
    ) -> Result<FetchedRange, DownloadError> {
        self.require_enabled()?;
        // Hold an ORIGINATED request to the same per-stream ceiling a hop would apply to it. The
        // asymmetry is where amplification lives: a requestor free to ask for a window every hop on
        // the path is bound to refuse spends the network `n` transfers to deliver nothing, and the
        // requestor is the one node that could have known in advance.
        if req.length > self.config.max_bytes_per_stream {
            return Err(DownloadError::state(StreamRelayRefusal::StreamTooLarge {
                declared: req.length,
                ceiling: self.config.max_bytes_per_stream,
            }));
        }
        self.channel
            .fetch_range_through(&self.path, provider, req)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relaying() -> StreamRelayConfig {
        StreamRelayConfig {
            enabled: true,
            relays_asks_only: false,
            ..Default::default()
        }
    }

    fn inbound(hops: u8, len: u64) -> InboundStream {
        InboundStream {
            hops_remaining: Some(hops),
            declared_len: Some(len),
        }
    }

    #[test]
    fn a_node_carries_nothing_by_default() {
        let config = StreamRelayConfig::default();
        assert!(
            !config.enabled,
            "onion mode is off until an operator says so"
        );
        assert!(
            config.relays_asks_only,
            "and even switched on, streams are refused until an operator opts in"
        );
        assert_eq!(
            decide_relay_stream(&config, &inbound(2, 1024), u64::MAX),
            StreamRelayDecision::Refuse(StreamRelayRefusal::Disabled)
        );
    }

    #[test]
    fn a_hop_may_relay_asks_while_refusing_streams() {
        // The distinct configuration #30 asks for: useful to discovery, not underwriting transfers.
        let asks_only = StreamRelayConfig {
            enabled: true,
            relays_asks_only: true,
            ..Default::default()
        };
        assert_eq!(
            decide_relay_stream(&asks_only, &inbound(2, 1024), u64::MAX),
            StreamRelayDecision::Refuse(StreamRelayRefusal::AsksOnly),
            "refusing to carry bytes is its own answer, distinguishable from being switched off"
        );
        // The SAME node, same budget, carries the stream once the operator opts in — so the refusal
        // above is attributable to this switch and not to some other bound in the fixture.
        assert_eq!(
            decide_relay_stream(&relaying(), &inbound(2, 1024), u64::MAX),
            StreamRelayDecision::Carry {
                hops_remaining: 1,
                byte_ceiling: 1024
            }
        );
    }

    #[test]
    fn an_unreadable_declared_length_is_refused_not_carried_optimistically() {
        // The bound that matters most: a length nobody can read is an unbounded byte cost. The
        // fixture keeps EVERY other input admissible — enabled, streams allowed, hops left, an
        // unlimited allowance — so only the unreadable length can produce a refusal.
        let unreadable = InboundStream {
            hops_remaining: Some(2),
            declared_len: None,
        };
        assert_eq!(
            decide_relay_stream(&relaying(), &unreadable, u64::MAX),
            StreamRelayDecision::Refuse(StreamRelayRefusal::UnreadableLength)
        );
    }

    #[test]
    fn an_unreadable_hop_budget_is_refused() {
        let unreadable = InboundStream {
            hops_remaining: None,
            declared_len: Some(1024),
        };
        assert_eq!(
            decide_relay_stream(&relaying(), &unreadable, u64::MAX),
            StreamRelayDecision::Refuse(StreamRelayRefusal::UnreadableHopBudget)
        );
    }

    #[test]
    fn an_exhausted_hop_budget_ends_the_path_here() {
        assert_eq!(
            decide_relay_stream(&relaying(), &inbound(0, 1024), u64::MAX),
            StreamRelayDecision::Refuse(StreamRelayRefusal::HopBudgetSpent)
        );
    }

    #[test]
    fn the_per_stream_ceiling_is_pinned_from_both_sides() {
        // A bound tested only from below can only confirm itself. At the ceiling it must carry; one
        // byte over it must refuse.
        let config = StreamRelayConfig {
            max_bytes_per_stream: 1_000,
            ..relaying()
        };
        assert_eq!(
            decide_relay_stream(&config, &inbound(2, 1_000), u64::MAX),
            StreamRelayDecision::Carry {
                hops_remaining: 1,
                byte_ceiling: 1_000
            },
            "at the ceiling exactly, the transfer is admitted"
        );
        assert_eq!(
            decide_relay_stream(&config, &inbound(2, 1_001), u64::MAX),
            StreamRelayDecision::Refuse(StreamRelayRefusal::StreamTooLarge {
                declared: 1_001,
                ceiling: 1_000
            }),
            "one byte over it, refused whole rather than truncated"
        );
    }

    #[test]
    fn the_window_allowance_is_pinned_from_both_sides() {
        let config = StreamRelayConfig {
            max_bytes_per_stream: 10_000,
            ..relaying()
        };
        assert_eq!(
            decide_relay_stream(&config, &inbound(2, 500), 500),
            StreamRelayDecision::Carry {
                hops_remaining: 1,
                byte_ceiling: 500
            },
            "a transfer that exactly exhausts the remaining allowance still fits in it"
        );
        assert_eq!(
            decide_relay_stream(&config, &inbound(2, 501), 500),
            StreamRelayDecision::Refuse(StreamRelayRefusal::RelayByteBudgetSpent {
                declared: 501,
                available: 500
            }),
            "one byte past it is refused — and named as an allowance, not as a size limit"
        );
    }

    #[test]
    fn a_refusal_is_never_an_absence_of_content() {
        // Every refusal carries its own reason. A caller that collapsed them into "not found" would
        // teach a requestor that content does not exist when in truth nobody would carry it.
        let reasons = [
            decide_relay_stream(&StreamRelayConfig::default(), &inbound(2, 1), 0),
            decide_relay_stream(&relaying(), &inbound(0, 1), 0),
            decide_relay_stream(
                &relaying(),
                &InboundStream {
                    hops_remaining: Some(2),
                    declared_len: None,
                },
                0,
            ),
        ];
        for reason in reasons {
            let StreamRelayDecision::Refuse(refusal) = reason else {
                panic!("expected a refusal, got {reason:?}");
            };
            assert!(
                !refusal.to_string().is_empty(),
                "a refusal states why this node would not carry the transfer"
            );
        }
    }

    #[test]
    fn an_empty_hop_path_is_refused_because_the_privacy_loss_would_be_silent() {
        assert_eq!(HopPath::try_new(Vec::new()), Err(HopPathError::Empty));
    }

    #[test]
    fn a_peer_may_not_occupy_two_positions_on_one_path() {
        // A duplicate hop is one peer presenting itself as two: the path looks longer than it is
        // while that peer sees both of its own positions.
        let repeated = HopPath::try_new(vec!["a".into(), "b".into(), "a".into()]);
        assert_eq!(repeated, Err(HopPathError::DuplicateHop("a".into())));
        // A distinct path of the same length is accepted, so the rejection above is attributable to
        // the duplicate and not to the length.
        let distinct = HopPath::try_new(vec!["a".into(), "b".into(), "c".into()])
            .expect("three distinct hops are a valid path");
        assert_eq!(distinct.len(), 3);
        assert_eq!(distinct.hops(), ["a", "b", "c"]);
    }

    #[test]
    fn the_hop_path_length_bound_is_pinned_from_both_sides() {
        let at_bound: Vec<String> = (0..MAX_HOP_PATH).map(|i| i.to_string()).collect();
        assert!(HopPath::try_new(at_bound).is_ok(), "MAX_HOP_PATH hops fit");
        let over: Vec<String> = (0..=MAX_HOP_PATH).map(|i| i.to_string()).collect();
        assert_eq!(
            HopPath::try_new(over),
            Err(HopPathError::TooLong(MAX_HOP_PATH + 1))
        );
    }
}
