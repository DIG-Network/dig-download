//! [`SourceSelector`] — the **selection seam**: dig-download delegates "which of these candidate
//! peers should serve this content, and in what order?" to an injected brain, and reports the real
//! measured outcome of every range fetch back to it.
//!
//! # Why a seam, not a built-in brain (the anti-second-brain rule)
//!
//! dig-download is the **executor**: it fans byte ranges across peers, verifies each independently,
//! retries the bad ones, and reassembles — as fast as the peers allow. It deliberately owns **no
//! throughput model / speed ranking / cross-transfer learning**. That intelligence lives in ONE place
//! (`dig-peer-selector`, the self-tuning decision layer), wired in by dig-node so a single learning
//! loop informs every transfer. If dig-download also ranked peers it would be a *second, competing*
//! brain — divergent, un-tunable, and impossible to keep coherent with the real selector.
//!
//! So dig-download exposes this trait and calls it for ordering; the selector decides **who + in what
//! order**, dig-download **executes + reports outcomes back**. With no selector injected, the
//! [`NullSelector`] (a fair round-robin) keeps the crate fully usable standalone.
//!
//! # Layering (why the DTOs live here, not in dig-peer-selector)
//!
//! dig-download and dig-peer-selector are both level-30 crates, so dig-download may **not** depend on
//! dig-peer-selector (reference-DOWN only — no same-level edge). The seam is therefore defined here in
//! dig-download with its OWN minimal DTOs; dig-peer-selector (or dig-node's adapter) *implements*
//! [`SourceSelector`] against them. dig-node's richer notions — a peer's discovery `Provenance`, its
//! address book — never enter these types; a candidate carries only an opaque [`CandidateRef::tag`]
//! the selector may round-trip.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// One candidate peer the selector may choose to fetch from: its `peer_id` (64-hex), its dialable
/// address strings, and an **opaque** selector-defined tag.
///
/// The `tag` is Provenance-agnostic on purpose: dig-download never interprets it, it only round-trips
/// whatever a caller attaches (dig-node stamps a small discovery-source hint here). Keeping it opaque
/// keeps dig-node's `Provenance` out of dig-download entirely (layering).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRef {
    /// The candidate provider's `peer_id` as lowercase 64-hex.
    pub peer_id: String,
    /// The candidate's dialable address strings (`host:port`), best-first, or empty for a
    /// relay-only-reachable peer.
    pub addrs: Vec<String>,
    /// An opaque selector-defined tag dig-download round-trips but never inspects (dig-node stamps a
    /// discovery-source hint). `None` when unset.
    pub tag: Option<u64>,
}

impl CandidateRef {
    /// A candidate with no tag (the value dig-download itself constructs — it has no Provenance to
    /// stamp).
    pub fn new(peer_id: impl Into<String>, addrs: Vec<String>) -> Self {
        CandidateRef {
            peer_id: peer_id.into(),
            addrs,
            tag: None,
        }
    }
}

/// The question posed to the selector on each scheduling pass: given these live candidates and the
/// download's current state, which peers should serve the still-needed ranges, and in what order?
#[derive(Debug, Clone)]
pub struct SelectRequest<'a> {
    /// The content's stable key (64-hex of its DHT content key) — an opaque identity the selector may
    /// use to scope per-content learning; dig-download does not require the selector to use it.
    pub content_key: &'a str,
    /// The candidate peers currently eligible to be scheduled (already filtered to live, non-backed-off
    /// holders — liveness/backoff is dig-download's mechanical debounce, NOT the selector's job).
    pub candidates: &'a [CandidateRef],
    /// How many ranges still need fetching (pending, not yet done/in-flight).
    pub ranges_needed: usize,
    /// How many range fetches are currently in flight across all peers (the scheduler's live load).
    pub inflight: usize,
}

/// The selector's answer: the candidates to use, in preference order (best first), plus an OPTIONAL
/// explicit per-range assignment.
///
/// The scheduler assigns each pending range to the first peer in [`ordered`](Self::ordered) that is
/// under its per-source in-flight cap. An entry in [`assignments`](Self::assignments) pins a specific
/// range to a specific peer when present; ranges without an assignment fall back to `ordered`.
#[derive(Debug, Clone, Default)]
pub struct SelectPlan {
    /// Candidate `peer_id`s in preference order (best first). A subset of the request's candidates —
    /// the selector may drop candidates it wants to avoid this pass.
    pub ordered: Vec<String>,
    /// Optional explicit `(range_index, peer_id)` pins. Empty means "assign purely by `ordered`".
    pub assignments: Vec<(usize, String)>,
}

impl SelectPlan {
    /// A plan that simply uses the given peers in the given order (no explicit per-range pins).
    pub fn ordered(peers: Vec<String>) -> Self {
        SelectPlan {
            ordered: peers,
            assignments: Vec::new(),
        }
    }
}

/// How a single range fetch turned out — fed back to the selector so its learning loop sees the real,
/// measured result of every transfer (this is dig-download's ONLY reporting channel; it computes no
/// ranking of its own from these numbers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeOutcome {
    /// The `peer_id` (64-hex) the range was fetched from.
    pub peer_id: String,
    /// Bytes actually transferred (0 for a failure/timeout before any verified bytes landed).
    pub bytes: u64,
    /// Wall-clock elapsed for the fetch attempt.
    pub elapsed: Duration,
    /// The result of the attempt.
    pub result: RangeResult,
}

/// The three terminal states of one range fetch attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeResult {
    /// The range was fetched and verified successfully.
    Ok,
    /// The fetch failed (transport error) or the bytes failed verification.
    Failed,
    /// The fetch exceeded the configured per-range timeout.
    TimedOut,
}

/// The selection brain dig-download delegates peer choice to. Implemented by dig-peer-selector (wired
/// in by dig-node); [`NullSelector`] is the standalone default.
///
/// Both methods take `&self` (interior mutability if the impl learns) so one selector instance can
/// inform many concurrent downloads.
pub trait SourceSelector: Send + Sync {
    /// Choose which candidates to fetch from, and in what order, for this scheduling pass.
    fn select(&self, req: &SelectRequest) -> SelectPlan;

    /// Report the measured outcome of one range fetch, feeding the selector's learning loop.
    fn record(&self, outcome: &RangeOutcome);
}

/// The default [`SourceSelector`] when none is injected: a fair **round-robin** over the candidates,
/// rotating the starting offset each pass so no single peer is always tried first. It keeps NO speed
/// model — it is deliberately un-intelligent, so dig-download standalone has no hidden ranking brain.
#[derive(Debug, Default)]
pub struct NullSelector {
    cursor: AtomicUsize,
}

impl NullSelector {
    /// A fresh round-robin selector.
    pub fn new() -> Self {
        NullSelector::default()
    }
}

impl SourceSelector for NullSelector {
    fn select(&self, req: &SelectRequest) -> SelectPlan {
        let n = req.candidates.len();
        if n == 0 {
            return SelectPlan::default();
        }
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % n;
        let ordered = req
            .candidates
            .iter()
            .cycle()
            .skip(start)
            .take(n)
            .map(|c| c.peer_id.clone())
            .collect();
        SelectPlan::ordered(ordered)
    }

    /// The null selector learns nothing — outcomes are intentionally ignored.
    fn record(&self, _outcome: &RangeOutcome) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidates(n: usize) -> Vec<CandidateRef> {
        (0..n)
            .map(|i| CandidateRef::new(format!("peer{i}"), vec![format!("10.0.0.{i}:9444")]))
            .collect()
    }

    fn request(cands: &[CandidateRef]) -> SelectRequest<'_> {
        SelectRequest {
            content_key: "test-content-key",
            candidates: cands,
            ranges_needed: 4,
            inflight: 0,
        }
    }

    #[test]
    fn null_selector_returns_all_candidates_in_a_rotating_order() {
        let sel = NullSelector::new();
        let cands = candidates(3);
        let p0 = sel.select(&request(&cands));
        let p1 = sel.select(&request(&cands));
        // Every pass returns ALL candidates (a permutation), and the starting peer rotates.
        assert_eq!(p0.ordered.len(), 3);
        assert_eq!(p1.ordered.len(), 3);
        assert_ne!(p0.ordered[0], p1.ordered[0], "start rotates each pass");
        let mut sorted = p0.ordered.clone();
        sorted.sort();
        assert_eq!(sorted, vec!["peer0", "peer1", "peer2"]);
    }

    #[test]
    fn null_selector_empty_candidates_is_empty_plan() {
        let sel = NullSelector::new();
        let cands = candidates(0);
        let plan = sel.select(&request(&cands));
        assert!(plan.ordered.is_empty());
        assert!(plan.assignments.is_empty());
    }

    #[test]
    fn null_selector_record_is_a_noop() {
        let sel = NullSelector::new();
        // Recording must not panic and must not alter subsequent selection.
        sel.record(&RangeOutcome {
            peer_id: "peer0".into(),
            bytes: 1024,
            elapsed: Duration::from_millis(5),
            result: RangeResult::Ok,
        });
        let cands = candidates(2);
        assert_eq!(sel.select(&request(&cands)).ordered.len(), 2);
    }

    #[test]
    fn select_plan_ordered_helper_has_no_assignments() {
        let plan = SelectPlan::ordered(vec!["a".into(), "b".into()]);
        assert_eq!(plan.ordered, vec!["a", "b"]);
        assert!(plan.assignments.is_empty());
    }
}
