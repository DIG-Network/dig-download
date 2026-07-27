//! Per-range + whole-resource integrity — L7 §9 "per-range integrity".
//!
//! A fetched range must be verifiable so a single peer cannot forge bytes and a multi-source mix
//! always reassembles correctly. Two checks, at two moments:
//!
//! 1. **Per range, immediately** ([`Verifier::verify_range`]) — the returned bytes cover whole
//!    chunk(s) whose lengths match the commitment's `chunk_lens`, and the range's declared generation
//!    `root` matches the one being downloaded. This is the cheap check that catches a truncated /
//!    mis-sized / wrong-generation source the moment its range arrives, so the orchestrator can
//!    discard it and re-fetch from another provider.
//! 2. **Whole resource, at completion** ([`Verifier::verify_resource`]) — once every range is
//!    assembled, `resource_leaf = SHA-256(concatenated chunk ciphertexts)` (L7 §9 / the digstore
//!    merkle-proofs read path) must be the leaf committed under the **chain-anchored generation
//!    `root`**. Whichever mix of peers served the ranges, they all verify against the *same* on-chain
//!    root — so mixing sources never weakens integrity.
//!
//! ## The commitment is established once, then trusted
//!
//! The first frame of the first successfully-fetched range carries `total_length` + `chunk_lens` +
//! `root` (+ `inclusion_proof`). That establishes the [`ResourceCommitment`]; every subsequent range
//! is checked against it (a peer that reports a *different* `chunk_lens` / `root` is serving a
//! different generation and is rejected). The on-chain binding — that `resource_leaf` really is
//! committed under `root` — is delegated to an injected [`ProofVerifier`] so this crate does not
//! re-implement the digstore merkle-proof byte format; dig-node supplies the real one via
//! [`MerkleVerifier::with_proof_verifier`] (see the implementers' note in the crate docs). There is
//! no fail-open default constructor: the only structural-only path
//! ([`MerkleVerifier::insecure_structural_only`]) is explicitly named and `#[doc(hidden)]`, so a
//! production caller cannot accidentally build a verifier that skips the on-chain binding.

use std::collections::BTreeMap;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::error::VerifyError;
use crate::plan::ChunkLayout;

/// Streaming SHA-256 of a resource's ciphertext fed range-by-range in ARBITRARY order, so the
/// whole-resource `resource_leaf` can be computed WITHOUT retaining every range and then
/// concatenating a second full-length copy (the old path held ~2N bytes for an N-byte resource —
/// MEDIUM #179).
///
/// Ranges are hashed strictly in ascending offset order. A range whose offset is not yet the
/// next-needed contiguous offset is buffered in a small out-of-order window and drained the moment
/// the gap before it fills; a range at (or before, as a verified idempotent re-feed of the exact
/// same bytes) the next offset is hashed immediately. Because the orchestrator feeds only verified,
/// chunk-aligned, non-overlapping ranges that tile the resource exactly, the buffer holds at most the
/// ranges fetched out of order and is emptied as the contiguous frontier advances.
#[derive(Debug, Default)]
pub struct ResourceHasher {
    hasher: Sha256,
    /// The next contiguous byte offset still to be hashed.
    next_offset: u64,
    /// Ranges received ahead of `next_offset`, keyed by their offset, awaiting the gap to fill.
    pending: BTreeMap<u64, Vec<u8>>,
}

impl ResourceHasher {
    /// A fresh hasher positioned at offset 0.
    pub fn new() -> Self {
        ResourceHasher::default()
    }

    /// Feed one verified range's `bytes` at absolute `offset`. Hashes it (and any now-contiguous
    /// buffered ranges) immediately if `offset` is the contiguous frontier, else buffers it. A range
    /// strictly before the frontier (already hashed) is ignored — feeding is idempotent for a range
    /// that was hashed and then re-delivered, which cannot happen for distinct ranges but keeps the
    /// contract robust.
    pub fn feed(&mut self, offset: u64, bytes: Vec<u8>) {
        if offset < self.next_offset {
            return; // already consumed
        }
        self.pending.insert(offset, bytes);
        while let Some(chunk) = self.pending.remove(&self.next_offset) {
            self.hasher.update(&chunk);
            self.next_offset = self.next_offset.saturating_add(chunk.len() as u64);
        }
    }

    /// The contiguous byte length hashed so far (the frontier offset).
    pub fn hashed_len(&self) -> u64 {
        self.next_offset
    }

    /// Whether any out-of-order ranges are still buffered (a gap remains before the frontier).
    pub fn has_gap(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Finalize into the `resource_leaf` digest. Valid only once every range has been fed contiguously
    /// (`has_gap()` is false); a caller checks `hashed_len() == total_length` for completeness.
    pub fn finalize(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}

/// The default ceiling on a peer-DECLARED resource `total_length` — 512 MiB, the resource-side
/// counterpart of [`DEFAULT_MAX_MODULE_SIZE`](crate::module::DEFAULT_MAX_MODULE_SIZE).
///
/// # It is a HOST-MEMORY bound, not a statement about layout capability
///
/// Worth separating, because the two were once read as one number and the reading was wrong in a way
/// that invited "fixing" this constant. This bounds how large a resource this host is willing to size a
/// plan and a range buffer for. It says nothing about how large a resource the FRAMING can describe —
/// that is a wire property, bounded by how many `chunk_lens` entries a stream can carry
/// (dig-nat's `MAX_CHUNK_LENS_PER_FRAME`, paged to `MAX_RESOURCE_CHUNK_COUNT`), and it is owned by
/// dig-nat rather than by this crate.
///
/// The two limits therefore move for different reasons and must not be reconciled by lowering this one.
/// While the layout ceiling was one frame's worth of entries the framing was the tighter of the two, so
/// a resource inside this bound could still be unreadable; the paged prologue lifts the layout ceiling
/// far above 512 MiB, so the constraint that binds is once again this one — host memory — which is
/// exactly what it was always for. Lowering it would ALSO be a real break: it is the `pub const`
/// default of a public config field, so any deployment relying on it would silently start refusing
/// resources it reads today.
///
/// The first frame's declared length sizes everything downstream of it (the plan, and the assembler's
/// per-range buffer), and it arrives from a peer that has proven nothing yet, so it MUST be bounded
/// before it is believed. Like the module bound, it is deliberately sized to what a modest host can
/// actually hold rather than to the largest conceivable resource: a ceiling above real host memory
/// bounds nothing. A deployment that genuinely reads larger resources raises
/// [`DownloadConfig::max_resource_size`](crate::DownloadConfig::max_resource_size) explicitly, having
/// sized the host for it.
pub const DEFAULT_MAX_RESOURCE_SIZE: u64 = 512 * 1024 * 1024;

/// The trusted per-resource metadata a download verifies every range against: the chunk boundaries,
/// the total length, the chain-anchored generation `root`, and (for a resource, not a capsule) the
/// whole-resource `inclusion_proof`.
///
/// Established from the first frame of the first fetched range (or an availability answer + the first
/// frame). Immutable for the life of the download: a range whose first-frame metadata disagrees with
/// this commitment is rejected as a different/forged generation.
///
/// # Adoption is NOT verification
///
/// Every gate available when a layout is adopted — the root match against the caller's content id, and the
/// `chunk_lens`-sums-to-`total_length` consistency check — is satisfiable by a holder that lies consistently,
/// because both compare fields the SAME untrusted holder supplied. Only [`Verifier::verify_resource_leaf`]
/// binds the layout to the chain, and it cannot run until the whole resource has been fetched against that
/// layout. So a commitment is a HYPOTHESIS about the resource's shape, and a holder positioned first in the
/// provider order can therefore deny a read by declaring a short but self-consistent layout for the correct
/// root (#1670, OPEN).
///
/// That denial is not fixable from here. Attributing the later refutation to the holder that supplied the
/// layout requires distinguishing "the shape was wrong" from "the bytes were wrong", and nothing in the
/// system can: per-range verification is length and alignment only, with no per-chunk hash. Three successive
/// attempts to stand a vote over peer DECLARATIONS in for that missing evidence each produced a cheaper
/// denial than the one they replaced, because those declarations are optional wire fields that cost an
/// attacker a keypair to forge and that honest holders legitimately omit. #1670 is re-scoped onto per-chunk
/// attribution, which is the only thing that can name a bad holder.
///
/// `#[non_exhaustive]`: the adoption path is expected to gain provenance once that evidence exists. Build one
/// with [`from_first_frame`](Self::from_first_frame) or
/// [`from_first_frame_bounded`](Self::from_first_frame_bounded).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResourceCommitment {
    /// The chunk boundaries (`chunk_lens` → offsets).
    pub layout: ChunkLayout,
    /// The full resource ciphertext length.
    pub total_length: u64,
    /// The chain-anchored generation root (64-hex) every range verifies against. `None` only for a
    /// self-verifying capsule fetch that carries no per-resource root.
    pub root: Option<String>,
    /// The whole-resource merkle inclusion proof (base64), relayed verbatim from the first frame;
    /// `None` for a `capsule: true` fetch (the capsule self-verifies on install).
    pub inclusion_proof: Option<String>,
}

impl ResourceCommitment {
    /// Build a commitment from first-frame verification metadata, bounded by
    /// [`DEFAULT_MAX_RESOURCE_SIZE`].
    ///
    /// Equivalent to [`from_first_frame_bounded`](Self::from_first_frame_bounded) with the default
    /// ceiling — see it for what the bound defends against.
    pub fn from_first_frame(
        total_length: u64,
        chunk_lens: Vec<u64>,
        root: Option<String>,
        inclusion_proof: Option<String>,
    ) -> Result<Self, VerifyError> {
        Self::from_first_frame_bounded(
            total_length,
            chunk_lens,
            root,
            inclusion_proof,
            DEFAULT_MAX_RESOURCE_SIZE,
        )
    }

    /// Build a commitment from first-frame verification metadata, refusing a declared
    /// `total_length` above `max_resource_size`.
    ///
    /// Validates that `chunk_lens` sums to `total_length` with CHECKED arithmetic (a peer reporting
    /// inconsistent metadata is rejected up front) — and, BEFORE that, that the declared length is
    /// within the ceiling.
    ///
    /// The ceiling is load-bearing, not hygiene. `total_length` and the individual `chunk_lens` come
    /// from the first frame of a peer that has not proven anything yet, and they SIZE the download: a
    /// single chunk becomes at least one whole [`Range`](crate::plan::Range) regardless of the window,
    /// and the range assembler then buffers up to that length. So an unbounded declared length is a
    /// one-frame memory-exhaustion primitive: a peer answering the metadata probe with
    /// `total_length: 2^40, chunk_lens: [2^40]` makes the client try to buffer a terabyte. Bounding it
    /// here — before any layout or plan exists — is what keeps that a rejection instead of an
    /// allocation. (The range assembler's own reservation is additionally FALLIBLE, so even a
    /// within-ceiling length that this host cannot hold is a recoverable error rather than an
    /// uncatchable abort.)
    pub fn from_first_frame_bounded(
        total_length: u64,
        chunk_lens: Vec<u64>,
        root: Option<String>,
        inclusion_proof: Option<String>,
        max_resource_size: u64,
    ) -> Result<Self, VerifyError> {
        if total_length > max_resource_size {
            return Err(VerifyError::Metadata(format!(
                "declared total_length {total_length} exceeds the maximum {max_resource_size}"
            )));
        }
        // The lengths came off the wire, so the layout is built with the CHECKED, bounded, fallible
        // constructor: a saturating sum would let `[1, u64::MAX]` match a declared `u64::MAX` total and
        // pass the consistency check below as if it were a real resource (#1608).
        let layout = ChunkLayout::try_new(chunk_lens)?;
        if layout.total_length() != total_length {
            return Err(VerifyError::Metadata(format!(
                "chunk_lens sum {} != total_length {}",
                layout.total_length(),
                total_length
            )));
        }
        Ok(ResourceCommitment {
            layout,
            total_length,
            root,
            inclusion_proof,
        })
    }

    /// Check that a range's declared first-frame metadata is consistent with this commitment (same
    /// `chunk_lens`, `total_length`, and `root`). Used when a later range's first frame arrives to
    /// reject a source serving a different generation.
    pub fn check_consistent(
        &self,
        total_length: Option<u64>,
        chunk_lens: Option<&[u64]>,
        root: Option<&str>,
    ) -> Result<(), VerifyError> {
        if let Some(tl) = total_length {
            if tl != self.total_length {
                return Err(VerifyError::Metadata(format!(
                    "total_length {tl} != committed {}",
                    self.total_length
                )));
            }
        }
        if let Some(cl) = chunk_lens {
            if cl != self.layout.chunk_lens() {
                return Err(VerifyError::Metadata("chunk_lens differ".into()));
            }
        }
        if let (Some(r), Some(committed)) = (root, self.root.as_deref()) {
            if r != committed {
                return Err(VerifyError::Metadata(format!(
                    "root {r} != committed {committed}"
                )));
            }
        }
        Ok(())
    }
}

/// Verifies a reassembled resource's `resource_leaf` is committed under the chain-anchored `root` —
/// the digstore merkle inclusion check.
///
/// This is a **seam**: the digstore merkle-proof byte format lives with the store types, so dig-node
/// injects the real verifier and this crate ships only the explicitly-opt-in
/// [`StructuralOnlyProofVerifier`] (which does NOT bind to the chain). See the implementers' note in
/// the crate docs.
pub trait ProofVerifier: Send + Sync {
    /// Return `true` iff `resource_leaf` (SHA-256 of the whole resource ciphertext) is the leaf
    /// committed under `root` per `inclusion_proof`. For a capsule fetch (`inclusion_proof` / `root`
    /// = `None`) an implementation returns `true` (the capsule self-verifies on install).
    fn verify_inclusion(
        &self,
        resource_leaf: &[u8; 32],
        inclusion_proof: Option<&str>,
        root: Option<&str>,
    ) -> bool;
}

/// A **structural-only, fail-OPEN** [`ProofVerifier`] that accepts any `resource_leaf` without
/// parsing the digstore merkle proof — so a [`MerkleVerifier`] using it enforces length + chunk
/// alignment + metadata consistency + resource self-consistency, but does **NOT** bind the resource
/// to the on-chain root.
///
/// This provides **no chain-anchored integrity** and MUST NOT be used in production: a
/// [`Downloader`](crate::Downloader) built with it will accept right-length-but-forged content that a
/// real proof verifier would reject. It exists only to unit-test the structural checks and to let a
/// caller opt in EXPLICITLY via [`MerkleVerifier::insecure_structural_only`]. dig-node injects a real
/// digstore proof verifier via [`MerkleVerifier::with_proof_verifier`] to bind to the chain.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default)]
pub struct StructuralOnlyProofVerifier;

impl ProofVerifier for StructuralOnlyProofVerifier {
    fn verify_inclusion(
        &self,
        _resource_leaf: &[u8; 32],
        _inclusion_proof: Option<&str>,
        _root: Option<&str>,
    ) -> bool {
        true
    }
}

/// Per-range + whole-resource integrity verification. The orchestrator holds one and calls
/// [`verify_range`](Self::verify_range) as each range arrives and
/// [`verify_resource`](Self::verify_resource) once the resource is fully assembled.
pub trait Verifier: Send + Sync {
    /// Fast per-range check: `bytes` (the reassembled range starting at chunk `first_chunk_index`)
    /// is EXACTLY `expected_len` bytes AND covers whole chunk(s) whose lengths match the commitment.
    ///
    /// The `expected_len` check is load-bearing for integrity: a peer can serve fewer whole chunks
    /// than requested (a boundary-aligned SHORT range) whose bytes still start and end on chunk
    /// boundaries — structurally aligned yet incomplete. Requiring `bytes.len() == expected_len`
    /// (the planned [`Range::length`](crate::plan::Range::length)) rejects that short range as
    /// [`VerifyError::Length`], so the orchestrator re-fetches it from another provider rather than
    /// silently writing a hole. Returns [`VerifyError::Length`] for a mis-sized range and
    /// [`VerifyError::Alignment`] for an unaligned one.
    fn verify_range(
        &self,
        commitment: &ResourceCommitment,
        first_chunk_index: u64,
        expected_len: u64,
        bytes: &[u8],
    ) -> Result<(), VerifyError>;

    /// Whole-resource check once every range is assembled: `full` has the committed `total_length`
    /// and its `resource_leaf` verifies under the chain-anchored `root`.
    fn verify_resource(
        &self,
        commitment: &ResourceCommitment,
        full: &[u8],
    ) -> Result<(), VerifyError>;

    /// Whole-resource check from a PRE-COMPUTED `resource_leaf` + the contiguously-hashed
    /// `assembled_len`, so the orchestrator can hash ranges incrementally
    /// ([`ResourceHasher`]) and avoid retaining the whole resource + a concatenated copy in RAM
    /// (~2N bytes — MEDIUM #179). `assembled_len` must equal the committed `total_length` (else the
    /// resource is incomplete → [`VerifyError::Length`]); `leaf` is then bound to the chain-anchored
    /// `root`. The default implementation mirrors [`verify_resource`](Self::verify_resource) minus the
    /// hashing.
    fn verify_resource_leaf(
        &self,
        commitment: &ResourceCommitment,
        leaf: &[u8; 32],
        assembled_len: u64,
    ) -> Result<(), VerifyError>;
}

/// The real [`Verifier`]: chunk-length + alignment per range, `resource_leaf = SHA-256(concat)` bound
/// to the chain-anchored `root` (via a [`ProofVerifier`]) for the whole resource — exactly L7 §9.
pub struct MerkleVerifier {
    proof: Arc<dyn ProofVerifier>,
}

impl MerkleVerifier {
    /// A verifier that binds `resource_leaf` to the chain-anchored `root` with `proof` — the
    /// production constructor. dig-node supplies the real digstore proof verifier here so the
    /// whole-resource check is chain-anchored.
    ///
    /// There is deliberately **no** `new()` / `Default` fail-open constructor: a chain-bound
    /// [`ProofVerifier`] must be supplied explicitly, so a consumer cannot *accidentally* get a
    /// verifier that skips the on-chain binding. The only structural-only path is the explicitly
    /// named, `#[doc(hidden)]` [`insecure_structural_only`](Self::insecure_structural_only).
    pub fn with_proof_verifier(proof: Arc<dyn ProofVerifier>) -> Self {
        MerkleVerifier { proof }
    }

    /// A **structural-only, fail-OPEN** verifier (length + alignment + metadata consistency only,
    /// NO chain binding) — see [`StructuralOnlyProofVerifier`].
    ///
    /// This gives no chain-anchored integrity and is for tests / explicit opt-in ONLY; production
    /// callers MUST use [`with_proof_verifier`](Self::with_proof_verifier) with a real digstore proof
    /// verifier. The name and `#[doc(hidden)]` are intentional: getting the insecure path requires
    /// asking for it by name.
    #[doc(hidden)]
    pub fn insecure_structural_only() -> Self {
        MerkleVerifier {
            proof: Arc::new(StructuralOnlyProofVerifier),
        }
    }

    /// The committed `resource_leaf` of `full`: the SHA-256 of the whole resource ciphertext (L7 §9;
    /// UNTAGGED, matching the digstore merkle-proofs read path `resource_leaf(ciphertext)`).
    pub fn resource_leaf(full: &[u8]) -> [u8; 32] {
        let digest = Sha256::digest(full);
        digest.into()
    }
}

impl Verifier for MerkleVerifier {
    fn verify_range(
        &self,
        commitment: &ResourceCommitment,
        first_chunk_index: u64,
        expected_len: u64,
        bytes: &[u8],
    ) -> Result<(), VerifyError> {
        // Length first, fail-closed: a boundary-aligned SHORT range (fewer whole chunks than
        // planned) still passes the alignment check below, so the ONLY thing that catches it is
        // this exact-length comparison against the planned range length.
        if bytes.len() as u64 != expected_len {
            return Err(VerifyError::Length {
                expected: expected_len,
                actual: bytes.len() as u64,
            });
        }
        // EXPLICIT conversion, not `as usize`: on a 32-bit target a truncating cast maps an absurd
        // chunk index onto a VALID one, turning a rejection into a check against the wrong chunk. A
        // library cannot delegate this to a profile flag (#1608).
        let start = usize::try_from(first_chunk_index).map_err(|_| {
            VerifyError::Alignment(format!(
                "chunk_index {first_chunk_index} does not fit this platform's address space"
            ))
        })?;
        let layout = &commitment.layout;
        if start >= layout.chunk_count() {
            return Err(VerifyError::Alignment(format!(
                "chunk_index {start} out of range (chunk_count {})",
                layout.chunk_count()
            )));
        }
        let offset = layout
            .chunk_offset(start)
            .ok_or_else(|| VerifyError::Alignment("chunk_index has no offset".into()))?;
        // The bytes must cover whole chunk(s): find the chunk boundary at offset+len.
        let (cs, ce) = layout.chunks_for_range(offset, bytes.len() as u64)?;
        debug_assert_eq!(cs, start);
        let _ = ce;
        Ok(())
    }

    fn verify_resource(
        &self,
        commitment: &ResourceCommitment,
        full: &[u8],
    ) -> Result<(), VerifyError> {
        let leaf = MerkleVerifier::resource_leaf(full);
        self.verify_resource_leaf(commitment, &leaf, full.len() as u64)
    }

    fn verify_resource_leaf(
        &self,
        commitment: &ResourceCommitment,
        leaf: &[u8; 32],
        assembled_len: u64,
    ) -> Result<(), VerifyError> {
        if assembled_len != commitment.total_length {
            return Err(VerifyError::Length {
                expected: commitment.total_length,
                actual: assembled_len,
            });
        }
        if !self.proof.verify_inclusion(
            leaf,
            commitment.inclusion_proof.as_deref(),
            commitment.root.as_deref(),
        ) {
            return Err(VerifyError::Root);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commitment(chunk_lens: Vec<u64>) -> ResourceCommitment {
        let total = chunk_lens.iter().sum();
        ResourceCommitment::from_first_frame(total, chunk_lens, Some("aa".repeat(32)), None)
            .unwrap()
    }

    #[test]
    fn from_first_frame_rejects_inconsistent_total() {
        let err = ResourceCommitment::from_first_frame(999, vec![10, 20], None, None);
        assert!(matches!(err, Err(VerifyError::Metadata(_))));
    }

    #[test]
    fn resource_hasher_matches_concat_hash_regardless_of_feed_order() {
        // The incremental hasher must produce EXACTLY the SHA-256 of the concatenated ranges, no
        // matter what order the ranges are fed in (MEDIUM #179 — replaces retain-all + concat).
        let full: Vec<u8> = (0..90u16).map(|i| i as u8).collect();
        let expect = MerkleVerifier::resource_leaf(&full);

        // Feed the three 30-byte ranges out of order: 60, 0, 30.
        let mut h = ResourceHasher::new();
        h.feed(60, full[60..90].to_vec());
        assert!(
            h.has_gap(),
            "range at 60 is ahead of the frontier → buffered"
        );
        assert_eq!(h.hashed_len(), 0);
        h.feed(0, full[0..30].to_vec());
        assert_eq!(h.hashed_len(), 30);
        assert!(h.has_gap(), "range at 60 still buffered, 30..60 missing");
        h.feed(30, full[30..60].to_vec());
        assert!(!h.has_gap(), "the gap filled → everything drained");
        assert_eq!(h.hashed_len(), 90);
        assert_eq!(h.finalize(), expect);

        // In-order feed yields the same digest.
        let mut h2 = ResourceHasher::new();
        for off in [0u64, 30, 60] {
            h2.feed(off, full[off as usize..off as usize + 30].to_vec());
        }
        assert_eq!(h2.hashed_len(), 90);
        assert_eq!(h2.finalize(), expect);
    }

    #[test]
    fn resource_hasher_ignores_a_range_before_the_frontier() {
        let mut h = ResourceHasher::new();
        h.feed(0, vec![1u8; 10]);
        assert_eq!(h.hashed_len(), 10);
        // A stale re-feed strictly before the frontier is ignored (does not double-hash).
        h.feed(0, vec![1u8; 10]);
        assert_eq!(h.hashed_len(), 10);
        h.feed(10, vec![2u8; 10]);
        assert_eq!(h.hashed_len(), 20);
        let mut concat = vec![1u8; 10];
        concat.extend_from_slice(&[2u8; 10]);
        assert_eq!(h.finalize(), MerkleVerifier::resource_leaf(&concat));
    }

    #[test]
    fn verify_resource_leaf_length_and_root_binding() {
        let c = commitment(vec![10, 20]);
        // Precomputed leaf of the correct 30-byte resource.
        let correct = vec![3u8; 30];
        let leaf = MerkleVerifier::resource_leaf(&correct);
        // Short assembled length → Length error before any root binding.
        let v = MerkleVerifier::insecure_structural_only();
        assert!(matches!(
            v.verify_resource_leaf(&c, &leaf, 20),
            Err(VerifyError::Length { .. })
        ));
        // Correct length passes the structural-only verifier.
        assert!(v.verify_resource_leaf(&c, &leaf, 30).is_ok());

        // A real proof verifier binds the leaf to the root.
        struct OnlyLeaf([u8; 32]);
        impl ProofVerifier for OnlyLeaf {
            fn verify_inclusion(&self, l: &[u8; 32], _p: Option<&str>, _r: Option<&str>) -> bool {
                l == &self.0
            }
        }
        let v2 = MerkleVerifier::with_proof_verifier(Arc::new(OnlyLeaf(leaf)));
        assert!(v2.verify_resource_leaf(&c, &leaf, 30).is_ok());
        assert!(matches!(
            v2.verify_resource_leaf(&c, &[0u8; 32], 30),
            Err(VerifyError::Root)
        ));
    }

    #[test]
    fn verify_range_accepts_whole_chunks() {
        let c = commitment(vec![10, 20, 5]);
        let v = MerkleVerifier::insecure_structural_only();
        // chunk 0 alone (10 bytes)
        assert!(v.verify_range(&c, 0, 10, &[0u8; 10]).is_ok());
        // chunks 1..3 (25 bytes) starting at chunk 1
        assert!(v.verify_range(&c, 1, 25, &[0u8; 25]).is_ok());
    }

    #[test]
    fn verify_range_rejects_wrong_length() {
        let c = commitment(vec![10, 20, 5]);
        let v = MerkleVerifier::insecure_structural_only();
        // chunk 0 should be 10 bytes; 9 bytes → length mismatch (also not a chunk boundary).
        assert!(matches!(
            v.verify_range(&c, 0, 10, &[0u8; 9]),
            Err(VerifyError::Length {
                expected: 10,
                actual: 9
            })
        ));
    }

    #[test]
    fn verify_range_rejects_boundary_aligned_short_range() {
        // CRITICAL #179: a range planned over chunks 0..2 (30 bytes) but served only the first whole
        // chunk (10 bytes). Those 10 bytes ARE chunk-aligned, so alignment alone would pass — the
        // exact-length check is what rejects the short range.
        let c = commitment(vec![10, 20, 5]);
        let v = MerkleVerifier::insecure_structural_only();
        assert!(matches!(
            v.verify_range(&c, 0, 30, &[0u8; 10]),
            Err(VerifyError::Length {
                expected: 30,
                actual: 10
            })
        ));
    }

    /// The #836 class, one layer up: an over-long chunk-granular answer is a holder's LEGITIMATE
    /// granularity (§2.2), not a protocol violation — asserting otherwise is what defended the read-leg
    /// defect through six investigations.
    ///
    /// [`Verifier::verify_range`] receives bytes that [`assemble_range_stream`] has already CLIPPED to
    /// the requested window, so its exact-length check is a check on the ASSEMBLED range, not a verdict
    /// on what the holder streamed. This asserts the property that actually matters, at the layer that
    /// owns the freedom: a 30-byte answer to a 10-byte window, once clipped, VERIFIES. `RangeTransport`
    /// is a public trait and dig-node injects its own verifier, so any feeder that clips first must find
    /// this path open.
    #[tokio::test]
    async fn an_over_long_chunk_granular_answer_verifies_once_clipped() {
        let c = commitment(vec![10, 20, 5]);
        let v = MerkleVerifier::insecure_structural_only();

        // A chunk-granular holder answers a 10-byte window with a whole 30-byte span.
        let over_long = dig_nat::RangeFrame::data(0, vec![0u8; 30])
            .with_complete(true)
            .with_identity("aa".repeat(32), 35, 3)
            .with_chunk_lens_page(0, vec![10, 20, 5])
            .with_chunk_index(0);
        let wire = over_long
            .encode()
            .expect("a 30-byte fixture frame is far inside the framing ceilings");
        let mut stream = std::io::Cursor::new(wire);
        let (clipped, _meta) = crate::source::assemble_range_stream(&mut stream, 10)
            .await
            .expect("an over-long frame is clipped, never rejected");

        assert_eq!(clipped.len(), 10, "clipped to the requested window");
        assert!(
            v.verify_range(&c, 0, 10, &clipped).is_ok(),
            "a clipped chunk-granular answer verifies — the holder's granularity is not a violation"
        );
    }

    #[test]
    fn verify_range_rejects_out_of_range_chunk_index() {
        let c = commitment(vec![10]);
        let v = MerkleVerifier::insecure_structural_only();
        assert!(matches!(
            v.verify_range(&c, 5, 10, &[0u8; 10]),
            Err(VerifyError::Alignment(_))
        ));
    }

    #[test]
    fn verify_resource_length_mismatch() {
        let c = commitment(vec![10, 20]);
        let v = MerkleVerifier::insecure_structural_only();
        assert!(matches!(
            v.verify_resource(&c, &[0u8; 5]),
            Err(VerifyError::Length { .. })
        ));
    }

    #[test]
    fn insecure_structural_only_is_fail_open_on_the_root() {
        // The explicitly-named structural-only verifier does NOT bind to the chain: right-length but
        // arbitrary bytes pass verify_resource (this is why the constructor is named "insecure" and
        // #[doc(hidden)] — production callers must use with_proof_verifier). There is deliberately no
        // MerkleVerifier::new() / Default that could yield this posture by accident (#179 HIGH).
        let c = commitment(vec![10, 20]);
        let v = MerkleVerifier::insecure_structural_only();
        assert!(v.verify_resource(&c, &[0u8; 30]).is_ok());
        assert!(v.verify_resource(&c, &[0xFFu8; 30]).is_ok());
    }

    #[test]
    fn verify_resource_binds_to_root_with_real_proof_verifier() {
        // A proof verifier that only accepts the leaf of a specific "correct" resource.
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
        let correct = vec![7u8; 30];
        let leaf = MerkleVerifier::resource_leaf(&correct);
        let v = MerkleVerifier::with_proof_verifier(Arc::new(OnlyLeaf(leaf)));
        let c = commitment(vec![10, 20]);
        // Correct bytes verify.
        assert!(v.verify_resource(&c, &correct).is_ok());
        // Corrupt-but-right-length bytes fail the root binding.
        assert!(matches!(
            v.verify_resource(&c, &[8u8; 30]),
            Err(VerifyError::Root)
        ));
    }

    #[test]
    fn commitment_consistency_check() {
        let c = commitment(vec![10, 20, 5]);
        assert!(c
            .check_consistent(Some(35), Some(&[10, 20, 5]), Some(&"aa".repeat(32)))
            .is_ok());
        assert!(matches!(
            c.check_consistent(Some(99), None, None),
            Err(VerifyError::Metadata(_))
        ));
        assert!(matches!(
            c.check_consistent(None, Some(&[1, 2]), None),
            Err(VerifyError::Metadata(_))
        ));
        assert!(matches!(
            c.check_consistent(None, None, Some(&"bb".repeat(32))),
            Err(VerifyError::Metadata(_))
        ));
    }

    #[test]
    fn resource_leaf_is_sha256_untagged() {
        let leaf = MerkleVerifier::resource_leaf(b"hello");
        let expect: [u8; 32] = Sha256::digest(b"hello").into();
        assert_eq!(leaf, expect);
    }

    /// #1608 — a library's own `[profile.release] overflow-checks` protects NOTHING (only the ROOT
    /// package's profile applies), so a validator that leans on wrapping/saturating arithmetic for
    /// hostile-input safety is silently unsound in a consumer build. Here the hostile descriptor is
    /// `{ total_length: u64::MAX, chunk_lens: [1, u64::MAX] }`: a SATURATING sum lands on exactly
    /// u64::MAX, equals the declared total, and the commitment is ACCEPTED — the plan then covers
    /// spans no resource can have. The arithmetic must be CHECKED and the overflow a typed rejection.
    #[test]
    fn a_saturating_chunk_len_sum_cannot_pass_as_a_consistent_commitment() {
        // Bounded with a ceiling ABOVE the declared total, so the size bound cannot be what rejects it
        // and the CHECKED arithmetic is the thing under test.
        let err = ResourceCommitment::from_first_frame_bounded(
            u64::MAX,
            vec![1, u64::MAX],
            None,
            None,
            u64::MAX,
        )
        .expect_err("an overflowing chunk layout is refused");
        assert!(
            err.to_string().contains("overflow"),
            "names the arithmetic it broke: {err}"
        );
        // And under the DEFAULT ceiling the same descriptor is refused on size, before any arithmetic.
        let err = ResourceCommitment::from_first_frame(u64::MAX, vec![1, u64::MAX], None, None)
            .expect_err("an absurd declared total_length is refused");
        assert!(
            err.to_string().contains("exceeds the maximum"),
            "names the bound it broke: {err}"
        );
    }

    /// The declared chunk COUNT sizes the layout's own vectors, so it is bounded before allocation —
    /// the same one-message allocation attack as an absurd declared length.
    #[test]
    fn an_absurd_resource_chunk_count_is_refused() {
        let err = ResourceCommitment::from_first_frame(
            0,
            vec![0; crate::plan::MAX_RESOURCE_CHUNK_COUNT + 1],
            None,
            None,
        )
        .expect_err("an over-cap chunk count is refused");
        assert!(
            err.to_string().contains("exceeds the maximum"),
            "names the bound it broke: {err}"
        );
    }
}
