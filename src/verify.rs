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

use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::error::VerifyError;
use crate::plan::ChunkLayout;

/// The trusted per-resource metadata a download verifies every range against: the chunk boundaries,
/// the total length, the chain-anchored generation `root`, and (for a resource, not a capsule) the
/// whole-resource `inclusion_proof`.
///
/// Established from the first frame of the first fetched range (or an availability answer + the first
/// frame). Immutable for the life of the download: a range whose first-frame metadata disagrees with
/// this commitment is rejected as a different/forged generation.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Build a commitment from first-frame verification metadata. Validates that `chunk_lens` sums to
    /// `total_length` (a peer that reports inconsistent metadata is rejected up front).
    pub fn from_first_frame(
        total_length: u64,
        chunk_lens: Vec<u64>,
        root: Option<String>,
        inclusion_proof: Option<String>,
    ) -> Result<Self, VerifyError> {
        let layout = ChunkLayout::new(chunk_lens);
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
        let start = first_chunk_index as usize;
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
        if full.len() as u64 != commitment.total_length {
            return Err(VerifyError::Length {
                expected: commitment.total_length,
                actual: full.len() as u64,
            });
        }
        let leaf = MerkleVerifier::resource_leaf(full);
        if !self.proof.verify_inclusion(
            &leaf,
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
        // A too-LONG boundary-aligned range (extra whole chunk) is likewise rejected on length.
        assert!(matches!(
            v.verify_range(&c, 0, 10, &[0u8; 30]),
            Err(VerifyError::Length {
                expected: 10,
                actual: 30
            })
        ));
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
}
