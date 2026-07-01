//! Range planning: turn a resource's chunk layout into the chunk-aligned byte ranges a download fans
//! across providers, and track each range's scheduling state.
//!
//! A resource's ciphertext is a sequence of chunks whose per-chunk lengths are `chunk_lens` (L7 §9,
//! from the first `dig.fetchRange` frame / the availability answer). [`ChunkLayout`] turns that into
//! byte offsets; [`plan_ranges`] partitions the resource into contiguous, **chunk-aligned** ranges of
//! at most the node window (so a single range always maps to whole chunk(s) and is independently
//! verifiable — L7 §9 "a requested range maps to whole chunk(s)"). Each range is scheduled
//! independently: fetched from some provider, verified, and marked done — and a done range is never
//! re-fetched (the basis of resume).

use crate::error::VerifyError;

/// The chunk boundaries of a resource: the per-chunk ciphertext lengths and their cumulative byte
/// offsets. Built from the `chunk_lens` a peer reports in the first range frame (or the availability
/// answer), this is the map from a byte range to the chunk(s) it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkLayout {
    /// Per-chunk ciphertext lengths, in order (`chunk_lens` on the wire).
    chunk_lens: Vec<u64>,
    /// Cumulative start offset of each chunk (len = `chunk_lens.len() + 1`; last = total length).
    offsets: Vec<u64>,
}

impl ChunkLayout {
    /// Build a layout from per-chunk lengths. Zero-length chunks are permitted (an empty resource has
    /// no chunks; a resource with content has ≥1).
    pub fn new(chunk_lens: Vec<u64>) -> Self {
        let mut offsets = Vec::with_capacity(chunk_lens.len() + 1);
        let mut acc = 0u64;
        offsets.push(0);
        for &len in &chunk_lens {
            acc = acc.saturating_add(len);
            offsets.push(acc);
        }
        ChunkLayout {
            chunk_lens,
            offsets,
        }
    }

    /// The number of chunks.
    pub fn chunk_count(&self) -> usize {
        self.chunk_lens.len()
    }

    /// The per-chunk lengths.
    pub fn chunk_lens(&self) -> &[u64] {
        &self.chunk_lens
    }

    /// The total ciphertext length (sum of all chunk lengths).
    pub fn total_length(&self) -> u64 {
        *self.offsets.last().unwrap_or(&0)
    }

    /// The byte start offset of chunk `index`, or `None` if out of range.
    pub fn chunk_offset(&self, index: usize) -> Option<u64> {
        self.offsets.get(index).copied()
    }

    /// The length of chunk `index`, or `None` if out of range.
    pub fn chunk_len(&self, index: usize) -> Option<u64> {
        self.chunk_lens.get(index).copied()
    }

    /// The chunk index range `[start, end)` that a byte range `[offset, offset+length)` covers,
    /// requiring the byte range to be **chunk-aligned** (start on a chunk boundary, end on a chunk
    /// boundary). Returns [`VerifyError::Alignment`] otherwise — an unaligned range is not a
    /// verifiable unit.
    pub fn chunks_for_range(
        &self,
        offset: u64,
        length: u64,
    ) -> Result<(usize, usize), VerifyError> {
        let end = offset.saturating_add(length);
        let start_idx = self
            .offsets
            .iter()
            .position(|&o| o == offset)
            .ok_or_else(|| {
                VerifyError::Alignment(format!("offset {offset} is not a chunk boundary"))
            })?;
        let end_idx =
            self.offsets.iter().position(|&o| o == end).ok_or_else(|| {
                VerifyError::Alignment(format!("end {end} is not a chunk boundary"))
            })?;
        if end_idx < start_idx {
            return Err(VerifyError::Alignment(format!(
                "range end {end} precedes start {offset}"
            )));
        }
        Ok((start_idx, end_idx))
    }
}

/// One planned byte range of the resource — a contiguous set of whole chunks fetched as a unit.
///
/// A range is the scheduling atom: it is fetched from a single provider at a time, verified against
/// the resource commitment, and marked done. Ranges are independent, so different ranges of the same
/// resource are fetched from different providers concurrently and a failed range is re-fetched
/// elsewhere without disturbing the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    /// Stable index of this range in the plan (0-based, ascending by offset).
    pub index: usize,
    /// Byte start offset within the resource ciphertext.
    pub offset: u64,
    /// Byte length (sum of the lengths of the chunks it covers).
    pub length: u64,
    /// First chunk index this range covers (into `chunk_lens`).
    pub chunk_start: usize,
    /// One-past-the-last chunk index this range covers.
    pub chunk_end: usize,
}

impl Range {
    /// The `[chunk_start, chunk_end)` chunk index range this byte range covers.
    pub fn chunk_range(&self) -> std::ops::Range<usize> {
        self.chunk_start..self.chunk_end
    }
}

/// Partition a resource into chunk-aligned ranges of at most `window` bytes each.
///
/// Chunks are packed greedily into ranges: a chunk is added to the current range while the range
/// stays within `window`; a chunk larger than `window` becomes its own range (a range is always ≥ one
/// whole chunk, since a chunk is the smallest verifiable unit). The result tiles the whole resource
/// exactly, in ascending offset order.
pub fn plan_ranges(layout: &ChunkLayout, window: u64) -> Vec<Range> {
    let window = window.max(1);
    let mut ranges = Vec::new();
    let mut i = 0usize;
    let n = layout.chunk_count();
    while i < n {
        let chunk_start = i;
        let offset = layout.chunk_offset(i).unwrap_or(0);
        let mut length = 0u64;
        // Always take at least one chunk; keep adding whole chunks while within the window.
        while i < n {
            let clen = layout.chunk_len(i).unwrap_or(0);
            if length > 0 && length.saturating_add(clen) > window {
                break;
            }
            length = length.saturating_add(clen);
            i += 1;
        }
        ranges.push(Range {
            index: ranges.len(),
            offset,
            length,
            chunk_start,
            chunk_end: i,
        });
    }
    ranges
}

/// The scheduling state of one range in a running download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeState {
    /// Not yet started (or re-queued after a failure) — awaiting assignment to a provider.
    Pending,
    /// Currently being fetched from the provider with this `peer_id` (64-hex).
    InFlight(String),
    /// Fetched and verified — will never be fetched again (the resume invariant).
    Done,
}

impl RangeState {
    /// Whether this range still needs work (pending or in-flight).
    pub fn is_incomplete(&self) -> bool {
        !matches!(self, RangeState::Done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_offsets_and_total() {
        let l = ChunkLayout::new(vec![10, 20, 5]);
        assert_eq!(l.chunk_count(), 3);
        assert_eq!(l.total_length(), 35);
        assert_eq!(l.chunk_offset(0), Some(0));
        assert_eq!(l.chunk_offset(1), Some(10));
        assert_eq!(l.chunk_offset(2), Some(30));
        assert_eq!(l.chunk_offset(3), Some(35));
        assert_eq!(l.chunk_offset(4), None);
        assert_eq!(l.chunk_len(1), Some(20));
        assert_eq!(l.chunk_len(9), None);
    }

    #[test]
    fn chunks_for_aligned_range() {
        let l = ChunkLayout::new(vec![10, 20, 5]);
        assert_eq!(l.chunks_for_range(0, 30).unwrap(), (0, 2));
        assert_eq!(l.chunks_for_range(10, 25).unwrap(), (1, 3));
        assert_eq!(l.chunks_for_range(30, 5).unwrap(), (2, 3));
        // Whole resource.
        assert_eq!(l.chunks_for_range(0, 35).unwrap(), (0, 3));
    }

    #[test]
    fn unaligned_range_rejected() {
        let l = ChunkLayout::new(vec![10, 20, 5]);
        assert!(matches!(
            l.chunks_for_range(5, 10),
            Err(VerifyError::Alignment(_))
        ));
        assert!(matches!(
            l.chunks_for_range(0, 15),
            Err(VerifyError::Alignment(_))
        ));
    }

    #[test]
    fn plan_packs_chunks_into_windows() {
        let l = ChunkLayout::new(vec![10, 10, 10, 10]);
        // window 25 → [10,10] (20), [10,10] (20)
        let ranges = plan_ranges(&l, 25);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].offset, 0);
        assert_eq!(ranges[0].length, 20);
        assert_eq!(ranges[0].chunk_range(), 0..2);
        assert_eq!(ranges[1].offset, 20);
        assert_eq!(ranges[1].length, 20);
        assert_eq!(ranges[1].chunk_range(), 2..4);
        // The plan tiles the whole resource exactly.
        assert_eq!(
            ranges.iter().map(|r| r.length).sum::<u64>(),
            l.total_length()
        );
    }

    #[test]
    fn plan_oversized_chunk_is_its_own_range() {
        let l = ChunkLayout::new(vec![100, 5]);
        let ranges = plan_ranges(&l, 25);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].length, 100); // one big chunk, over the window, alone
        assert_eq!(ranges[0].chunk_range(), 0..1);
        assert_eq!(ranges[1].length, 5);
        assert_eq!(ranges[1].chunk_range(), 1..2);
    }

    #[test]
    fn plan_single_range_when_window_large() {
        let l = ChunkLayout::new(vec![10, 20, 5]);
        let ranges = plan_ranges(&l, 1_000_000);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].offset, 0);
        assert_eq!(ranges[0].length, 35);
        assert_eq!(ranges[0].index, 0);
    }

    #[test]
    fn plan_empty_resource_has_no_ranges() {
        let l = ChunkLayout::new(vec![]);
        assert!(plan_ranges(&l, 100).is_empty());
        assert_eq!(l.total_length(), 0);
    }

    #[test]
    fn range_state_incompleteness() {
        assert!(RangeState::Pending.is_incomplete());
        assert!(RangeState::InFlight("p".into()).is_incomplete());
        assert!(!RangeState::Done.is_incomplete());
    }
}
