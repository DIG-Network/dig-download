//! [`DownloadError`] — the crate's top-level error, and [`VerifyError`] — why a fetched range or a
//! reassembled resource failed integrity.
//!
//! The orchestrator treats most errors as **recoverable per range**: a transport failure or a
//! [`VerifyError`] on one range marks that source suspect and re-queues the range to another
//! provider (it is never fatal to the whole download). Only the terminal conditions —
//! [`DownloadError::NoProviders`] (nowhere left to fetch a still-missing range) and
//! [`DownloadError::Cancelled`] — end a download.

use thiserror::Error;

/// An error from a download operation.
#[derive(Debug, Error)]
pub enum DownloadError {
    /// A transport-level failure fetching from one provider (connect failed, stream dropped,
    /// availability/range RPC errored, timeout). Carries the reason as text. **Recoverable**: the
    /// orchestrator marks the provider suspect and re-queues the range to another holder.
    #[error("transport error from provider {provider}: {reason}")]
    Transport {
        /// The provider `peer_id` (64-hex) the failure came from.
        provider: String,
        /// The underlying reason (stable, greppable text).
        reason: String,
    },

    /// A range fetch exceeded the configured per-range timeout (`DownloadConfig::range_timeout`) — a
    /// too-slow or stalled source. **Recoverable**: the range is re-queued to another holder and the
    /// slow source is backed off (its `TimedOut` outcome is reported to the selector).
    #[error("range fetch from provider {provider} timed out")]
    Timeout {
        /// The provider `peer_id` (64-hex) whose fetch timed out.
        provider: String,
    },

    /// A fetched range failed integrity verification. **Recoverable**: the bad range is discarded and
    /// re-fetched from a different provider, and the serving provider is penalized.
    #[error("integrity failure: {0}")]
    Verify(#[from] VerifyError),

    /// A still-needed range has no live provider left to fetch it from — every known holder has been
    /// tried + failed and a fresh `find_providers` discovered no more. This is terminal for the
    /// download (there is nowhere left to get the missing bytes).
    #[error("no providers left holding the content (needed {needed} more range(s))")]
    NoProviders {
        /// How many ranges were still missing when the provider set was exhausted.
        needed: usize,
    },

    /// The content could not be located at all — `find_providers` returned no holders and no plan
    /// metadata could be obtained. Terminal.
    #[error("content not found: no providers located for {content}")]
    NotFound {
        /// A short description of the content id that could not be located.
        content: String,
    },

    /// The download was cancelled via [`DownloadHandle::cancel`](crate::DownloadHandle::cancel).
    /// Terminal (by request).
    #[error("download cancelled")]
    Cancelled,

    /// Persisting or loading resume state failed. Carries the reason.
    #[error("state store error: {0}")]
    State(String),

    /// The sink (store-write path) rejected a write. Carries the reason.
    #[error("sink write error: {0}")]
    Sink(String),

    /// The requested content id cannot be downloaded as a byte stream — a bare store id names a
    /// whole store (many capsules), not a single resource/capsule to fetch. Supply a root/capsule or
    /// resource content id.
    #[error("content id is not directly downloadable (needs a root/capsule or resource, got a bare store id)")]
    NotDownloadable,

    /// The orchestrator task ended unexpectedly (its channel closed before a terminal result). This
    /// indicates a bug or an aborted runtime, not a normal download outcome.
    #[error("download task ended without a result")]
    TaskEnded,
}

impl DownloadError {
    /// Build a [`DownloadError::Transport`] for `provider` from anything displayable.
    pub fn transport(provider: impl Into<String>, reason: impl std::fmt::Display) -> Self {
        DownloadError::Transport {
            provider: provider.into(),
            reason: reason.to_string(),
        }
    }

    /// Build a [`DownloadError::Sink`] from anything displayable.
    pub fn sink(reason: impl std::fmt::Display) -> Self {
        DownloadError::Sink(reason.to_string())
    }

    /// Build a [`DownloadError::State`] from anything displayable.
    pub fn state(reason: impl std::fmt::Display) -> Self {
        DownloadError::State(reason.to_string())
    }

    /// Whether this error is **recoverable per range** (the download can continue by retrying the
    /// range elsewhere) rather than terminal for the whole download.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            DownloadError::Transport { .. }
                | DownloadError::Verify(_)
                | DownloadError::Timeout { .. }
        )
    }
}

/// Why a fetched range or a reassembled resource failed integrity — the checks of L7 §9
/// "per-range integrity". A [`VerifyError`] on a range marks its source suspect + re-fetches.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// A returned range's byte length did not match the sum of the `chunk_lens` for the chunk(s) it
    /// was supposed to cover — the cheapest, per-range detection of a bad/truncated source.
    #[error("range length mismatch: expected {expected} bytes for chunks, got {actual}")]
    Length {
        /// The length the `chunk_lens` say the range should be.
        expected: u64,
        /// The length actually delivered.
        actual: u64,
    },

    /// A range's first-frame metadata was inconsistent with the resource commitment already
    /// established (a differing `chunk_lens`, `total_length`, or generation `root`) — a source
    /// serving a different/forged generation.
    #[error("range metadata mismatch with the resource commitment: {0}")]
    Metadata(String),

    /// A range was not aligned to whole chunk boundaries (offset/length did not start/end on a chunk
    /// edge per `chunk_lens`), so it cannot be a verifiable unit.
    #[error("range is not chunk-aligned: {0}")]
    Alignment(String),

    /// The reassembled whole resource's `resource_leaf` (= SHA-256 of its concatenated chunk
    /// ciphertexts) was not committed under the chain-anchored generation `root` — the on-chain
    /// integrity check. Either the assembled bytes are corrupt or the inclusion proof does not verify.
    #[error("resource does not verify against the chain-anchored root")]
    Root,

    /// The first frame of a range was missing the verification metadata (`total_length` / `chunk_lens`
    /// / `root`) required to establish or check the commitment.
    #[error("first frame is missing verification metadata ({0})")]
    MissingMetadata(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_helper_formats_with_provider() {
        let e = DownloadError::transport("abcd", "connection refused");
        assert!(e.to_string().contains("abcd"));
        assert!(e.to_string().contains("connection refused"));
        assert!(e.is_recoverable());
    }

    #[test]
    fn verify_errors_are_recoverable() {
        let e: DownloadError = VerifyError::Length {
            expected: 10,
            actual: 9,
        }
        .into();
        assert!(e.is_recoverable());
    }

    #[test]
    fn timeout_is_recoverable() {
        let e = DownloadError::Timeout {
            provider: "abcd".into(),
        };
        assert!(e.is_recoverable());
        assert!(e.to_string().contains("abcd"));
        assert!(e.to_string().contains("timed out"));
    }

    #[test]
    fn terminal_errors_are_not_recoverable() {
        assert!(!DownloadError::NoProviders { needed: 1 }.is_recoverable());
        assert!(!DownloadError::Cancelled.is_recoverable());
        assert!(!DownloadError::NotDownloadable.is_recoverable());
    }

    #[test]
    fn sink_and_state_helpers_format() {
        assert!(DownloadError::sink("disk full")
            .to_string()
            .contains("disk full"));
        assert!(DownloadError::state("corrupt")
            .to_string()
            .contains("corrupt"));
    }

    #[test]
    fn verify_error_display_is_descriptive() {
        assert!(VerifyError::Root
            .to_string()
            .contains("chain-anchored root"));
        assert!(VerifyError::Metadata("x".into())
            .to_string()
            .contains("commitment"));
        assert!(VerifyError::Alignment("y".into())
            .to_string()
            .contains("chunk-aligned"));
        assert!(VerifyError::MissingMetadata("z".into())
            .to_string()
            .contains("missing verification metadata"));
    }
}
