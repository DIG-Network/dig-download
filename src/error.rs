//! [`DownloadError`] — the crate's top-level error, and [`VerifyError`] — why a fetched range or a
//! reassembled resource failed integrity.
//!
//! The orchestrator treats most errors as **recoverable per range**: a transport failure or a
//! [`VerifyError`] on one range marks that source suspect and re-queues the range to another
//! provider (it is never fatal to the whole download). Only the terminal conditions —
//! [`DownloadError::NoProviders`] (nowhere left to fetch a still-missing range) and
//! [`DownloadError::Cancelled`] — end a download.

use thiserror::Error;

/// The character bound applied to a foreign error `reason` when it is rendered (#1603). Long enough
/// for a nested dial/transport chain, short enough that a hostile peer cannot flood a log line.
pub const MAX_ERROR_REASON_CHARS: usize = 512;

/// The character bound applied to a rendered failure CONTEXT (a per-holder reason list), which is
/// legitimately longer than one reason but still bounded.
pub const MAX_ERROR_CONTEXT_CHARS: usize = 4096;

/// Render an untrusted identifier for a log or an error message: the lowercase 64-hex value if it IS
/// canonical 64-hex, else `<non-canonical-{label}>`.
///
/// Peer ids and a descriptor's hashes are peer-supplied free-form strings. Echoing one verbatim lets a
/// hostile holder inject newlines, markup, or forged log lines into the node's own diagnostics — so a
/// non-canonical value never reaches the output, and a log an attacker can write is never mistaken for
/// evidence (#1603). Applied in [`DownloadError`]'s own `Display`, so the raw id is UNREPRESENTABLE in
/// an error string however the error was constructed.
pub fn hex64_or_sentinel(value: &str, label: &str) -> String {
    let canonical = value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit());
    if canonical {
        value.to_ascii_lowercase()
    } else {
        format!("<non-canonical-{label}>")
    }
}

/// Render free-form foreign TEXT (a remote error message, a returned status line) safely: control
/// characters are escaped rather than emitted, and the result is bounded to `max_chars`.
///
/// A peer-supplied reason lands inside error messages consumers LOG, so an un-escaped newline lets a
/// holder forge whole log lines — the same #1603 class as an un-sentinelled peer id, through a
/// different door. Escaping (not deleting) keeps the reason diagnosable while making it exactly ONE
/// line.
pub fn sanitize_untrusted_text(text: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(text.len().min(max_chars));
    for (count, ch) in text.chars().enumerate() {
        if count == max_chars {
            out.push_str("…<truncated>");
            break;
        }
        if ch.is_control() || is_bidi_control(ch) {
            out.extend(ch.escape_debug());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Whether `ch` is a Unicode bidirectional-formatting character (the LRE/RLE/PDF/LRO/RLO overrides,
/// the isolate set, and the LRM/RLM/ALM marks).
///
/// These are category-`Cf`, NOT control characters, so `is_control` misses them — yet they visually
/// REORDER the text around them, which is enough to make a rendered log line read as something other
/// than what it says (the classic `…exe.txt` / `…txt.exe` swap). Escaped, not deleted, like every other
/// untrusted byte here.
fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{200E}' | '\u{200F}' | '\u{061C}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// An error from a download operation.
#[derive(Error)]
pub enum DownloadError {
    /// A transport-level failure fetching from one provider (connect failed, stream dropped,
    /// availability/range RPC errored, timeout). Carries the reason as text. **Recoverable**: the
    /// orchestrator marks the provider suspect and re-queues the range to another holder.
    #[error(
        "transport error from provider {}: {}",
        hex64_or_sentinel(provider, "peer-id"),
        sanitize_untrusted_text(reason, MAX_ERROR_REASON_CHARS)
    )]
    Transport {
        /// The provider `peer_id` (64-hex) the failure came from.
        provider: String,
        /// The underlying reason (stable, greppable text).
        reason: String,
    },

    /// A range fetch exceeded the configured per-range timeout (`DownloadConfig::range_timeout`) — a
    /// too-slow or stalled source. **Recoverable**: the range is re-queued to another holder and the
    /// slow source is backed off (its `TimedOut` outcome is reported to the selector).
    #[error(
        "range fetch from provider {} timed out",
        hex64_or_sentinel(provider, "peer-id")
    )]
    Timeout {
        /// The provider `peer_id` (64-hex) whose fetch timed out.
        provider: String,
    },

    /// A fetched range failed integrity verification. **Recoverable**: the bad range is discarded and
    /// re-fetched from a different provider, and the serving provider is penalized.
    ///
    /// The wrapped reason is SANITIZED here for the same reason a transport reason is: a verify failure
    /// routinely quotes peer-reported metadata (a first-frame `root`, a declared length), so it is
    /// untrusted text arriving through a different door.
    #[error(
        "integrity failure: {}",
        sanitize_untrusted_text(&.0.to_string(), MAX_ERROR_REASON_CHARS)
    )]
    Verify(#[from] VerifyError),

    /// A still-needed range has no live provider left to fetch it from — every known holder has been
    /// tried + failed and a fresh `find_providers` discovered no more. This is terminal for the
    /// download (there is nowhere left to get the missing bytes).
    #[error("no providers left holding the content (needed {needed} more range(s))")]
    NoProviders {
        /// How many ranges were still missing when the provider set was exhausted.
        needed: usize,
    },

    /// The content could not be fetched at all — either `find_providers` returned no holders, or
    /// no located holder could answer the metadata probe. Terminal.
    ///
    /// `content` names the content id AND which of those two steps failed: the message must never
    /// blame discovery for a probe failure (that ambiguity cost four #1586 investigations).
    #[error(
        "content not found: {}",
        sanitize_untrusted_text(content, MAX_ERROR_CONTEXT_CHARS)
    )]
    NotFound {
        /// The content id that could not be fetched, plus the step that failed.
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

/// `Debug` delegates to the SANITIZING [`Display`](std::fmt::Display) rather than printing raw fields.
///
/// `Debug` is not a developer-only rendering in practice: `tracing`'s `?field`, a `{:?}` in a log line,
/// and every `unwrap`/`expect` panic message emit it. A derived `Debug` would print the untrusted
/// `provider` / `reason` / verify text verbatim — unbounded, with markup intact — bypassing the very
/// sanitization `Display` applies. One rendering, one door.
impl std::fmt::Debug for DownloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DownloadError({self})")
    }
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
#[derive(Error, Clone, PartialEq, Eq)]
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

/// `Debug` sanitizes the wrapped text the same way [`DownloadError::Verify`]'s `Display` does, rather
/// than printing the derived struct fields verbatim.
///
/// `Metadata` / `Alignment` / `MissingMetadata` carry peer-reported text (a first-frame `root`, a
/// declared length) — the same untrusted-text class [`DownloadError`]'s own manual `Debug` guards.
/// `DownloadError::Verify`'s `Display` already sanitizes a WRAPPED `VerifyError`, but a bare one
/// reaches `{:?}` too (an `unwrap`/`expect` panic, a raw `tracing::error!(?e)`) — this closes that
/// second door with the same [`sanitize_untrusted_text`] the wrapping site uses.
impl std::fmt::Debug for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "VerifyError({})",
            sanitize_untrusted_text(&self.to_string(), MAX_ERROR_REASON_CHARS)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A canonical 64-hex peer id is a real identifier and is reported as-is.
    #[test]
    fn transport_helper_formats_with_provider() {
        let peer = "ab".repeat(32);
        let e = DownloadError::transport(&peer, "connection refused");
        assert!(e.to_string().contains(&peer));
        assert!(e.to_string().contains("connection refused"));
        assert!(e.is_recoverable());
    }

    /// #1603 — the provider id is UNREPRESENTABLE raw in an error string. The crate's own idiom
    /// stamps `&provider.provider_peer_id` (free-form text off the wire) straight into
    /// [`DownloadError::transport`], so the sanitization must live in `Display`, not at each call
    /// site: otherwise a hostile holder's forged log line rides out inside the wrapped error even
    /// though the surrounding code sentinelled the peer id.
    #[test]
    fn a_hostile_provider_id_and_reason_are_never_echoed() {
        let hostile = "not-hex <script>x</script>\n[FATAL] forged log line";
        let rendered =
            DownloadError::transport(hostile, "remote said: \n[FATAL] also forged").to_string();
        assert!(
            rendered.contains("<non-canonical-peer-id>"),
            "the id is sentinelled: {rendered}"
        );
        assert!(
            !rendered.contains("<script>"),
            "no peer-supplied id text: {rendered}"
        );
        assert!(
            !rendered.contains('\n'),
            "a foreign reason can never forge a second log line: {rendered}"
        );

        // Struct-literal construction bypasses the helper — Display still sanitizes.
        let direct = DownloadError::Transport {
            provider: hostile.to_string(),
            reason: "x\ny".to_string(),
        }
        .to_string();
        assert!(!direct.contains('\n') && !direct.contains("<script>"));
    }

    /// #1603, second door — a peer-reported first-frame `root` reaches a log through
    /// `VerifyError::Metadata` (`verify.rs`), and the `Verify` arm wrapped it VERBATIM. A wrapped
    /// integrity failure is as untrusted as a transport one, so `Display` must sanitize it too.
    #[test]
    fn a_hostile_verify_reason_can_never_forge_a_log_line() {
        let hostile = "root deadbeef\n[FATAL] forged by a peer != committed abc";
        let rendered =
            DownloadError::Verify(VerifyError::Metadata(hostile.to_string())).to_string();
        assert!(
            !rendered.contains('\n'),
            "a wrapped verify reason forges a second line: {rendered}"
        );
        assert!(
            rendered.contains("deadbeef"),
            "still diagnosable: {rendered}"
        );
    }

    /// A bare (unwrapped) `VerifyError`'s `{:?}` must sanitize too — not just `DownloadError::Verify`'s
    /// `Display`. `unwrap`/`expect` on a `Result<_, VerifyError>` and a raw `tracing::error!(?e)` both
    /// go through `Debug` directly, bypassing the wrapping site entirely.
    #[test]
    fn a_bare_verify_error_debug_is_sanitized_too() {
        let hostile = "root deadbeef\n[FATAL] forged by a peer != committed abc";
        let rendered = format!("{:?}", VerifyError::Metadata(hostile.to_string()));
        assert!(
            !rendered.contains('\n'),
            "a bare Debug forges a second line: {rendered}"
        );
        assert!(
            rendered.contains("deadbeef"),
            "still diagnosable: {rendered}"
        );
    }

    /// A bidi override reorders a rendered log line without being a control char, so it is escaped
    /// exactly like one.
    #[test]
    fn bidi_overrides_are_escaped_like_control_characters() {
        let sanitized = sanitize_untrusted_text("safe\u{202E}dorp.exe", 64);
        assert!(
            !sanitized.contains('\u{202E}'),
            "the override survived: {sanitized}"
        );
        assert!(sanitized.contains("safe"), "still diagnosable: {sanitized}");
    }

    #[test]
    fn untrusted_text_is_escaped_and_bounded() {
        assert_eq!(sanitize_untrusted_text("a\nb", 64), "a\\nb");
        assert_eq!(sanitize_untrusted_text("héllo", 64), "héllo");
        let long = sanitize_untrusted_text(&"x".repeat(100), 10);
        assert_eq!(long, format!("{}…<truncated>", "x".repeat(10)));
    }

    #[test]
    fn untrusted_ids_are_sentinelled() {
        let canonical = "ab".repeat(32);
        assert_eq!(hex64_or_sentinel(&canonical, "peer-id"), canonical);
        assert_eq!(
            hex64_or_sentinel(&"AB".repeat(32), "peer-id"),
            canonical,
            "canonical form is lowercase"
        );
        assert_eq!(
            hex64_or_sentinel("short", "peer-id"),
            "<non-canonical-peer-id>"
        );
        assert_eq!(
            hex64_or_sentinel(&"zz".repeat(32), "hash"),
            "<non-canonical-hash>"
        );
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
        let peer = "cd".repeat(32);
        let e = DownloadError::Timeout {
            provider: peer.clone(),
        };
        assert!(e.is_recoverable());
        assert!(e.to_string().contains(&peer));
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
