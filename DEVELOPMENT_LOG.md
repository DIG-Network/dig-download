# dig-download — development log

Durable realizations worth keeping. Context, not a change diary.

## `format!("{host}:{port}").parse::<SocketAddr>()` silently bans IPv6

The socket-address grammar requires an IPv6 literal to be **bracketed** (`[2001:db8::1]:9444`). Composing
`host:port` from a bare IPv6 host and parsing it back therefore fails with `invalid socket address
syntax` — and it fails BEFORE any socket is opened, so the symptom is a transport error with no dial in
any packet capture.

This killed the whole #836 read leg: an AWS holder advertised `::ffff:172.31.79.22`, the metadata probe
turned it into `"::ffff:172.31.79.22:9444"`, and every confirmed holder was declared unusable → the read
404'd. The upstream candidate was correct all along (dig-node logged the properly bracketed
`[::ffff:172.31.79.22]:9444`); the corruption was purely this string round trip inside dig-download.

Rule: parse the host as an `IpAddr` and build `SocketAddr::new(ip, port)`. Never let a socket address
pass through the text grammar in the middle of a program. Rendering back to text goes through
`SocketAddr::to_string()` (or `addr::display`), which brackets correctly. Both live in `src/addr.rs`.

## One bad candidate must not condemn a holder

The same bug was only fatal because the dial considered a provider's FIRST address and nothing else —
the record ALSO carried a perfectly dialable `172.31.79.22:9444` that was never tried. §5.2 is IPv6-first
with IPv4 **fallback**, which means iterating: every candidate (v6, then v4, then relay-only), each
failure logged with the address it came from, and "unreachable" reported only once the list is exhausted.

## A metadata probe asks for 1 byte; a holder answers with a whole chunk

`establish_commitment` seeds a download by fetching `offset = 0, length = 1` — not because it wants a
byte, but because the FIRST `RangeFrame` of any range carries the verification metadata
(`total_length`, `chunk_lens`, `root`, `inclusion_proof`). The bytes are discarded.

Holders serve at their own storage granularity, so a chunk-granular holder answers that probe with a
whole chunk (e.g. 4096 bytes). An assembler that treats "frame longer than the requested window" as a
protocol error therefore rejects EVERY such holder, unconditionally — and it throws the result away
*after* it has already captured the metadata the probe existed to obtain. Every confirmed holder was
discarded, the download reported `NotFound`, and the read 404'd while packet capture showed the holder
happily serving bytes.

Rule: a request's `length` is a bound on what the CLIENT keeps, not a promise about how the SERVER
frames it. Clip an over-long frame to the window and stop once the window is full (that bound is what
protects memory); reserve the error for a frame starting at or beyond the window, whose bytes cannot
belong to the range at all. Any request/response boundary where the two sides have different natural
granularity wants the same shape.

## A resume that trusts its own staging file inherits corruption it can no longer localize

The obvious resume is: read the already-verified chunks back from the staging file, mark them done, fetch
only the rest. That treats staging as a trusted input — and it is not one. It outlives the process, is
reachable by anything else on the host, and is subject to plain bit-rot; the whole reason it exists is
that the pull was interrupted.

If a staged chunk is corrupted between runs, a trusting resume assembles the corruption, and the only
thing that notices is the whole-blob gate at the very end. That gate is fail-closed, so nothing bad is
SERVED — but the pull can never succeed again either, because the engine has no idea WHICH chunk is bad
and re-fetches nothing. Every subsequent resume fails identically. A fail-closed check that cannot
localize its failure turns transient corruption into a permanent dead download.

The fix is cheap because the descriptor already carries per-chunk hashes: re-attribute a rehydrated chunk
against `chunk_hashes` exactly like a freshly-fetched one, and on mismatch simply leave it not-done and
correct the checkpoint. Resume stays a pure optimization. Rule: a resume path may skip WORK, never a
CHECK — and the check it must keep is the one fine-grained enough to say what to redo.

## An untrusted descriptor that sizes a buffer is an allocation primitive for an attacker

`ModuleInfo.total_size` arrives from one peer over `getModuleInfo` and is exactly what the puller
allocates its assembly buffer from. With no bound, a single well-formed RPC reply naming 2^40 bytes makes
the node allocate until the OS kills it — no bytes transferred, no crypto broken, one message. The
descriptor's own self-consistency checks do not help: a liar makes the final `chunk_lens` entry match.

Any field that crosses a trust boundary and then feeds `Vec::with_capacity` / `vec![0; n]` / a
pre-allocated file needs a configured ceiling checked BEFORE the allocation, not a sanity check after it.
The bound belongs in config (callers legitimately differ) with a documented default sized to the real
artifact — here 8 GiB against capsules measured in megabytes.

## A peer-supplied descriptor's arithmetic must be CHECKED — a WRAPPING sum passes every self-consistency check

A transfer descriptor a peer sends (`ModuleInfo`: `total_size` + per-chunk `chunk_lens`) is validated by
checking the lengths sum to the declared total. With UNCHECKED arithmetic that check is vacuous against a
descriptor built to wrap: `{ total_size: 0, chunk_lens: [1, u64::MAX] }` sums to `1 + u64::MAX == 0`, which
equals `total_size`, so it passes — and then behaves differently in the two build configurations, both bad:

- `overflow-checks = on` (dig-node's release profile): the process PANICS inside `Iterator::sum` while
  validating. One `getModuleInfo` response, zero bytes fetched, no per-holder fallback — the panic happens
  before any recovery path exists.
- `overflow-checks = off`: the descriptor is ACCEPTED, producing spans `[(0, 1), (1, u64::MAX)]` against a
  zero-length assembly buffer, which panics on the copy — and reaches an 18 EiB INFALLIBLE allocation
  (`vec![0u8; len]`), whose failure is `handle_alloc_error`, an UNCATCHABLE abort.

Three durable lessons:

1. **A library's own `[profile.release]` does not protect it.** Only the ROOT package's profile applies, so
   a crate cannot rely on `overflow-checks = true` in its own `Cargo.toml`; its hostile-input validators must
   be total in BOTH configurations. Never treat "we enable overflow checks" as a mitigation.
2. **A validator whose stated job is "bound this before any allocation" must be TOTAL** — `checked_add` /
   `try_fold` on every accumulation, a cap on every declared COUNT (not just the declared SIZE), a
   `try_from` instead of `as usize`, and a `try_reserve` instead of `vec![0; n]` for anything the untrusted
   input sizes. An infallible allocation is a denial-of-service primitive with no error path.
3. **A size ceiling above real host memory is not a bound.** Capping a declared in-memory assembly at 8 GiB
   only raises the attacker's price to one message; the cap must be sized to what the host can actually hold
   (512 MiB default here), with the streaming rewrite tracked separately.

## Sanitizing an untrusted id at the REPORTING site does not sanitize it — the wrapped error carries it back

An untrusted `provider_peer_id` was correctly replaced by a sentinel where holder reasons were recorded, and
the test proving it passed — yet the raw id still reached the log, because the recorded REASON was a
`DownloadError::Transport` whose own `Display` is `"transport error from provider {provider}: {reason}"`
with the raw id inside. The crate's own idiom (`DownloadError::transport(&provider.provider_peer_id, e)`)
reproduces the leak at every call site, and a new adapter written by pattern-matching that code inherits it.
The test only passed because the ONE mock on that path happened to pass a literal instead of the peer id.

Put the sanitization in the error type's `Display`, not at the reporting site: then the raw value is
UNREPRESENTABLE in a rendered error however the error was constructed (including a struct literal), and the
leak cannot be reintroduced by a new call site. Sanitize the foreign REASON text the same way (escape
control characters + bound the length) — a remote error message is as attacker-controlled as an id, and an
un-escaped newline forges a whole log line. And make the test use the crate's real idiom, or it defends
nothing.

## One lying descriptor can deny a whole capsule's reshare if only the BYTES have holder rotation

A multi-source pull had careful per-chunk holder rotation + re-locate, but took its transfer DESCRIPTOR from
whichever holder answered first and never retried that step. Since holder order is deterministic, a single
holder answering with a well-formed-but-WRONG descriptor made every attempt — including every resume —
assemble honest bytes, fail the final whole-blob/anchor gate, and die terminally: an indefinite reshare
denial of a targeted capsule, from one message, with honest holders sitting right there.

The layer that controls the PLAN needs the same source rotation as the layer that fetches bytes: on a
final-gate failure, demote the descriptor's source, drop the checkpoint its plan produced, and re-handshake
with another holder (bounded attempts). And distinguish the two failure kinds — a chunk-level exhaustion
means the bytes are unavailable (terminal), while a final-gate failure means the descriptor lied (retry
elsewhere) — and report the descriptor failure as such, never as "not found".

## "Verified" only means something if the artifact verified is the artifact PROMOTED

A module pull verified the in-memory assembled blob against both final gates and then promoted the STAGING
AREA — two different artifacts, silently. A staging area is written by offset and nothing ever shortens it
(`FileSink::finalize` was `sync_all` + `rename`), so any earlier attempt that staged MORE bytes left a tail
the verified blob does not contain. The descriptor-demotion retry makes that reachable on purpose: a holder
declares a module LARGER than the real capsule with self-consistent `chunk_hashes`, serves those bytes
(passing every per-chunk check and the whole-blob hash), fails the chain-anchor gate on purpose, and the
pull then completes honestly against a SHORTER descriptor. `download()` returns `Ok(8)`, both gates passed,
and the promoted file is 8 honest bytes followed by 24 attacker bytes. There is an attacker-free trigger
too: a shape-mismatched checkpoint is discarded but the leftover staging FILE is not, so any resume across a
shape change promotes the same divergence.

That is a cache-poisoning primitive, not a length bug. On the reshare leg the node caches a `.dig` whose
SHA-256 is not `module_hash`, reports success, announces itself as a holder — and every downstream peer that
re-verifies fails, with an honest node as the authoritative-looking source of corrupt content.

So make promotion PROVE the equality rather than assume it: shorten the staging area to the verified length,
CONFIRM nothing is readable past that length (fail closed if it is — a sink that cannot shrink must refuse to
promote, not promote long), and reset the sink whenever a plan is abandoned (descriptor demotion, or a
checkpoint that does not resume the current shape). Assert on the PROMOTED bytes in the test, not on
`Ok(len)`: the existing tests all asserted the return value and the in-memory sink contents, which is
exactly why a 32-vs-8 promotion sat there green.

## Chunk exhaustion under an unverified descriptor is a DESCRIPTOR failure, not a missing-bytes failure

The demotion fix above classified a final-gate failure as "the descriptor lied" and chunk exhaustion as
"the bytes are unavailable, terminal". That handed the attacker a CHEAPER attack: fabricate `chunk_hashes`
instead of `module_hash` and serve nothing. Nobody can satisfy hashes of nothing, so the pull exhausts every
holder on chunk 0, returns `NotFound`, never reaches a gate — and the liar is never demoted, so no second
descriptor is ever tried. Zero bytes served, permanent reshare denial.

Exhaustion is genuinely AMBIGUOUS from inside one attempt; the honest discriminator is whether any chunk has
EVER verified under that descriptor. None → the descriptor is the suspect (demote + re-handshake). At least
one → the descriptor is credible and the exhaustion really is missing bytes (terminal; re-handshaking would
only replay the same fetches). Generalization: whenever a retry policy keys off WHICH check failed, enumerate
what an attacker can do to avoid reaching that check at all — the cheapest lie is usually the one that makes
your detector never run.
