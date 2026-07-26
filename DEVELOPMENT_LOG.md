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
