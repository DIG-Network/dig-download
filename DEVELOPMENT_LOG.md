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

## Reshare: the announce is driven by a FILE PATH, not by a function call (#1576)

The node's DHT provider records are derived from its cache inventory, so **the existence of
`<cache>/modules/<store>/<root>.module` IS this node's network-wide claim to be an authoritative holder
of that capsule.** There is no "announce()" you can forget to guard — writing the file is the announce.

Consequence for any code that produces a module (a gap-fill, a §21 sync, a reshare pull): it MUST NOT
stage anywhere under the cache. A whole-capsule pull that staged at the cache path would advertise a
half-downloaded capsule for the duration of the download, and a *failed* pull would leave a permanent
claim to content the node cannot serve. The reshare leg therefore stages under `<downloads>` and moves
into the cache (write-then-rename) only after the pull succeeded AND the artifact was re-proven.

## A hash gate cannot detect the empty module (#1576)

`ModuleDownloader` runs two hash gates before admitting a module: every chunk against `chunk_hashes`,
then the whole blob against `module_hash`. **Both pass trivially for a 0-byte module.** The attacker
declares `total_size: 0` and `module_hash: sha256("")`, serves nothing, and `sha256(&[])` genuinely
equals the declared value — the arithmetic is correct and the module is worthless.

More generally: every check before the chain-anchor gate compares attacker-chosen bytes against
attacker-chosen hashes. They prove SELF-CONSISTENCY, never authenticity. The anchor gate — the module's
committed `CurrentRoot` versus a root resolved from the CHAIN — is the only check that says anything
about authenticity, which is why the empty-blob and unparseable-blob rejections live in the verifier and
not somewhere more convenient.

## "verified artifact" and "promoted artifact" are different objects (#1576)

`ModuleDownloader` verifies an in-memory blob, then promotes a STAGING FILE. Those are two objects, and
`download() == Ok` only speaks about the first. Anything that can touch the staging file between the gate
and the promotion (another process, a leftover tail from a longer earlier attempt, a crash mid-rename)
breaks the equivalence silently — the caller sees success and caches something that was never verified.

The external check is to re-hash the file about to be promoted. The reference for that comparison must
NOT be the descriptor's `module_hash`: that value was chosen by the serving peer. Instead the anchor
verifier records the digest of the bytes it actually ADMITTED — it is the only component that ever sees
the fully-assembled, gate-passed blob — and the promotion compares against that. Both sides of the
comparison are then the node's own.

## A caret dep can be right while the resolved tree is wrong (#1576, sibling of #836)

dig-download 0.8.0 depended on dig-rpc-protocol `"0.5"` — correct — and still resolved **0.3.1 as well**,
because dig-peer 0.4.1 pulled the older major. Two `ModuleInfo` types then sat either side of the module
pull's trust boundary, on `chunk_hashes`/`chunk_lens`: the fields that drive the whole pull plan. Rust
compiles that happily; it presents as content that arrives and never verifies (exactly #836's
`serde_bytes`-vs-base64 range-frame skew, six blind diagnosis rounds).

Two lessons, both now enforced by tests that read `Cargo.lock`:

1. Assert the invariant against the **resolved lock**, not the manifest. `cargo tree -i <crate>@<version>`
   names the culprit in one command.
2. The culprit is often **your own workspace**. After bumping dig-node-core to dig-rpc-protocol 0.5, the
   lock STILL carried 0.3.1 — from `dig-node-service`, the shell in the same repo, whose own pin nobody
   had thought to bump. A cross-repo cascade is not finished until every crate in the consuming workspace
   is on the new major.

## Cargo features can smuggle a fail-open bypass past every test (#1576)

dig-download compiles its fail-OPEN `AcceptAnyModuleAnchor` out of a default build (`cfg(any(test,
feature = "testkit"))`) precisely so a production wiring cannot name it. That protection is a **manifest
edit** away from gone — and the edit compiles, and every existing test still passes.

So the protection needs a test that reads the manifest: `testkit` must appear only under
`[dev-dependencies]`, never on the production edge (dev-dependency features do not propagate to
consumers, so the binaries never see it). A guarantee enforced by build configuration needs an assertion
at the build-configuration level; a unit test cannot reach it.

## A one-sided length proof fails open on the other side, with the same signature

The promotion guard shortened the staging area to the verified length and then probed for a byte PAST it.
That closes the long side and nothing else. `truncate` never extends, so a staging area SHORTER than the
verified length survives it untouched; the past-the-end probe on a short file reads `UnexpectedEof`, which
the guard read as "clean"; and the short artifact was renamed onto the final path with `Ok(total_length)`
returned — byte-for-byte the same observable signature as the long-side defect it was written to prevent.

Reachable with no attacker at all: the GC reaps `<target>.download.tmp` plus its `.state` sidecar, while
`FileStateStore` keeps its checkpoint under a different filename entirely, so a checkpoint routinely
outlives the bytes it describes. With the whole-resource backstop disabled, nothing else was checking
completeness — and the toggle is documented as dropping chain-anchoring, not completeness.

Rule: when a proof is a comparison, prove BOTH inequalities. "Not longer than" is not "equal to". And when
an integrity check's absence is configurable, write down what the config actually removes — someone will
read `verify_whole_resource: false` as "skip the expensive hash", not as "skip the only guarantee that the
promoted file is whole".

## "Unsupported" and "absent" must not share an error

`read_at` returned `Err` both for "this sink cannot read back" and for "there is nothing there", and the
promotion probe had to interpret one of them. Whichever way it guesses, a sink exists that it gets wrong:
treat `Err` as "nothing past the end" and an unproven sink promotes; treat it as "bytes are there" and an
honest whole-commit sink can never promote. The crate's own `truncate` doc even RECOMMENDED the combination
that fails open (override `truncate` to `Ok(())`, leave `read_at` alone) — a documented recipe that
reinstated the defect the release was fixing.

The fix is a capability, not a smarter guess: `supports_read_back()` defaults to false and a sink that
cannot prove its staged length is refused promotion. Generalization: when a guard's decision depends on
distinguishing two causes of one error value, the type is wrong — make the capability explicit and default
it to the fail-closed answer.

## Reputation that excludes must be triggered by "nobody left", not "everybody named"

The escape hatch protecting against reputation-denial asked "are ALL located holders remembered?". The
denial actually happens whenever excluding the remembered ones leaves nobody ASKABLE — which includes the
much more interesting partial case: verdicts on the honest holders, none on the liar. Then the memory
excludes the honest holders, the liar wins the handshake, fails a gate, is demoted, and the pull dies with
honest holders sitting right there. The right predicate is the one about the resource you are running out
of ("no usable holder remains"), not the one about the state you happen to be holding.

And the state itself was remotely inducible. Chunk exhaustion was persisted as a bad-descriptor verdict,
but exhaustion is not evidence about the SOURCE — the peers refusing chunks need not be the peer that
supplied the descriptor. Since DHT provider announcement is unauthenticated, sybils could refuse their
assigned chunks and get an honest descriptor source blacklisted on the victim for 24 h, per capsule,
repeatably, until only attacker-supplied descriptors were ever asked for: availability loss plus
attacker-chosen plans, from a feature added to save bandwidth.

Two rules fell out. A durable, exclusionary record may only be written from evidence that is attributable
to the peer it names — demote on suspicion, PERSIST only on proof. And any exclusion mechanism needs its
"what if this excludes everyone" path designed with it, not bolted on, because that path is what an
attacker aims for.

## A peer-declared length is an allocation instruction until you bound it

`ResourceCommitment::from_first_frame` checked the chunk COUNT and the checked sum, but never the declared
`total_length` itself — there was no resource-side counterpart to the module puller's `max_module_size`. So
a peer answering the metadata probe with `total_length: 2^40, chunk_lens: [2^40]` shaped the whole download:
`plan_ranges` always takes at least one WHOLE chunk regardless of the 3 MiB window, so that became a single
1 TiB range, and the assembler then ran with `max_len = 2^40`. One ~64-byte frame with `offset` just inside
the window drove `buf.resize(2^40, 0)` — an infallible allocation, i.e. `handle_alloc_error`, i.e. abort.

Two defects, both needed fixing: a missing CEILING (the bound must exist before the number is believed) and
an INFALLIBLE allocation (even within a ceiling, the host may not have the memory, and that must be an
error the scheduler routes around, not a death). A ceiling without fallibility just moves the cliff; the
`#1608` ticket said exactly this and it was still true one layer down.

Testing note: forcing a real allocation failure is not portable — an overcommitting host cheerfully commits
a terabyte and dies later, elsewhere. An ~18 EiB reservation, by contrast, fails deterministically on every
host without touching a page, so the sparse-frame test uses `u64::MAX` and asserts a RECOVERABLE error.

## A `bool` cannot say "I could not check", so it says "it failed" — and something durable believes it

`ModuleAnchorVerifier::verify_module_anchor` returned `bool`. An implementation that consults the chain has
no third answer available, so a coinset outage had to be reported as "not anchored" — a claim about the
HOLDER. Downstream, "not anchored" was proven-false evidence and earned a persisted 24 h demotion, so one
local outage branded every honest holder the pull tried. Worse than the lost bandwidth: for the whole TTL
the node's descriptor preference was INVERTED — remembered honest holders skipped, unremembered peers asked
first, and "unremembered" is exactly what a fresh sybil is.

The same shape appeared twice more in the same file from the other direction: a failed `try_reserve` for
the assembly buffer and for the chunk plan were both mapped to `BadDescriptor`, i.e. a local out-of-memory
outcome recorded as a peer's lie — and memory pressure is remotely inducible, since every concurrent pull
reserves up to `max_module_size` for an attacker-declared size.

The rule that ties all three together: **a durable, exclusionary record may only be written from evidence
attributable to the party it names.** Before persisting anything against a peer, ask which of us actually
failed. If the answer is "cannot tell", the type is wrong — give the check a third value.

And then the part that took one more round to see: **"who failed?" and "what happens next?" are two
INDEPENDENT axes, and one enum arm answers both — so picking an arm on the strength of the blame axis
alone silently picks the wrong next step.** Routing the failed allocation to `Terminal` was right about
blame (nobody) and wrong about routing (die instead of asking the next holder), which converted a
misattribution into a one-message denial: a ~100-byte self-consistent descriptor with an inflated
`total_size` passes the ceiling, fails the reservation, and kills every pull of that capsule. The correct
arm — demote-for-this-call, record nothing, try the next descriptor — was already in the enum, and the
justification for it was already written in the comment above the site ("the pressure itself is remotely
inducible"): remotely inducible pressure argues for routing AROUND a descriptor, not for surrendering to
it. Sanity check that generalizes: for every failure you classify, say the blame and the next step OUT
LOUD as separate sentences before choosing the variant, and confirm a test can distinguish the next-step
half — a test where every holder is hostile cannot see a missed retry.

## Fail-closed needs a recovery path, or it is a permanent denial

Two paths in this crate refuse and then self-heal (a failed whole-resource check, an abandoned descriptor
plan) — they drop the checkpoint AND the bytes it describes, so the next attempt starts clean. The
promotion refusal did not, and it is reachable without an attacker: GC reaps `<target>.download.tmp` plus
its `.state` sidecar while the `StateStore` keeps its checkpoint under an unrelated filename, so a
checkpoint outlives its bytes routinely. The refusal was correct; the absence of cleanup made it eternal
for that target.

The generalization is worth holding onto: every fail-closed branch has two questions, not one. Does it
refuse? And does the state that CAUSED the refusal survive it? A guard whose triggering state is durable
converts one bad checkpoint into permanent denial. Same reasoning made the exclusivity claim an RAII guard
rather than a paired register/unregister: `tokio::spawn` absorbs a panic, so an unwind past a manual
release would leave a path both GC-exempt and un-downloadable forever — the guard turning into the denial
it exists to prevent.
