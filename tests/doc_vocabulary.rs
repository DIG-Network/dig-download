//! A mechanical guard against doc rot on the layout-adoption ordering.
//!
//! # Why this file exists
//!
//! This crate's candidate ordering was designed wrong twice, and each wrong design left vocabulary behind
//! in comments. Three review rounds were then spent finding the next unswept surface: `src/` was swept and
//! `tests/` was not, one stale phrase was replaced by a DIFFERENT forbidden design's phrase, and a manifest
//! comment kept asserting a dependency invariant the cascade had removed. Spot-checking found them one at a
//! time; nothing found them all at once.
//!
//! The failure mode is specific and worth naming: a doc that describes a design the SPEC forbids is worse
//! than one that is merely out of date, because a reimplementer building from it implements the defect. So
//! the retired vocabulary is banned mechanically, and the ban is enforced here rather than by review.
//!
//! # Deliberate history is allowed, and must be MARKED
//!
//! Recording a rejected design is valuable — it is why the third attempt did not repeat the first two — so
//! this does not ban the words outright. It requires every occurrence to sit in a BLOCK carrying
//! [`HISTORY_MARKER`] — a block being a run of consecutive non-blank lines, so one marker covers a whole
//! doc comment — which makes "this describes something we deliberately do NOT do" machine-checkable
//! instead of a matter of tone.
//!
//! # This guard asserts REACH, not just absence
//!
//! A grep guard that visits nothing passes identically to one that visits everything and finds nothing
//! wrong, so an emptiness assertion alone is worthless. Every check below is therefore paired with a
//! positive one: the scanned files must be present and substantial, the marker must actually be FOUND, and
//! the anchors that prove the right files were read must be present. If this file ever stops matching real
//! text, it fails rather than passing quietly.

/// Every surface whose prose can describe the removed machinery, embedded at COMPILE time so the assertions
/// cannot drift from the source they claim to check.
///
/// The manifest and the two Markdown files are in the set because all three rot findings this file exists
/// for were found in DIFFERENT surfaces: one in `src/`, one in `tests/`, and one in a `Cargo.toml` comment
/// asserting a dependency invariant the cascade had removed. A guard scanning only code would have missed
/// the third, which is the same one-surface-at-a-time failure it is meant to end.
///
/// Deliberately not this file itself: it necessarily contains every banned term.
///
/// Each entry carries its OWN line floor. A single global floor cannot describe both a 2,000-line module and
/// a 180-line manifest: set high enough for the module it rejects the manifest, and set low enough for the
/// manifest it stops proving anything about the module. Each number is roughly half the file's current
/// length, so ordinary editing never touches it while a truncated or wrong file cannot pass.
const SCANNED: [(&str, &str, usize); 6] = [
    (
        "src/orchestrator.rs",
        include_str!("../src/orchestrator.rs"),
        900,
    ),
    ("src/source.rs", include_str!("../src/source.rs"), 800),
    (
        "tests/orchestrator_scenarios.rs",
        include_str!("orchestrator_scenarios.rs"),
        900,
    ),
    ("Cargo.toml", include_str!("../Cargo.toml"), 80),
    ("SPEC.md", include_str!("../SPEC.md"), 300),
    ("CHANGELOG.md", include_str!("../CHANGELOG.md"), 40),
];

/// Vocabulary belonging to designs and APIs this crate REMOVED. Any occurrence must be marked history.
///
/// Every entry MUST be lowercase, and [`the_ban_list_itself_cannot_contain_a_dead_entry`] enforces it: the
/// matcher lowercases each line before comparing, so a term carrying a capital can never match anything.
/// `"LayoutRefuted"` sat in this list in exactly that state — a banned term that banned nothing — which is
/// the vacuity class this whole file exists to prevent, occurring inside the guard.
///
/// Three groups, and the third exists because the first two left a gap of exactly the class this file is
/// for:
///
/// - retired ORDERING mechanisms. There is no modal vote, no interleave across groups, no grouping by
///   declared shape, and group SIZE is never consulted. Phrases rather than bare words, so unrelated prose
///   ("the largest conceivable resource") is not swept up.
/// - IDENTIFIERS deleted with the #1670 attributability machinery. A removal leaves rot exactly as a
///   redesign does, and one round found a doc still pricing work in a config field that no longer exists.
/// - the retired ATTRIBUTION RULE stated as a CLASS. This group was missing, and its absence was a
///   coverage hole rather than an oversight of a few lines: an identifier ban catches a doc that names a
///   dead field, and cannot catch a doc that describes what the dead field DID. Two such docs sat in
///   already-scanned files and stayed green through a full round — `establish_commitment` still promising
///   that the commitment "records which holder it came from", and `adopt_layout` still returning an
///   "attributed" commitment.
///
/// The generalisable form: **when a rejected design turns out to be invisible to the ban list, that is a
/// coverage finding.** The observation that set this file's reach floor — "the attribution design contains
/// none of the banned terms" — was equally evidence that the design was out of scope entirely, and only the
/// floor conclusion was drawn. Widening the ban to cover it raised the floor from 2 to 3 as a consequence.
///
/// Phrases here are chosen narrowly enough not to sweep up the module-pull path, which legitimately DOES
/// attribute a bad descriptor to the holder that supplied it because it has per-chunk hashes. That is why
/// there is no bare "attributable" in this list.
const RETIRED_VOCABULARY: [&str; 16] = [
    // retired orderings
    "modal",
    "interleav",
    "grouped by declared shape",
    "largest agreeing group",
    "largest it keeps leading",
    "budget spans distinct declared shapes",
    // deleted identifiers
    "max_commitment_attempts",
    "established_from",
    "layoutrefuted",
    "refuted_layout_shapes",
    // the retired attribution rule, stated over the class
    "records which holder",
    "attributed commitment",
    "refutation later needs",
    "excludes its source",
    "adoption budget",
    "strict minority",
];

/// The marker that makes a mention deliberate history rather than rot.
const HISTORY_MARKER: &str = "REJECTED-DESIGN:";

/// Text that must be PRESENT for this guard to be meaningful — the anchors proving the intended files were
/// read and still contain the machinery being described.
const REQUIRED_ANCHORS: [(&str, &str); 4] = [
    ("src/orchestrator.rs", "fn establish_commitment"),
    ("src/orchestrator.rs", "fn adopt_layout"),
    ("src/source.rs", "fn assemble_range_stream"),
    (
        "tests/orchestrator_scenarios.rs",
        "fn a_refutation_adopts_a_layout_exactly_once",
    ),
];

/// **Proves:** no entry in the ban list is silently unmatchable.
///
/// **Catches:** a dead ban entry, which is the ban list's own version of a vacuous test. The matcher
/// lowercases each scanned line, so an entry containing a capital compares against text that can never hold
/// it and quietly bans nothing. `"LayoutRefuted"` was in the list in precisely that state — added to close a
/// gap, and closing none — and no other check would ever have reported it, because a term that matches
/// nothing looks identical to a term with nothing to match.
#[test]
fn the_ban_list_itself_cannot_contain_a_dead_entry() {
    for term in RETIRED_VOCABULARY {
        assert_eq!(
            term,
            term.to_ascii_lowercase(),
            "ban entry {term:?} contains a capital, so it can never match: the scan lowercases every line              before comparing"
        );
        assert!(
            !term.trim().is_empty(),
            "an empty ban entry matches every line and would make the whole ban unusable"
        );
    }
}

/// **Proves:** every mention of a removed mechanism or API is marked as deliberate history.
///
/// **Catches:** the rot class that cost three review rounds — a comment that still summarises the ordering
/// as "modal shape first", or justifies a mechanism by a group being "the LARGEST", or prices work in a
/// config field that has been deleted, when none of those exist.
#[test]
fn retired_vocabulary_appears_only_as_marked_history() {
    let mut unmarked: Vec<String> = Vec::new();
    for (name, body, _) in SCANNED {
        for (number, line, licensed) in scan_blocks(body) {
            if licensed {
                continue;
            }
            let lowered = line.to_ascii_lowercase();
            for term in RETIRED_VOCABULARY {
                if lowered.contains(term) {
                    unmarked.push(format!("{name}:{number}: [{term}] {}", line.trim()));
                }
            }
        }
    }
    assert!(
        unmarked.is_empty(),
        "these lines describe a mechanism this crate does not have. Either reword them to match the shipped \
         design, or put `{HISTORY_MARKER}` anywhere in the same block if it is deliberately recording a \
         rejected one:\n  {}",
        unmarked.join("\n  ")
    );
}

/// Every line of `body` as `(line number, text, whether its BLOCK carries the history marker)`.
///
/// A block is a run of consecutive non-blank lines, so one marker licenses a whole doc comment and the item
/// beneath it. That granularity is not a convenience: scoping the marker to the LINE was tried first and lost
/// to `cargo fmt`, which rewraps doc prose and so moved a banned term off its marked line onto an unmarked
/// continuation. The build then failed for a reflow rather than for rot, and a guard that fights the
/// formatter gets deleted rather than fixed.
fn scan_blocks(body: &str) -> Vec<(usize, &str, bool)> {
    let lines: Vec<&str> = body.lines().collect();
    let mut licensed = vec![false; lines.len()];
    let mut start = 0;
    while start < lines.len() {
        if lines[start].trim().is_empty() {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < lines.len() && !lines[end].trim().is_empty() {
            end += 1;
        }
        if lines[start..end]
            .iter()
            .any(|line| line.contains(HISTORY_MARKER))
        {
            licensed[start..end].fill(true);
        }
        start = end;
    }
    lines
        .into_iter()
        .enumerate()
        .map(|(index, line)| (index + 1, line, licensed[index]))
        .collect()
}

/// **Proves:** the guard above actually READ the files it claims to check, and matched real text in them.
///
/// **Catches:** the vacuity that makes a grep guard worthless — a renamed or moved file, an empty
/// `include_str!`, or a scan that visits nothing. An emptiness assertion cannot tell "nothing wrong" from
/// "nothing looked at", so the reach is asserted separately and from the positive side.
#[test]
fn the_vocabulary_guard_actually_reaches_the_source_it_checks() {
    let mut total_lines = 0;
    for (name, body, floor) in SCANNED {
        let lines = body.lines().count();
        assert!(
            lines > floor,
            "{name} looks truncated or wrong ({lines} lines, floor {floor}) — the scan would pass while \
             checking nothing"
        );
        total_lines += lines;
    }
    assert!(
        total_lines > 3_000,
        "the scanned surface shrank to {total_lines} lines; the ordering prose lives in these files and \
         cannot have moved wholesale without a deliberate update here"
    );

    for (name, anchor) in REQUIRED_ANCHORS {
        let body = SCANNED
            .iter()
            .find(|(candidate, _, _)| *candidate == name)
            .map(|(_, body, _)| *body)
            .unwrap_or_else(|| panic!("{name} is not in the scanned set"));
        assert!(
            body.contains(anchor),
            "{name} no longer contains `{anchor}`, so this guard is describing machinery that has moved; \
             update the guard deliberately rather than letting it pass on the wrong file"
        );
    }

    // The POSITIVE half: the marker must be found, and found on lines that genuinely carry banned terms.
    // If the rejected-design history is ever deleted wholesale this fails, which is the intended prompt to
    // update this guard on purpose instead of silently losing the record of why the ordering looks as it
    // does.
    let marked_with_a_banned_term: usize = SCANNED
        .iter()
        .map(|(_, body, _)| {
            scan_blocks(body)
                .into_iter()
                .filter(|(_, line, licensed)| {
                    *licensed && {
                        let lowered = line.to_ascii_lowercase();
                        RETIRED_VOCABULARY.iter().any(|term| lowered.contains(term))
                    }
                })
                .count()
        })
        .sum();
    assert!(
        // THREE, one per rejected design, and the number moved from two to three as a DIRECT result of
        // widening the ban above. It was two while the ban covered only the retired orderings, because the
        // third design — the strict-minority attribution rule — contained none of the listed terms. That
        // fact was the evidence for a coverage hole, and it was first read only as a floor calculation:
        // "the attribution design names none of the terms" answers "what is the true count?" and
        // "is that design in scope at all?", and only the first question was asked.
        //
        // So the floor is now a live check on the ban's COVERAGE, not just on its reach: it is satisfiable
        // only while every rejected design remains describable in banned vocabulary. If a fourth design is
        // ever rejected, this number must rise with it.
        marked_with_a_banned_term >= 3,
        "only {marked_with_a_banned_term} marked history line(s) carry retired vocabulary. Either the \
         matcher has stopped matching real text — in which case the ban above is vacuous — or the record \
         of the rejected orderings has been deleted"
    );
}

/// **Proves:** `SPEC.md` still states that a refutation is terminal, that a vote over peer declarations is
/// forbidden, that #1670 is OPEN, and that adoption order is discovery's.
///
/// **Catches:** the inverse of doc rot — a normative requirement, or an admitted limitation, quietly
/// disappearing. Three separate implementations of a declaration-based attribution rule were shipped and
/// removed here; the prohibition and the reason are what stop a fourth. The open-residual statement matters
/// just as much: silence about a known denial is its own kind of overclaim.
#[test]
fn the_spec_still_states_the_terminal_refutation_and_ordering_rules() {
    const SPEC: &str = include_str!("../SPEC.md");
    // Whitespace-COLLAPSED before matching. A normative sentence in Markdown wraps wherever the line length
    // falls, so a raw `contains` on a phrase spanning a line break fails for a reflow rather than for a
    // dropped requirement — a guard that cries wolf on formatting gets disabled.
    let normative: String = SPEC.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        normative.len() > 20_000,
        "SPEC.md looks truncated ({} chars after collapsing); the checks below would pass while reading          almost nothing",
        normative.len()
    );
    for required in [
        "A whole-resource refutation is TERMINAL and attributes to nobody",
        "Standing in a vote over peer DECLARATIONS for that missing evidence is FORBIDDEN",
        "#1670 is OPEN",
        "Adoption ORDER (MUST be discovery's order)",
        "MUST NEVER PROMOTE one on a declaration",
        "MUST NOT outrank one that declares something",
    ] {
        assert!(
            normative.contains(required),
            "SPEC.md no longer states: {required:?} — the ordering requirement or one of the forbidden \
             designs has been dropped from the normative text"
        );
    }
}
