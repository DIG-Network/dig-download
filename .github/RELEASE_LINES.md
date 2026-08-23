# Maintained release lines

`dig-download` ships from more than one line at a time. This file is the authoritative list of which
lines are live, why, and what a change to `main` owes them.

| Line | Branch | Status | Exists because |
|---|---|---|---|
| **0.20.x** | `main` | development line | current work, on the chia-0.36 transport stack |
| **0.19.x** | `release/0.19` | **maintenance** | `dig-node` pins `dig-download = "0.19"` (`dig-node-core/Cargo.toml`) and cannot take 0.20 until the chia-0.36 cascade lands (DIG-Network/dig_ecosystem#3152) |

## The obligation

**A fix that lands on `main` and matters to a pinned consumer must land on that consumer's line in the
same unit of work.** The 0.19 line is not an archive — it is the line the shipped node actually runs.

Two fixes have already reached 0.19 by hand-cherry-picking off an unmerged `backport/*` branch, and
the first of them (`0.19.1`) reached crates.io with **no tag and no PR**, so nothing in the repo said
which commit it was built from (#41). Nothing was keeping the lines in step; the only thing preventing
a missed backport was that someone happened to remember.

## What keeps them in step now

1. **`backport-gate.yml`** — a PR to `main` whose diff touches `src/` must carry exactly one of
   `backport:0.19` or `no-backport`. The gate is **driven by this table**: it only demands a decision
   for lines listed above whose branch actually exists, so retiring a line is a one-line edit here plus
   deleting the branch, and the gate retires itself.
2. **The PR template** restates the decision in prose, for the human writing the PR.

A checklist alone was rejected as the mechanism: the failure this is fixing *is* someone not
remembering, and a checklist is only read by someone who already remembers. The gate makes the
decision explicit and recorded, without deciding it for you — `no-backport` is always a legitimate
answer, and the label is the record of having made it.

## Cutting a release on a maintenance line

The same way `main` does, because `release.yml` fires on `release/**` as well:

1. Land the change on `release/0.19` (branch off it, PR into it) with the version bumped in
   `Cargo.toml`.
2. On push, `release.yml` regenerates `CHANGELOG.md`, commits it to **that branch**, and tags
   `vX.Y.Z` at that commit.
3. The tag fires `publish.yml`, which publishes to crates.io. It **skips** a version already on the
   index, so re-cutting or retroactively tagging a tag is a no-op rather than a red run.

**Never hand-push a tag.** A tag pushed outside the workflow — and a `GITHUB_TOKEN`-pushed tag in
particular — does not fire `publish.yml`, so the version silently never reaches crates.io.

**Verify the artifact, never the run conclusion:**

```bash
curl -sH 'User-Agent: dig-loop' https://index.crates.io/di/g-/dig-download
```

The `User-Agent` header is **required** — without it the index answers with something that reads
exactly like "not published".
