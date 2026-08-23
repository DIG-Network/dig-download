## What changed, and why

<!-- The behaviour, not the steps. Link the issue: `Closes #N`. -->

## Blast radius

<!-- Which symbols/flows this touches and how you checked (impact analysis, callers, consumers). -->

## How it was verified

<!-- A real result: a test run, a CI run id, a command output. Not "should work". -->

## Version bump

<!-- patch / minor / major, and why. Both Cargo.toml and package.json where both exist. -->

## Maintained release lines

`dig-download` ships a **0.19 maintenance line** alongside `main`, because `dig-node` is pinned to
`dig-download = "0.19"` — see [`.github/RELEASE_LINES.md`](./RELEASE_LINES.md).

If this PR touches `src/`, decide and label:

- [ ] **`backport:0.19`** — the 0.19 line needs this too. Open the companion PR against `release/0.19`
      and link it here.
- [ ] **`no-backport`** — the 0.19 line does not need it. Say in one line why (0.20-only code, a
      dependency the 0.19 line does not have, cosmetic).

`backport-gate.yml` enforces that exactly one of those labels is present. The label is the record that
the decision was *made*, not that it went a particular way.
