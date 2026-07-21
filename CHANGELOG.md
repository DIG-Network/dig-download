# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.4.0] - 2026-07-21

### Features
- **dig-download:** Dig-dht 0.4 + full NAT dial ladder on content fetch (§5.3 fall-through) (#7)

## [0.3.0] - 2026-07-21

### Chores
- **deps:** Adopt dig-nat 0.8 + dig-dht 0.3 (cascade) + release 0.3.0 (#6)

## [0.2.1] - 2026-07-20

### Chores
- **deps:** Bump dig-nat to 0.7 (full NAT ladder unification, #836) (#5)

## [0.2.0] - 2026-07-20

### Features
- **deps:** Adopt dig-nat 0.6.0 (dig-tls CA-signed cert cutover) (#4)

## [0.1.3] - 2026-07-18

### Features
- **dig-download:** Bump to latest dig-nat 0.3 + dig-dht 0.1.3 (#947) (#3)

## [0.1.2] - 2026-07-17

### Bug Fixes
- **deps:** Resolve dig-nat 0.2 from crates.io (#2)

## [0.1.1] - 2026-07-12

### Bug Fixes
- **deps:** Re-resolve DIG git deps to rewritten (co-author/signed) revs

### CI
- Enforce version increment in PRs (package.json / Cargo.toml)- Enforce Conventional Commits with commitlint on PRs- Enforce Conventional Commits with commitlint on PRs- Release automation (git-cliff changelog + tag on merge); publish is manual workflow_dispatch (#230)- Re-arm crates.io auto-publish on version tag (token in org secrets; auto-publish-everything #230)- Add flaky-test management (#489) (#1)

### Chores
- **changelog:** Add git-cliff config for Conventional-Commit changelog


