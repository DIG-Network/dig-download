# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.15.0] - 2026-08-02

### Chores
- **deps:** Dig-nat 0.18 + dig-dht 0.11 + dig-peer 0.9 (#23)

## [0.14.0] - 2026-08-01

### Features
- **module:** Verify the module anchor from a reader, not a whole-module buffer (#22)

## [0.13.0] - 2026-07-31

### Chores
- **deps:** Bump dig-nat 0.15, dig-dht 0.9, dig-peer 0.8 together (#21)

## [0.12.0] - 2026-07-27

### Features
- Page-aware frame identity checks, named read failures, and the dig-nat 0.14 cascade (#20)

## [0.11.0] - 2026-07-27

### Chores
- **deps:** Adopt dig-nat 0.13 / dig-dht 0.7 / dig-peer 0.6 / dig-rpc-protocol 0.6 (#1656 level 3) (#19)

## [0.10.0] - 2026-07-26

### Features
- **dig-download:** Bind resumed reads to the chain root + promote only verified bytes (#18)

## [0.8.1] - 2026-07-26

### Chores
- **deps:** Bump dig-peer 0.4.1 -> 0.5.0 to collapse a ModuleInfo shape skew (#1576) (#17)

## [0.8.0] - 2026-07-26

### Features
- **dig-download:** ModuleDownloader — fail-closed whole-.dig peer pull (#1576) (#13)

## [0.7.4] - 2026-07-26

### Bug Fixes
- **source:** Clip an over-long range frame instead of erroring (#836) (#16)

## [0.7.3] - 2026-07-26

### Bug Fixes
- **source:** Parse provider host as IpAddr + try all candidates v6->v4 (#836) (#15)

## [0.7.2] - 2026-07-25

### Bug Fixes
- **orchestrator:** Name the failing step in NotFound + trace locate/probe (#1586) (#14)

## [0.7.1] - 2026-07-23

### Chores
- **deps:** Bump dig-nat 0.11 + dig-dht 0.5.1 + dig-peer 0.4.1 (#12)

## [0.7.0] - 2026-07-22

### Features
- **dig-download:** Adopt DigPeer transport + §5.3 read-ladder (#1283) (#11)

## [0.6.0] - 2026-07-22

### Chores
- **deps:** Adopt dig-nat 0.10 + dig-dht 0.5 (cascade #1494) — release 0.6.0 (#10)

## [0.5.1] - 2026-07-22

### CI
- **lockfile:** Gate Cargo.lock own-version + --locked in ci (#9)

## [0.5.0] - 2026-07-21

### Features
- **dig-download:** Active download optimizer + selector-agnostic seam (#1435 #1440) (#8)

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


