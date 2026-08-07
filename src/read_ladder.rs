//! [`resolve_node`] — the client→node connection-order ladder (`CLAUDE.md` §5.3,
//! `dig-node/SPEC.md` §2.2).
//!
//! Any node-class client that must reach a DIG node — as opposed to a specific, already-known peer
//! (which dig-download reaches by `peer_id`-pinned [`PeerTarget`](dig_nat::PeerTarget) over the
//! `NatRangeTransport`) — resolves the node endpoint in this fixed order, taking the FIRST tier that
//! answers a cheap health probe within a short timeout:
//!
//! 1. an EXPLICITLY-CONFIGURED node — always wins, overriding the ladder entirely. Precedence among
//!    override sources (highest first): an explicit `--node` flag/argument > `$DIG_NODE_URL` > the
//!    persisted `node.url` config value.
//! 2. `dig.local` — the installed local node (the installer's hosts registration), probed as its
//!    PORTLESS `https://dig.local` (§4.1a `:443`) then the plaintext fail-soft `http://dig.local`
//!    (§4.1a `:80`).
//! 3. `localhost` — the loopback listener, probed as `http://localhost:9778` (`dig-node/SPEC.md`
//!    §4.1 — the loopback port is PLAINTEXT, not TLS), when `dig.local` does not respond.
//! 4. `rpc.dig.net` — the public gateway. FINAL fallback only.
//!
//! The resolved choice is cached for the invocation ([`CachedResolver`]) so a command that needs the
//! node endpoint more than once does not re-probe the ladder.
//!
//! ## Where this lives (#1283)
//!
//! The read-ladder is a fetch-client concern, so it lives here at L30 beside the rest of
//! dig-download's fetch surface (it was previously carried in the dig-store CLI). This module is pure
//! resolution + a [`HealthProbe`] trait seam — it holds NO transport of its own, so it stays
//! network-free and trivially unit-testable (the ladder's fall-through ORDER is proven over a scripted
//! probe). A consumer supplies the real probe; the optional [`HttpHealthProbe`] (feature `http-probe`)
//! is a ready-made `GET {base}/health` implementation.
//!
//! ## Transport note (§5.3)
//!
//! A node-class client (one holding a DIG identity key) is required to speak mTLS to every tier,
//! including `rpc.dig.net` (which is dual-mode: mTLS for node-class clients, plain HTTPS+CORS for
//! browsers). [`TransportMode`] is the seam that flips the probe/transport to mTLS once the gateway's
//! mTLS endpoint exists, without another change to the ladder logic itself.

use std::time::Duration;

// The §5.3 endpoint literals are canonical and live in ONE place — `dig-constants` (the ecosystem
// SSOT, #1283). dig-download re-exports them under the names its ladder + public API have always
// used, so there is a single source of truth for the values while downstream consumers see no
// source break (§5.1 additive):
//   RPC_DIG_NET             ← dig_constants::RPC_DIG_NET_URL  ("https://rpc.dig.net")
//   DIG_LOCAL_HOST          ← dig_constants::DIG_LOCAL_HOST   ("dig.local")
//   DEFAULT_LOCAL_NODE_PORT ← dig_constants::DIG_NODE_PORT    (9778)

/// The public gateway base URL — FINAL fallback tier, never the primary/hard-coded endpoint
/// (`CLAUDE.md` §5.3). Re-exported from the `dig-constants` SSOT.
pub use dig_constants::RPC_DIG_NET_URL as RPC_DIG_NET;

/// The installed local node's hosts-file registration (installer-managed). Re-exported from the
/// `dig-constants` SSOT.
pub use dig_constants::DIG_LOCAL_HOST;

/// A node's default loopback read port (`dig-node/SPEC.md` §1.1, canonical 9778). Re-exported from
/// the `dig-constants` SSOT (`DIG_NODE_PORT`).
pub use dig_constants::DIG_NODE_PORT as DEFAULT_LOCAL_NODE_PORT;

/// Default per-tier probe timeout: fast enough that a dead tier does not stall the caller, generous
/// enough for a loopback / local-LAN round trip under load.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_millis(600);

/// How the resolved endpoint was decided — surfaced for diagnostics so a caller can see WHY a given
/// node was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedTier {
    /// An explicit override was supplied (flag, env, or persisted config) — no probing occurred.
    Override,
    /// `dig.local` answered the health probe.
    DigLocal,
    /// `localhost` (loopback default port) answered the health probe.
    Localhost,
    /// Fell through to the public gateway (either it answered, or nothing else did and this is the
    /// final, un-probed fallback).
    PublicGateway,
}

/// The resolved node endpoint + how it was chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNode {
    /// Base URL, e.g. `https://dig.local` or `https://rpc.dig.net`.
    pub base_url: String,
    /// Which tier the endpoint came from.
    pub tier: ResolvedTier,
}

/// One local candidate the ladder probes before the public gateway: a fully-formed base URL paired
/// with the [`ResolvedTier`] it resolves to. The scheme/host/port are NOT uniform across rungs —
/// each rung targets a SPECIFIC `dig-node` listener (`dig-node/SPEC.md` §4.1/§4.1a), so it carries
/// its own complete URL rather than a shared scheme + a per-tier port (the defect fixed in #2164).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRung {
    /// The fully-formed base URL to probe, e.g. `https://dig.local` or `http://localhost:9778`.
    pub url: String,
    /// The tier this rung resolves to when it answers (`DigLocal` for the `dig.local` rungs,
    /// `Localhost` for the loopback rung).
    pub tier: ResolvedTier,
}

/// The transport a resolved node connection should use. Plain HTTPS is what every tier speaks today;
/// [`Mtls`](TransportMode::Mtls) is the seam for §5.3's node-class mTLS requirement, activated once the
/// gateway (and local node) mTLS endpoints exist. Kept as an explicit enum (not a bool) so a third
/// mode is not a breaking change later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportMode {
    /// Plain HTTPS (+ the existing §21.9 signed-request headers over the channel). Current behavior
    /// for all tiers, including `rpc.dig.net`.
    #[default]
    Https,
    /// mTLS with a client cert derived from the caller's DIG identity key
    /// (`peer_id = SHA-256(TLS SPKI DER)`), §21.9 signed-request authorization layered on top. NOT YET
    /// WIRED — it exists so callers/tests can express intent and so the flip to real mTLS is additive.
    Mtls,
}

/// Where an explicit node override came from, highest-precedence first. Purely informational
/// (surfaced in diagnostics); all three are otherwise equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideSource {
    /// `--node <url>` (or an equivalent constructor argument).
    Flag,
    /// `$DIG_NODE_URL`.
    Env,
    /// A persisted `node.url` config value.
    Config,
}

/// A cheap reachability probe for one candidate base URL. Implemented over real HTTP by the optional
/// [`HttpHealthProbe`] (feature `http-probe`); tests inject a deterministic fake so the ladder's
/// FALL-THROUGH ORDER is verified without a network.
#[async_trait::async_trait]
pub trait HealthProbe: Send + Sync {
    /// Return `true` if `base_url` answered a health check within `timeout`. MUST NOT panic or block
    /// past `timeout` — implementations race the check against the timeout themselves.
    async fn probe(&self, base_url: &str, timeout: Duration) -> bool;
}

/// Explicit override inputs, already extracted from their sources by the caller (a CLI flag,
/// `std::env::var`, or the persisted config file) so this module stays free of I/O and is trivially
/// unit-testable. Precedence: `flag` > `env_var` > `config_value`.
#[derive(Debug, Clone, Default)]
pub struct OverrideInputs {
    /// An explicit `--node <url>` flag/argument — highest precedence.
    pub flag: Option<String>,
    /// `$DIG_NODE_URL`.
    pub env_var: Option<String>,
    /// A persisted `node.url` config value — lowest precedence.
    pub config_value: Option<String>,
}

impl OverrideInputs {
    /// The highest-precedence override present, with its source tag.
    fn resolve(&self) -> Option<(&str, OverrideSource)> {
        if let Some(v) = self.flag.as_deref() {
            return Some((v, OverrideSource::Flag));
        }
        if let Some(v) = self.env_var.as_deref() {
            return Some((v, OverrideSource::Env));
        }
        if let Some(v) = self.config_value.as_deref() {
            return Some((v, OverrideSource::Config));
        }
        None
    }
}

/// Resolve the node endpoint per `CLAUDE.md` §5.3: override > `dig.local` > `localhost` >
/// `rpc.dig.net`, probing each non-override tier with `probe` and falling through on a
/// timeout/no-response. `rpc.dig.net` is the final fallback and is returned even if it does not itself
/// answer the probe (there is nowhere left to fall through to).
///
/// `local_rungs` are the fully-formed local candidates, in probe order, that come before the gateway
/// (callers build them once via [`local_urls`]); passing them in — rather than hardcoding a
/// scheme/host/port here — keeps this function transport-agnostic and lets callers vary the port.
/// Each rung carries the [`ResolvedTier`] it resolves to, because the ladder now has more rungs than
/// tiers (two `dig.local` schemes both map to `DigLocal`; see [`local_urls`]).
///
/// Panics-free; never fails — the public gateway is always a valid last resort.
pub async fn resolve_node(
    overrides: &OverrideInputs,
    local_rungs: &[LocalRung],
    probe: &dyn HealthProbe,
    timeout: Duration,
) -> ResolvedNode {
    if let Some((url, _source)) = overrides.resolve() {
        return ResolvedNode {
            base_url: url.trim_end_matches('/').to_string(),
            tier: ResolvedTier::Override,
        };
    }

    for rung in local_rungs {
        if probe.probe(&rung.url, timeout).await {
            return ResolvedNode {
                base_url: rung.url.trim_end_matches('/').to_string(),
                tier: rung.tier,
            };
        }
    }

    ResolvedNode {
        base_url: RPC_DIG_NET.to_string(),
        tier: ResolvedTier::PublicGateway,
    }
}

/// Build the ladder's local rungs, in probe order, each targeting a REAL `dig-node` listener
/// (`dig-node/SPEC.md` §4.1/§4.1a). The listeners are NOT uniform, so each rung carries its own
/// scheme/host/port — this is the crux of #2164, where a single `https://…:{port}` shape addressed
/// listeners that do not exist and the local tiers could never answer:
///
/// 1. `https://dig.local` — the installed local node's PORTLESS TLS listener (§4.1a, `:443`, gated on
///    a dig-cert leaf). Tried first.
/// 2. `http://dig.local` — the PORTLESS plaintext fail-soft (§4.1a, `:80`) for when the dig-cert TLS
///    leaf is not yet provisioned.
/// 3. `http://localhost:{port}` — the loopback listener (§4.1, default [`DEFAULT_LOCAL_NODE_PORT`]),
///    which is PLAINTEXT (not TLS), so it MUST be `http`, never `https`.
///
/// The `dig.local` rungs are portless (they hit `:443`/`:80`); only the loopback rung is port-bound.
/// `dig.local` (installer hosts entry) resolves IPv4-only to 127.0.0.2; the `localhost` rung uses
/// the hostname so the OS resolver prefers IPv6 (`[::1]`) with IPv4 fallback (`CLAUDE.md` §5.2).
#[must_use]
pub fn local_urls(port: u16) -> Vec<LocalRung> {
    vec![
        LocalRung {
            url: format!("https://{DIG_LOCAL_HOST}"),
            tier: ResolvedTier::DigLocal,
        },
        LocalRung {
            url: format!("http://{DIG_LOCAL_HOST}"),
            tier: ResolvedTier::DigLocal,
        },
        LocalRung {
            url: format!("http://localhost:{port}"),
            tier: ResolvedTier::Localhost,
        },
    ]
}

/// Which override source (if any) `overrides` would resolve to — used by diagnostics/tests that want
/// to assert precedence without running the async probe ladder.
#[must_use]
pub fn override_source(overrides: &OverrideInputs) -> Option<OverrideSource> {
    overrides.resolve().map(|(_, s)| s)
}

/// A per-invocation cache of the resolved node: probing is a network round trip, so a single command
/// that needs the node endpoint more than once resolves it ONCE. One resolution per instance is the
/// documented contract (`CLAUDE.md` §5.3 "cache the resolved choice for the invocation/session").
#[derive(Debug, Default)]
pub struct CachedResolver {
    cached: tokio::sync::OnceCell<ResolvedNode>,
}

impl CachedResolver {
    /// A fresh resolver with an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cached: tokio::sync::OnceCell::new(),
        }
    }

    /// Resolve once per instance; subsequent calls return the cached result without re-probing.
    pub async fn get_or_resolve(
        &self,
        overrides: &OverrideInputs,
        local_rungs: &[LocalRung],
        probe: &dyn HealthProbe,
        timeout: Duration,
    ) -> ResolvedNode {
        self.cached
            .get_or_init(|| resolve_node(overrides, local_rungs, probe, timeout))
            .await
            .clone()
    }
}

/// Production [`HealthProbe`] over HTTP (feature `http-probe`): `GET {base_url}/health`, racing the
/// request against `timeout` via `tokio::time::timeout` so a hung/unreachable tier can never stall the
/// ladder past the caller's patience. Any non-2xx status, a transport error, or an elapsed timeout is
/// treated as "not reachable" — the ladder falls through rather than surfacing a probe failure as a
/// hard error. Matches `dig-node`'s `GET /health` (`dig-node/SPEC.md` §1.1).
#[cfg(feature = "http-probe")]
pub struct HttpHealthProbe {
    http: reqwest::Client,
}

#[cfg(feature = "http-probe")]
impl HttpHealthProbe {
    /// A probe using the given HTTP client.
    #[must_use]
    pub fn new(http: reqwest::Client) -> Self {
        Self { http }
    }
}

#[cfg(feature = "http-probe")]
impl Default for HttpHealthProbe {
    /// A client tuned for a HEALTH probe: redirects disabled (a probe should not follow a redirect
    /// chain) and no client-level timeout — [`resolve_node`]'s caller-supplied `timeout` is the single
    /// source of truth, applied via `tokio::time::timeout` in [`probe`](HealthProbe::probe).
    fn default() -> Self {
        Self::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        )
    }
}

#[cfg(feature = "http-probe")]
#[async_trait::async_trait]
impl HealthProbe for HttpHealthProbe {
    async fn probe(&self, base_url: &str, timeout: Duration) -> bool {
        let url = format!("{}/health", base_url.trim_end_matches('/'));
        let request = self.http.get(&url).send();
        match tokio::time::timeout(timeout, request).await {
            Ok(Ok(resp)) => resp.status().is_success(),
            // Transport error (connection refused, DNS/TLS failure, …) or the timeout elapsed — both
            // mean "this tier did not respond".
            Ok(Err(_)) | Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// A scripted probe: answers `true`/`false` per exact URL from a fixed map, and records every URL
    /// it was asked about (in order) so tests can assert the ladder probed tiers in the right order and
    /// stopped at the first hit.
    #[derive(Default)]
    struct ScriptedProbe {
        answers: std::collections::HashMap<String, bool>,
        calls: Mutex<Vec<String>>,
    }

    impl ScriptedProbe {
        fn new(answers: &[(&str, bool)]) -> Self {
            Self {
                answers: answers.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl HealthProbe for ScriptedProbe {
        async fn probe(&self, base_url: &str, _timeout: Duration) -> bool {
            self.calls.lock().unwrap().push(base_url.to_string());
            self.answers.get(base_url).copied().unwrap_or(false)
        }
    }

    // The three local rungs in probe order (must match `local_urls`); see the SPEC-anchored
    // `local_rungs_target_real_dig_node_listeners` test below for WHY each targets a real listener.
    const DIG_LOCAL_HTTPS: &str = "https://dig.local";
    const DIG_LOCAL_HTTP: &str = "http://dig.local";
    const LOCALHOST_HTTP: &str = "http://localhost:9778";
    const T: Duration = Duration::from_millis(50);

    /// The ladder's local rungs at the default port — what a real caller passes to `resolve_node`.
    fn rungs() -> Vec<LocalRung> {
        local_urls(DEFAULT_LOCAL_NODE_PORT)
    }

    #[tokio::test]
    async fn prefers_dig_local_when_it_answers() {
        let probe = ScriptedProbe::new(&[(DIG_LOCAL_HTTPS, true), (LOCALHOST_HTTP, true)]);
        let resolved = resolve_node(&OverrideInputs::default(), &rungs(), &probe, T).await;
        assert_eq!(resolved.base_url, DIG_LOCAL_HTTPS);
        assert_eq!(resolved.tier, ResolvedTier::DigLocal);
        // Later rungs must NOT be probed once the first dig.local rung answered — first responder wins.
        assert_eq!(probe.calls(), vec![DIG_LOCAL_HTTPS.to_string()]);
    }

    #[tokio::test]
    async fn falls_soft_to_http_dig_local_when_https_is_unreachable() {
        // §4.1a fail-soft: the portless TLS listener is unprovisioned, the portless plaintext answers.
        let probe = ScriptedProbe::new(&[(DIG_LOCAL_HTTPS, false), (DIG_LOCAL_HTTP, true)]);
        let resolved = resolve_node(&OverrideInputs::default(), &rungs(), &probe, T).await;
        assert_eq!(resolved.base_url, DIG_LOCAL_HTTP);
        assert_eq!(resolved.tier, ResolvedTier::DigLocal);
        assert_eq!(
            probe.calls(),
            vec![DIG_LOCAL_HTTPS.to_string(), DIG_LOCAL_HTTP.to_string()]
        );
    }

    #[tokio::test]
    async fn falls_through_to_localhost_when_dig_local_is_unreachable() {
        let probe = ScriptedProbe::new(&[
            (DIG_LOCAL_HTTPS, false),
            (DIG_LOCAL_HTTP, false),
            (LOCALHOST_HTTP, true),
        ]);
        let resolved = resolve_node(&OverrideInputs::default(), &rungs(), &probe, T).await;
        assert_eq!(resolved.base_url, LOCALHOST_HTTP);
        assert_eq!(resolved.tier, ResolvedTier::Localhost);
        assert_eq!(
            probe.calls(),
            vec![
                DIG_LOCAL_HTTPS.to_string(),
                DIG_LOCAL_HTTP.to_string(),
                LOCALHOST_HTTP.to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn falls_through_to_public_gateway_as_final_fallback() {
        // No local rung answers — the gateway is returned un-probed as the last resort.
        let probe = ScriptedProbe::new(&[]);
        let resolved = resolve_node(&OverrideInputs::default(), &rungs(), &probe, T).await;
        assert_eq!(resolved.base_url, RPC_DIG_NET);
        assert_eq!(resolved.tier, ResolvedTier::PublicGateway);
    }

    /// A tier that never responds/times out falls through exactly like an explicit `false` — the probe
    /// contract is to return `false` on elapse, never to hang the ladder.
    #[tokio::test]
    async fn timeout_behaves_as_no_response_and_falls_through() {
        struct NeverRespondsProbe;
        #[async_trait::async_trait]
        impl HealthProbe for NeverRespondsProbe {
            async fn probe(&self, _base_url: &str, _timeout: Duration) -> bool {
                false
            }
        }
        let resolved = resolve_node(
            &OverrideInputs::default(),
            &rungs(),
            &NeverRespondsProbe,
            Duration::from_millis(5),
        )
        .await;
        assert_eq!(resolved.tier, ResolvedTier::PublicGateway);
    }

    #[tokio::test]
    async fn explicit_override_wins_without_probing_anything() {
        let probe = ScriptedProbe::new(&[(DIG_LOCAL_HTTPS, true), (LOCALHOST_HTTP, true)]);
        let overrides = OverrideInputs {
            flag: Some("https://custom.example:9999".to_string()),
            ..Default::default()
        };
        let resolved = resolve_node(&overrides, &rungs(), &probe, T).await;
        assert_eq!(resolved.base_url, "https://custom.example:9999");
        assert_eq!(resolved.tier, ResolvedTier::Override);
        // An override is trusted outright — the ladder is never consulted.
        assert!(probe.calls().is_empty());
    }

    #[tokio::test]
    async fn override_trailing_slash_is_normalized() {
        let probe = ScriptedProbe::new(&[]);
        let overrides = OverrideInputs {
            flag: Some("https://custom.example/".to_string()),
            ..Default::default()
        };
        let resolved = resolve_node(&overrides, &rungs(), &probe, T).await;
        assert_eq!(resolved.base_url, "https://custom.example");
    }

    #[test]
    fn flag_wins_over_env_and_config() {
        let overrides = OverrideInputs {
            flag: Some("flag-url".into()),
            env_var: Some("env-url".into()),
            config_value: Some("config-url".into()),
        };
        assert_eq!(override_source(&overrides), Some(OverrideSource::Flag));
    }

    #[test]
    fn env_wins_over_config_when_no_flag() {
        let overrides = OverrideInputs {
            flag: None,
            env_var: Some("env-url".into()),
            config_value: Some("config-url".into()),
        };
        assert_eq!(override_source(&overrides), Some(OverrideSource::Env));
    }

    #[test]
    fn config_used_when_no_flag_or_env() {
        let overrides = OverrideInputs {
            config_value: Some("config-url".into()),
            ..Default::default()
        };
        assert_eq!(override_source(&overrides), Some(OverrideSource::Config));
    }

    #[test]
    fn no_override_when_all_absent() {
        assert_eq!(override_source(&OverrideInputs::default()), None);
    }

    /// Regression for #2164: each local rung MUST address a listener `dig-node` actually serves, so
    /// this asserts the DECOMPOSED (scheme, host, port, tier) of every rung against the `dig-node`
    /// listener table AS DATA — not against a re-spelled copy of `local_urls`' own `format!` output.
    /// A future `dig-node/SPEC.md` listener change should therefore break this test rather than let
    /// the ladder silently diverge back to unreachable URLs.
    #[test]
    fn local_rungs_target_real_dig_node_listeners() {
        /// A rung's structural shape + the tier it resolves to.
        struct Listener {
            scheme: &'static str,
            host: &'static str,
            port: Option<u16>,
            tier: ResolvedTier,
        }

        // `dig-node/SPEC.md` §4.1/§4.1a — the listeners a local node exposes, in ladder probe order:
        //   §4.1a  https://dig.local       PORTLESS :443, gated on the dig-cert leaf   -> DigLocal
        //   §4.1a  http://dig.local        PORTLESS :80, plaintext fail-soft           -> DigLocal
        //   §4.1   http://localhost:9778   loopback, PLAINTEXT (not TLS)               -> Localhost
        let expected = [
            Listener {
                scheme: "https",
                host: "dig.local",
                port: None,
                tier: ResolvedTier::DigLocal,
            },
            Listener {
                scheme: "http",
                host: "dig.local",
                port: None,
                tier: ResolvedTier::DigLocal,
            },
            Listener {
                scheme: "http",
                host: "localhost",
                port: Some(9778),
                tier: ResolvedTier::Localhost,
            },
        ];

        // Decompose `scheme://host[:port]` into its parts so the assertion is structural, not a
        // string re-spelling of the builder.
        fn decompose(url: &str) -> (&str, &str, Option<u16>) {
            let (scheme, rest) = url.split_once("://").expect("rung URL has a scheme");
            match rest.split_once(':') {
                Some((host, port)) => (scheme, host, Some(port.parse().expect("numeric port"))),
                None => (scheme, rest, None),
            }
        }

        let rungs = local_urls(DEFAULT_LOCAL_NODE_PORT);
        assert_eq!(rungs.len(), expected.len(), "one rung per SPEC listener");
        for (rung, want) in rungs.iter().zip(expected.iter()) {
            let (scheme, host, port) = decompose(&rung.url);
            assert_eq!(scheme, want.scheme, "scheme for {}", rung.url);
            assert_eq!(host, want.host, "host for {}", rung.url);
            assert_eq!(port, want.port, "port for {}", rung.url);
            assert_eq!(rung.tier, want.tier, "tier for {}", rung.url);
        }
    }

    #[tokio::test]
    async fn cached_resolver_probes_only_once() {
        struct CountingProbe {
            calls: AtomicUsize,
        }
        #[async_trait::async_trait]
        impl HealthProbe for CountingProbe {
            async fn probe(&self, _base_url: &str, _timeout: Duration) -> bool {
                self.calls.fetch_add(1, Ordering::SeqCst);
                true
            }
        }
        let probe = CountingProbe {
            calls: AtomicUsize::new(0),
        };
        let cache = CachedResolver::new();
        let overrides = OverrideInputs::default();

        let first = cache.get_or_resolve(&overrides, &rungs(), &probe, T).await;
        let second = cache.get_or_resolve(&overrides, &rungs(), &probe, T).await;

        assert_eq!(first, second);
        assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn default_transport_is_https() {
        assert_eq!(TransportMode::default(), TransportMode::Https);
    }
}
