//! [`FcfsRateLimiter`] — a first-come-first-serve token-bucket rate limiter for the **outbound serve
//! path** (#1435 req. 2): when this node serves capsule bytes to requesting peers, it caps the rate
//! so it never overwhelms a single peer or its own uplink.
//!
//! # Fairness contract (why FCFS, not "whoever grabs the lock")
//!
//! Requests are admitted in **arrival order** within the rate budget: a caller that asked first is
//! granted first, so a burst of large requests cannot starve a small request that arrived earlier.
//! This is enforced with a single arrival-ordered queue (a fair [`tokio::sync::Semaphore`] admits one
//! waiter at a time, in FIFO order) guarding the token bucket — so exactly one caller refills/consumes
//! at the head of the line, then hands off to the next arrival.
//!
//! Two independent caps compose (both must be satisfied before bytes flow):
//! - a **global** cap across all connections (protects this node's total uplink), and
//! - a **per-connection** cap keyed by an opaque connection key (protects any single peer from being
//!   flooded).
//!
//! A cap of `0` bytes/sec means **unlimited** for that dimension (the limiter is a no-op there).
//!
//! This is a reusable primitive; dig-node wires it into its `dig.fetchRange` serve handler
//! (`acquire(peer_key, frame_len)` before writing each frame). It is network-free and fully
//! unit-tested with tokio's paused clock.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, Semaphore};
use tokio::time::Instant;

/// A token bucket: `capacity`-bounded tokens refilling at `rate` bytes/sec. One byte = one token.
///
/// A `rate` of 0 disables the bucket (every acquire is instant). The bucket never holds more than one
/// second's worth of tokens (`capacity == rate`), so an idle limiter admits a short burst then settles
/// to the steady rate — the standard token-bucket smoothing.
#[derive(Debug)]
struct Bucket {
    rate: f64,
    capacity: f64,
    tokens: f64,
    last_refill: Instant,
}

impl Bucket {
    fn new(rate_bps: u64, now: Instant) -> Self {
        let rate = rate_bps as f64;
        Bucket {
            rate,
            capacity: rate,
            tokens: rate,
            last_refill: now,
        }
    }

    /// Refill tokens for the time elapsed since the last refill, capped at `capacity`.
    fn refill(&mut self, now: Instant) {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
            self.last_refill = now;
        }
    }

    /// The wait from `now` until `need` tokens are available (0 if already available or unlimited).
    fn wait_for(&mut self, need: f64, now: Instant) -> Duration {
        if self.rate <= 0.0 {
            return Duration::ZERO; // unlimited
        }
        self.refill(now);
        // A request larger than one second's capacity can never fill the bucket; wait only until the
        // bucket is FULL, then admit it (consuming drives the balance negative — repaid by the next
        // caller's wait). This keeps an oversized frame from deadlocking the limiter.
        let effective = need.min(self.capacity);
        if self.tokens >= effective {
            Duration::ZERO
        } else {
            Duration::from_secs_f64((effective - self.tokens) / self.rate)
        }
    }

    /// Consume `need` tokens (may drive the balance negative by at most one large request, which the
    /// next caller's wait repays — keeps a single request larger than `capacity` from deadlocking).
    fn consume(&mut self, need: f64) {
        if self.rate > 0.0 {
            self.tokens -= need;
        }
    }
}

/// A first-come-first-serve outbound rate limiter with a global cap and a per-connection cap.
///
/// Construct with [`new`](Self::new) and call [`acquire`](Self::acquire) before serving each chunk of
/// bytes on a connection; it returns once the byte budget allows, preserving arrival order.
#[derive(Debug)]
pub struct FcfsRateLimiter {
    /// FIFO admission gate: a fair semaphore admits waiters in arrival order, so the token math below
    /// happens strictly first-come-first-serve.
    gate: Semaphore,
    global: Mutex<Bucket>,
    per_conn: Mutex<HashMap<String, Bucket>>,
    per_conn_bps: u64,
}

impl FcfsRateLimiter {
    /// Build a limiter with a `global_bps` cap across all connections and a `per_conn_bps` cap per
    /// connection key. A cap of `0` means unlimited for that dimension (e.g. `new(0, 0)` is a no-op
    /// limiter). Rates are in **bytes per second**.
    pub fn new(global_bps: u64, per_conn_bps: u64) -> Arc<Self> {
        let now = Instant::now();
        Arc::new(FcfsRateLimiter {
            gate: Semaphore::new(1),
            global: Mutex::new(Bucket::new(global_bps, now)),
            per_conn: Mutex::new(HashMap::new()),
            per_conn_bps,
        })
    }

    /// Wait (in arrival order) until `bytes` may be served on connection `conn_key`, then consume the
    /// budget. Both the global and the per-connection cap must allow the bytes before this returns.
    ///
    /// Serving a chunk larger than a cap's one-second capacity is still admitted (it cannot be split
    /// here) but repays its debt against the following callers — so a single oversized frame never
    /// deadlocks the limiter.
    pub async fn acquire(&self, conn_key: &str, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let need = bytes as f64;
        // FIFO gate: exactly one caller computes+waits at the head of the queue at a time, so
        // admission is strictly first-come-first-serve (no lock-stampede reordering).
        let _permit = self
            .gate
            .acquire()
            .await
            .expect("rate-limiter gate never closed");

        loop {
            let now = Instant::now();
            let wait_global = self.global.lock().await.wait_for(need, now);
            let wait_conn = {
                let mut map = self.per_conn.lock().await;
                let bucket = map
                    .entry(conn_key.to_string())
                    .or_insert_with(|| Bucket::new(self.per_conn_bps, now));
                bucket.wait_for(need, now)
            };
            let wait = wait_global.max(wait_conn);
            if wait.is_zero() {
                self.global.lock().await.consume(need);
                if let Some(bucket) = self.per_conn.lock().await.get_mut(conn_key) {
                    bucket.consume(need);
                }
                return;
            }
            tokio::time::sleep(wait).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn unlimited_limiter_never_waits() {
        let rl = FcfsRateLimiter::new(0, 0);
        let start = Instant::now();
        for _ in 0..100 {
            rl.acquire("peer", 1_000_000).await;
        }
        assert_eq!(start.elapsed(), Duration::ZERO, "no cap → no wait");
    }

    #[tokio::test(start_paused = true)]
    async fn global_cap_paces_total_throughput() {
        // 1000 B/s global. The initial bucket holds 1000 tokens (one second's burst), so the first
        // 1000 bytes are instant; the next 1000 must wait ~1s for a refill.
        let rl = FcfsRateLimiter::new(1000, 0);
        let start = Instant::now();
        rl.acquire("a", 1000).await; // consumes the initial burst
        rl.acquire("a", 1000).await; // must wait ~1s
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(900),
            "second 1000B should wait ~1s for refill, waited {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn per_conn_cap_isolates_connections() {
        // Per-conn 1000 B/s, global unlimited. Exhaust peer A's burst; peer B is unaffected.
        let rl = FcfsRateLimiter::new(0, 1000);
        rl.acquire("A", 1000).await; // A's burst gone
        let start = Instant::now();
        rl.acquire("B", 1000).await; // B has its own fresh bucket → instant
        assert_eq!(start.elapsed(), Duration::ZERO, "B has an independent cap");
        // A must now wait for its own refill.
        let start_a = Instant::now();
        rl.acquire("A", 1000).await;
        assert!(start_a.elapsed() >= Duration::from_millis(900));
    }

    #[tokio::test(start_paused = true)]
    async fn fcfs_preserves_arrival_order() {
        // Three callers arrive in order 0,1,2 on the same tight cap; assert they COMPLETE in arrival
        // order (the fair gate admits FIFO). Each 1000B request paces at ~1s after the initial burst.
        let rl = FcfsRateLimiter::new(1000, 0);
        let order = Arc::new(Mutex::new(Vec::<u32>::new()));
        let mut handles = Vec::new();
        for i in 0..3u32 {
            let rl = rl.clone();
            let order = order.clone();
            // Stagger spawns so arrival order is deterministic (0 first).
            tokio::time::sleep(Duration::from_millis(1)).await;
            handles.push(tokio::spawn(async move {
                rl.acquire("peer", 1000).await;
                order.lock().await.push(i);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(
            *order.lock().await,
            vec![0, 1, 2],
            "served in arrival order"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn zero_bytes_is_instant_and_free() {
        let rl = FcfsRateLimiter::new(1, 1);
        let start = Instant::now();
        rl.acquire("peer", 0).await;
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn oversized_request_does_not_deadlock() {
        // A single request larger than the one-second capacity is admitted (it can't be split) and the
        // limiter recovers for the next caller rather than hanging forever.
        let rl = FcfsRateLimiter::new(1000, 0);
        rl.acquire("peer", 5000).await; // 5x capacity — admitted after its own wait
                                        // The bucket is now deeply negative; the next small request waits it off but completes.
        rl.acquire("peer", 10).await;
    }
}
