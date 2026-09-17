//! Per-requester token-bucket rate limiter for the `claim` endpoint.
//!
//! Bucket capacity = `BURST`, refill rate = `RATE_PER_SEC`. Buckets live in
//! a process-local `DashMap` keyed by `Requester::rate_limit_key()`. The map
//! grows with unique requesters in any active window — bounded in practice
//! by the number of distinct peers + local users that hit `claim` at all.

use std::sync::OnceLock;
use std::time::Instant;

use dashmap::DashMap;

/// Refill rate in tokens per second. 60/min ⇒ 1/s.
const RATE_PER_SEC: f64 = 1.0;
/// Bucket capacity (a fresh bucket can serve up to this many immediate hits).
const BURST: f64 = 60.0;

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl Bucket {
    fn new() -> Self {
        Self {
            tokens: BURST,
            last_refill: Instant::now(),
        }
    }

    /// Add tokens proportional to elapsed time since the last refill,
    /// clamped at `BURST`.
    fn refill(&mut self, now: Instant) {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed * RATE_PER_SEC).min(BURST);
        self.last_refill = now;
    }
}

static BUCKETS: OnceLock<DashMap<String, Bucket>> = OnceLock::new();

fn buckets() -> &'static DashMap<String, Bucket> {
    BUCKETS.get_or_init(DashMap::new)
}

/// Try to consume one token for `key`. Returns `true` if the request may
/// proceed; `false` if the requester is rate-limited (`429` should follow).
pub fn try_consume(key: &str) -> bool {
    let now = Instant::now();
    let mut entry = buckets().entry(key.to_string()).or_insert_with(Bucket::new);
    entry.refill(now);
    if entry.tokens >= 1.0 {
        entry.tokens -= 1.0;
        true
    } else {
        false
    }
}
