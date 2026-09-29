//! Token buckets per requester, in this process's memory: a burst up to the capacity, then a
//! steady rate.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

pub struct RateLimiter {
    capacity: f64,
    per_second: f64,
    buckets: Mutex<HashMap<String, Bucket>>,
}

struct Bucket {
    tokens: f64,
    refilled_at: Instant,
}

impl RateLimiter {
    pub fn new(capacity: u32, per_second: f64) -> Self {
        Self {
            capacity: f64::from(capacity),
            per_second,
            buckets: Mutex::default(),
        }
    }

    /// Whether `key` may go ahead now, spending one token if so.
    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap();
        let bucket = buckets.entry(key.to_owned()).or_insert(Bucket {
            tokens: self.capacity,
            refilled_at: now,
        });
        let elapsed = now
            .saturating_duration_since(bucket.refilled_at)
            .as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.per_second).min(self.capacity);
        bucket.refilled_at = now;
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }
}
