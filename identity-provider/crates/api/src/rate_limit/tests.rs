use super::*;

#[test]
fn a_burst_is_allowed_then_the_steady_rate() {
    let limiter = RateLimiter::new(2, 0.0);

    let allowed: Vec<bool> = (0..3).map(|_| limiter.allow("alice")).collect();

    assert_eq!(allowed, vec![true, true, false]);
    assert!(limiter.allow("bob"));
}

#[test]
fn buckets_back_to_full_are_forgotten_once_there_are_many() {
    // Refilled at once: every bucket is full again by the next call.
    let limiter = RateLimiter::new(1, 1e9);

    for n in 0..=RateLimiter::MAX_KEYS {
        limiter.allow(&format!("key-{n}"));
    }

    assert!(limiter.buckets.lock().unwrap().len() < RateLimiter::MAX_KEYS);
}
