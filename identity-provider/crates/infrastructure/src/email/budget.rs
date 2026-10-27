//! A budget on the reset links mailed, whoever asks for them.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use domain::auth::{AuthError, ResetMail, ResetMailer};

/// Mails a reset link only within a budget for the whole instance: a burst, then one every so
/// often. A made-up address mails nothing, so only real ones spend it — each at most 5 an hour —,
/// and the relay's volume stays bounded whatever is asked. Past it, the send fails as any other.
pub struct ResetMailBudget {
    inner: Arc<dyn ResetMailer>,
    budget: Mutex<Budget>,
}

impl ResetMailBudget {
    /// 60 mails, then one every 6 seconds: 600 an hour.
    pub const BURST: u32 = 60;
    pub const EVERY: Duration = Duration::from_secs(6);

    pub fn new(inner: Arc<dyn ResetMailer>) -> Self {
        Self::with(inner, Self::BURST, Self::EVERY)
    }

    pub fn with(inner: Arc<dyn ResetMailer>, burst: u32, every: Duration) -> Self {
        Self {
            inner,
            budget: Mutex::new(Budget::full(burst, every, Instant::now())),
        }
    }
}

#[async_trait::async_trait]
impl ResetMailer for ResetMailBudget {
    async fn send_reset_link(&self, mail: &ResetMail) -> Result<(), AuthError> {
        if !self.budget.lock().unwrap().spend(Instant::now()) {
            return Err(AuthError::MailBudgetSpent);
        }
        self.inner.send_reset_link(mail).await
    }
}

/// A token bucket: `capacity` mails, one more every `every`.
struct Budget {
    capacity: f64,
    every: Duration,
    left: f64,
    at: Instant,
}

impl Budget {
    fn full(capacity: u32, every: Duration, now: Instant) -> Self {
        Self {
            capacity: f64::from(capacity),
            every,
            left: f64::from(capacity),
            at: now,
        }
    }

    /// Whether one mail may go `now`, spending it if so.
    fn spend(&mut self, now: Instant) -> bool {
        let refilled =
            now.saturating_duration_since(self.at).as_secs_f64() / self.every.as_secs_f64();
        self.left = (self.left + refilled).min(self.capacity);
        self.at = now;
        if self.left < 1.0 {
            return false;
        }
        self.left -= 1.0;
        true
    }
}

#[cfg(test)]
mod tests;
