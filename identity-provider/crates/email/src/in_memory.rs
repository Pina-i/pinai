//! Test-only EmailSender that records what would have been sent.
//!
//! Gated behind the `test-utils` feature so production binaries never link it.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::{EmailError, EmailSender};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentEmail {
    pub kind: &'static str,
    pub to: String,
    pub display_name: String,
    pub code: String,
}

#[derive(Default, Clone)]
pub struct InMemoryEmailSender {
    sent: Arc<Mutex<Vec<SentEmail>>>,
}

impl InMemoryEmailSender {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take everything sent so far and clear the buffer. Useful for asserting
    /// one specific email landed without bleed from a previous test.
    pub fn take_sent(&self) -> Vec<SentEmail> {
        std::mem::take(
            &mut *self
                .sent
                .lock()
                .expect("InMemoryEmailSender mutex poisoned"),
        )
    }

    pub fn peek_sent(&self) -> Vec<SentEmail> {
        self.sent
            .lock()
            .expect("InMemoryEmailSender mutex poisoned")
            .clone()
    }
}

#[async_trait]
impl EmailSender for InMemoryEmailSender {
    async fn send_signup_otp(
        &self,
        to: &str,
        display_name: &str,
        code: &str,
    ) -> Result<(), EmailError> {
        self.sent
            .lock()
            .expect("InMemoryEmailSender mutex poisoned")
            .push(SentEmail {
                kind: "signup_otp",
                to: to.to_string(),
                display_name: display_name.to_string(),
                code: code.to_string(),
            });
        Ok(())
    }
}

#[cfg(test)]
mod tests;
