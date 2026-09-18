//! Outbound email transport for the IdP.
//!
//! Trait-based so the auth crate stays decoupled from `lettre`. Production wires
//! [`LettreSmtpSender`]; tests use [`InMemoryEmailSender`] (behind the
//! `test-utils` feature) to assert what would have been sent.

use async_trait::async_trait;
use thiserror::Error;

pub mod lettre_smtp;
pub mod template;

#[cfg(any(test, feature = "test-utils"))]
pub mod in_memory;

#[derive(Debug, Error)]
pub enum EmailError {
    #[error("smtp error: {0}")]
    Smtp(String),
    #[error("template error: {0}")]
    Template(String),
    #[error("invalid address: {0}")]
    Address(String),
}

/// All outbound mail flows through this trait. One method per template kind so
/// each call site is type-checked and templates stay colocated with their
/// rendering.
#[async_trait]
pub trait EmailSender: Send + Sync {
    /// Send the 6-digit signup confirmation OTP.
    async fn send_signup_otp(
        &self,
        to: &str,
        display_name: &str,
        code: &str,
    ) -> Result<(), EmailError>;
}

pub use lettre_smtp::{EmailConfig, LettreSmtpSender};

#[cfg(any(test, feature = "test-utils"))]
pub use in_memory::{InMemoryEmailSender, SentEmail};
