use time::Duration;

use crate::identity::{ActorUri, Handle};
use crate::{UserId, ValidationError};

use super::{AuthError, PasswordHash};

/// Codes mailed in this window count towards the limit: a mailbox is not flooded.
pub const RESEND_WINDOW: Duration = Duration::minutes(10);
pub const RESEND_LIMIT: usize = 5;
/// Guesses per code; after that a new one must be asked for.
pub const CODE_ATTEMPTS: i32 = 5;
/// An account never confirmed is deleted after a week, freeing its address.
pub const UNVERIFIED_TTL: Duration = Duration::days(7);
/// Spent codes and tickets are kept a day, then deleted.
pub const SPENT_RETENTION: Duration = Duration::hours(24);

/// An address mail can be sent to, kept lowercase: `Alice@Example.com` and `alice@example.com`
/// are one account.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Email(String);

impl Email {
    /// One `@` between two non-empty parts, no whitespace, at most 254 characters (RFC 5321).
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let email = raw.trim().to_lowercase();
        let well_formed = email.len() <= 254
            && !email.chars().any(|c| c.is_whitespace() || c.is_control())
            && email.split_once('@').is_some_and(|(local, domain)| {
                !local.is_empty() && !domain.is_empty() && !domain.contains('@')
            });
        if !well_formed {
            return Err(ValidationError::new(
                "email",
                "an address like name@example.com",
            ));
        }
        Ok(Self(email))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An account as registering creates it: unconfirmed, without an authenticator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAccount {
    pub id: UserId,
    pub username: Handle,
    pub display_name: String,
    pub email: Email,
    pub password_hash: PasswordHash,
    pub actor_uri: ActorUri,
}

/// What the store made of a new account: the address and the handle are each one account's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registration {
    Created,
    EmailTaken,
    HandleTaken,
}

/// A code typed on the confirmation page, against the account's latest one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeAttempt {
    /// The right code: spent, and the address confirmed with it.
    Confirmed,
    Wrong {
        left: i32,
    },
    /// The latest code has had its guesses.
    Exhausted,
    /// No live code: none sent, expired, or retired by a newer one.
    NoCode,
    /// Spent by another request between reading it and spending it.
    AlreadyUsed,
}

/// A password of 8 bytes at least.
pub fn check_password(password: &str) -> Result<(), AuthError> {
    if password.len() < 8 {
        return Err(AuthError::PasswordTooShort);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
