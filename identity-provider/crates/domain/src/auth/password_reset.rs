use time::{Duration, OffsetDateTime};

use crate::UserId;

use super::{AuthError, Session, SignInAccount, check_password};

/// How long a reset link lets its member set a new password.
pub const RESET_TTL: Duration = Duration::hours(24);
/// How long a reset link used, replaced or expired is kept before it is swept.
pub const RESET_RETENTION: Duration = Duration::days(30);

link_token!(
    /// The secret a reset link carries. Only its SHA-256 is kept.
    ResetToken,
    "reset link"
);

/// A reset link as the store keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordReset {
    /// The account whose password it sets.
    pub member: UserId,
    /// The admin who made it.
    pub created_by: UserId,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub used_at: Option<OffsetDateTime>,
    /// A newer link for the same account took its place.
    pub replaced_at: Option<OffsetDateTime>,
}

impl PasswordReset {
    /// It sets a password: unused, not replaced and unexpired.
    pub fn is_open(&self, now: OffsetDateTime) -> bool {
        self.used_at.is_none() && self.replaced_at.is_none() && now < self.expires_at
    }

    /// When it stopped working: used, replaced or expired, whichever came first.
    pub fn ended_at(&self) -> OffsetDateTime {
        [self.used_at, self.replaced_at]
            .into_iter()
            .flatten()
            .fold(self.expires_at, OffsetDateTime::min)
    }
}

/// An open reset link, as its page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenReset {
    pub member: UserId,
    /// The member's display name.
    pub display_name: Option<String>,
    pub expires_at: OffsetDateTime,
}

/// What the store made of a reset link presented with a new password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordChange {
    /// The password set and the link spent; the member's sessions it ended.
    Changed { member: UserId, ended: Vec<Session> },
    /// The link is not open: used — perhaps by another submission at the same moment —,
    /// replaced, expired or unknown. Nothing changed.
    LinkUnusable,
}

/// Who an admin may give a reset link: a member who is no admin. An account still to confirm its
/// address is no member yet, and is as unknown as one that doesn't exist; an admin recovers
/// through `ADMIN_EMAIL` and `ADMIN_PASSWORD` instead.
pub fn reset_target(account: Option<SignInAccount>) -> Result<SignInAccount, AuthError> {
    match account.filter(|account| !account.needs_code()) {
        None => Err(AuthError::UnknownUser),
        Some(account) if account.admin => Err(AuthError::AdminNotResettable),
        Some(account) => Ok(account),
    }
}

/// The password a reset link sets, within the instance's rule and typed the same twice.
#[derive(Clone, PartialEq, Eq)]
pub struct NewPassword(String);

impl NewPassword {
    pub fn parse(password: &str, confirmation: &str) -> Result<Self, AuthError> {
        check_password(password)?;
        if password != confirmation {
            return Err(AuthError::PasswordMismatch);
        }
        Ok(Self(password.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for NewPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NewPassword(..)")
    }
}

#[cfg(test)]
mod tests;
