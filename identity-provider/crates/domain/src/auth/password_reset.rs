use time::{Duration, OffsetDateTime};

use crate::UserId;
use crate::identity::InstanceOrigin;

use super::{AuthError, Session, SignInAccount, check_password};

/// How long a reset link an admin makes lets its member set a new password.
pub const RESET_TTL: Duration = Duration::hours(24);
/// How long a reset link asked for by mail works: it only has to cross a mailbox.
pub const REQUESTED_RESET_TTL: Duration = Duration::minutes(30);
/// The links an account asked for in this window count towards [`RESET_REQUEST_LIMIT`].
pub const RESET_REQUEST_WINDOW: Duration = Duration::hours(1);
/// At most this many links asked for in [`RESET_REQUEST_WINDOW`]: a mailbox is not flooded.
pub const RESET_REQUEST_LIMIT: usize = 5;
/// How long a reset link used, replaced or expired is kept before it is swept.
pub const RESET_RETENTION: Duration = Duration::days(30);

link_token!(
    /// The secret a reset link carries. Only its SHA-256 is kept.
    ResetToken,
    "reset link"
);

/// What a reset link's path starts with, its token following.
pub const RESET_PATH_PREFIX: &str = "/r/";

/// Where a reset link opens on the instance: its page, and what its form posts to.
pub fn reset_path(token: &ResetToken) -> String {
    format!("{RESET_PATH_PREFIX}{}", token.as_str())
}

/// The link itself, `{issuer}/r/{token}`: the one place its token is ever written.
pub fn reset_link(origin: &InstanceOrigin, token: &ResetToken) -> String {
    format!("{}{}", origin.base_url(), reset_path(token))
}

/// Whose hands a reset link went through on its way to the account. Either way, setting the
/// password with it signs nobody in: a link its owner forwards must not sign anyone into the
/// owner's account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetBy {
    /// An admin made it, and sent it however they liked.
    Admin,
    /// The account asked for it, and it was mailed to the account's own address.
    Mailbox,
}

/// A reset link as the store keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordReset {
    /// The account whose password it sets.
    pub member: UserId,
    /// The admin who made it; `None` when the account asked for it by mail.
    pub created_by: Option<UserId>,
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

    pub fn by(&self) -> ResetBy {
        match self.created_by {
            Some(_) => ResetBy::Admin,
            None => ResetBy::Mailbox,
        }
    }
}

/// An open reset link, as its page shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenReset {
    pub member: UserId,
    /// The member's display name.
    pub display_name: Option<String>,
    /// The member's address: a link through the mailbox went there, and its page names it.
    pub email: String,
    pub by: ResetBy,
    pub expires_at: OffsetDateTime,
}

impl std::fmt::Debug for OpenReset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenReset")
            .field("member", &self.member)
            .field("by", &self.by)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
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

/// Who a link asked for by mail goes to: the account with the address, confirmed or admitted —
/// admins included, the account and the address being theirs. Not one still to confirm its
/// address: it finishes signing up instead.
pub fn reset_requester(account: Option<SignInAccount>) -> Option<SignInAccount> {
    account.filter(|account| !account.needs_code())
}

/// Whether an account that asked for `asked` links in the last [`RESET_REQUEST_WINDOW`] gets
/// another.
pub fn may_request_reset(asked: usize) -> bool {
    asked < RESET_REQUEST_LIMIT
}

/// A reset link asked for by mail, as the mail carries it.
#[derive(Clone, PartialEq, Eq)]
pub struct ResetMail {
    pub to: String,
    /// What the mail calls the account.
    pub name: String,
    /// The instance's name.
    pub instance: String,
    /// `{issuer}/r/{token}`.
    pub link: String,
    pub valid_for: Duration,
}

impl std::fmt::Debug for ResetMail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResetMail")
            .field("instance", &self.instance)
            .field("valid_for", &self.valid_for)
            .finish_non_exhaustive()
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
