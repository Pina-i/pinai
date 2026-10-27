use std::sync::Arc;

use domain::UserId;
use domain::auth::{
    AuthError, NewPassword, PasswordChange, PasswordHasher, PasswordResets, RESET_TTL, ResetToken,
    SessionNotifier, SignInAccounts, WebApp, reset_target,
};
use domain::identity::InstanceOrigin;
use time::OffsetDateTime;

use super::{require_admin, tell_ended};

/// A reset link just made: its token is in no other answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedReset {
    pub member: UserId,
    pub token: ResetToken,
    pub expires_at: OffsetDateTime,
}

/// `POST /api/admin/members/{id}/password-reset`: an admin's single-use link that lets whoever
/// holds it set a member's password, open for [`RESET_TTL`]. It replaces the link the member had
/// open. On open and invite-only instances alike: it is how a member gets back in.
pub struct IssuePasswordReset {
    accounts: Arc<dyn SignInAccounts>,
    resets: Arc<dyn PasswordResets>,
}

impl IssuePasswordReset {
    pub fn new(accounts: Arc<dyn SignInAccounts>, resets: Arc<dyn PasswordResets>) -> Self {
        Self { accounts, resets }
    }

    /// `member` is `None` when the request named no account. `UnknownUser` for an account that
    /// doesn't exist or is still to confirm its address, `AdminNotResettable` for an admin — but only once the caller is an admin.
    pub async fn execute(
        &self,
        caller: UserId,
        member: Option<UserId>,
        now: OffsetDateTime,
    ) -> Result<IssuedReset, AuthError> {
        require_admin(&*self.accounts, caller).await?;
        let found = match member {
            Some(member) => self.accounts.by_id(member).await?,
            None => None,
        };
        let member = reset_target(found)?;
        let expires_at = now + RESET_TTL;
        let token = self
            .resets
            .issue(member.id, caller, now, expires_at)
            .await?;
        Ok(IssuedReset {
            member: member.id,
            token,
            expires_at,
        })
    }
}

/// `POST /r/{token}`: the member's new password. The link is spent, and every session of theirs
/// ends — its tokens, refresh tokens and sockets —, so each device signs in again with the new
/// password. A second factor stays on.
pub struct ResetPassword {
    origin: InstanceOrigin,
    web_app: Option<WebApp>,
    hasher: Arc<dyn PasswordHasher>,
    resets: Arc<dyn PasswordResets>,
    notifier: Arc<dyn SessionNotifier>,
}

impl ResetPassword {
    pub fn new(
        origin: InstanceOrigin,
        web_app: Option<WebApp>,
        hasher: Arc<dyn PasswordHasher>,
        resets: Arc<dyn PasswordResets>,
        notifier: Arc<dyn SessionNotifier>,
    ) -> Self {
        Self {
            origin,
            web_app,
            hasher,
            resets,
            notifier,
        }
    }

    /// Where the web app opens on this instance, when one is known: the member signs in there.
    pub fn web_app_entry(&self) -> Option<String> {
        self.web_app.as_ref().map(|app| app.entry(&self.origin))
    }

    /// The member whose password it set. `ResetUnusable` when the link is not open, or stops
    /// being so before the password is set.
    pub async fn execute(
        &self,
        token: &ResetToken,
        password: &str,
        confirmation: &str,
        now: OffsetDateTime,
    ) -> Result<UserId, AuthError> {
        // Before the costly hash: a made-up link costs nothing.
        if self.resets.find_open(token, now).await?.is_none() {
            return Err(AuthError::ResetUnusable);
        }
        let password = NewPassword::parse(password, confirmation)?;
        let hash = self.hasher.hash(password.as_str())?;
        match self.resets.reset(token, &hash, now).await? {
            PasswordChange::Changed { member, ended } => {
                tell_ended(&*self.notifier, &ended);
                Ok(member)
            }
            PasswordChange::LinkUnusable => Err(AuthError::ResetUnusable),
        }
    }
}

#[cfg(test)]
mod tests;
