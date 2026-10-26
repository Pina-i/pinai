use std::sync::Arc;

use domain::auth::{
    AuthError, INVITATION_TTL, InvitationToken, Invitations, OpenInvitation, SignInAccounts,
};
use domain::{InvitationId, UserId};
use time::OffsetDateTime;

use super::require_admin;

/// An invitation just made: its token is in no other answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedInvitation {
    pub id: InvitationId,
    pub token: InvitationToken,
    pub expires_at: OffsetDateTime,
}

/// `POST /api/admin/invitations`: an admin's single-use link, open for [`INVITATION_TTL`].
pub struct CreateInvitation {
    accounts: Arc<dyn SignInAccounts>,
    invitations: Arc<dyn Invitations>,
}

impl CreateInvitation {
    pub fn new(accounts: Arc<dyn SignInAccounts>, invitations: Arc<dyn Invitations>) -> Self {
        Self {
            accounts,
            invitations,
        }
    }

    pub async fn execute(
        &self,
        caller: UserId,
        now: OffsetDateTime,
    ) -> Result<CreatedInvitation, AuthError> {
        require_admin(&*self.accounts, caller).await?;
        let expires_at = now + INVITATION_TTL;
        let (id, token) = self.invitations.issue(caller, now, expires_at).await?;
        Ok(CreatedInvitation {
            id,
            token,
            expires_at,
        })
    }
}

/// `GET /api/admin/invitations`: the invitations still open, newest first. Used, expired and
/// revoked ones are not listed.
pub struct ListInvitations {
    accounts: Arc<dyn SignInAccounts>,
    invitations: Arc<dyn Invitations>,
}

impl ListInvitations {
    pub fn new(accounts: Arc<dyn SignInAccounts>, invitations: Arc<dyn Invitations>) -> Self {
        Self {
            accounts,
            invitations,
        }
    }

    pub async fn execute(
        &self,
        caller: UserId,
        now: OffsetDateTime,
    ) -> Result<Vec<OpenInvitation>, AuthError> {
        require_admin(&*self.accounts, caller).await?;
        self.invitations.list_open(now).await
    }
}

/// `DELETE /api/admin/invitations/{id}`: an open invitation stops letting anyone in.
pub struct RevokeInvitation {
    accounts: Arc<dyn SignInAccounts>,
    invitations: Arc<dyn Invitations>,
}

impl RevokeInvitation {
    pub fn new(accounts: Arc<dyn SignInAccounts>, invitations: Arc<dyn Invitations>) -> Self {
        Self {
            accounts,
            invitations,
        }
    }

    /// `invitation` is `None` when the request named none. `InvitationUnusable` for one that
    /// isn't open — used, revoked, expired or unknown —, but only once the caller is an admin.
    pub async fn execute(
        &self,
        caller: UserId,
        invitation: Option<InvitationId>,
        now: OffsetDateTime,
    ) -> Result<(), AuthError> {
        require_admin(&*self.accounts, caller).await?;
        let Some(invitation) = invitation else {
            return Err(AuthError::InvitationUnusable);
        };
        if !self.invitations.revoke(invitation, now).await? {
            return Err(AuthError::InvitationUnusable);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
