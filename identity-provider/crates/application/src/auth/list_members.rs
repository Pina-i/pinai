use std::sync::Arc;

use domain::UserId;
use domain::auth::{AuthError, InstanceMembers, SignInAccounts};
use domain::presence::PresenceBoard;
use time::OffsetDateTime;

use super::require_admin;

/// A member as the admin panel shows them: by their display name only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedMember {
    pub id: UserId,
    pub display_name: Option<String>,
    pub admin: bool,
    pub last_active_at: Option<OffsetDateTime>,
    pub online: bool,
}

/// `GET /api/admin/members`: the accounts admitted or with their address confirmed, the most
/// recently active first, each online when this instance's presence board says it is around.
/// On open and invite-only instances alike.
pub struct ListMembers {
    accounts: Arc<dyn SignInAccounts>,
    members: Arc<dyn InstanceMembers>,
    board: Arc<PresenceBoard>,
}

impl ListMembers {
    pub fn new(
        accounts: Arc<dyn SignInAccounts>,
        members: Arc<dyn InstanceMembers>,
        board: Arc<PresenceBoard>,
    ) -> Self {
        Self {
            accounts,
            members,
            board,
        }
    }

    pub async fn execute(
        &self,
        caller: UserId,
        now: OffsetDateTime,
    ) -> Result<Vec<ListedMember>, AuthError> {
        require_admin(&*self.accounts, caller).await?;
        Ok(self
            .members
            .list(now)
            .await?
            .into_iter()
            .map(|member| ListedMember {
                online: member
                    .actor
                    .as_ref()
                    .is_some_and(|actor| self.board.state(actor).is_around()),
                id: member.id,
                display_name: member.display_name,
                admin: member.admin,
                last_active_at: member.last_active_at,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests;
