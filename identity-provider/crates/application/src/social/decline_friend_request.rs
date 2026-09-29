use std::sync::Arc;

use domain::identity::{Account, Accounts, RemoteActors};
use domain::social::{SocialError, SocialFederation, SocialGraph};
use domain::{FriendshipId, UserId};

/// `DELETE /api/friends/{id}/reject`: decline a request the caller received. Never announced to
/// the requester — a declined request just stops existing.
pub struct DeclineFriendRequest {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    graph: Arc<dyn SocialGraph>,
    federation: Arc<dyn SocialFederation>,
}

impl DeclineFriendRequest {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        graph: Arc<dyn SocialGraph>,
        federation: Arc<dyn SocialFederation>,
    ) -> Self {
        Self {
            accounts,
            remote_actors,
            graph,
            federation,
        }
    }

    pub async fn execute(&self, caller: UserId, request: FriendshipId) -> Result<(), SocialError> {
        let request = self
            .graph
            .find(request)
            .await?
            .ok_or(SocialError::RequestNotFound)?;
        request.answerable_by(caller)?;
        let caller = self.caller(caller).await?;
        self.graph.decline(&request, &caller).await?;
        if self.accounts.find_by_uri(&request.friend).await?.is_none()
            && let Some(requester) = self.remote_actors.find(&request.friend).await?
        {
            self.federation.send_reject(&caller, &requester, request.id);
        }
        Ok(())
    }

    async fn caller(&self, id: UserId) -> Result<Account, SocialError> {
        self.accounts
            .find(id)
            .await?
            .ok_or_else(|| SocialError::Unexpected(anyhow::anyhow!("the caller's account is gone")))
    }
}

#[cfg(test)]
mod tests;
