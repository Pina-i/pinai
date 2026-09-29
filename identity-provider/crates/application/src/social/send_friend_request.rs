use std::sync::Arc;

use domain::UserId;
use domain::identity::{Account, Accounts, Recipient, RemoteActors};
use domain::social::{
    Friendship, FriendshipEvent, SocialError, SocialFederation, SocialGraph, SocialNotifier,
};

/// `POST /api/friends/request`: ask a local or remote account to become friends.
pub struct SendFriendRequest {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    graph: Arc<dyn SocialGraph>,
    notifier: Arc<dyn SocialNotifier>,
    federation: Arc<dyn SocialFederation>,
}

impl SendFriendRequest {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        graph: Arc<dyn SocialGraph>,
        notifier: Arc<dyn SocialNotifier>,
        federation: Arc<dyn SocialFederation>,
    ) -> Self {
        Self {
            accounts,
            remote_actors,
            graph,
            notifier,
            federation,
        }
    }

    /// The caller's side of the request.
    pub async fn execute(&self, caller: UserId, to: Recipient) -> Result<Friendship, SocialError> {
        let caller = self.caller(caller).await?;
        match to {
            Recipient::Local(handle) => {
                let target = self
                    .accounts
                    .find_by_handle(&handle)
                    .await?
                    .ok_or(SocialError::UserNotFound)?;
                if target.id == caller.id {
                    return Err(SocialError::SelfRequest);
                }
                Friendship::requestable(
                    self.graph
                        .between(caller.id, &target.actor_uri)
                        .await?
                        .as_ref(),
                )?;
                let recorded = self.graph.record_local_request(&caller, &target).await?;
                self.notifier.friend_request(
                    target.id,
                    &FriendshipEvent {
                        friendship: recorded.target_side.id,
                        actor_uri: caller.actor_uri.clone(),
                        username: caller.username.clone(),
                        display_name: caller.display_name.clone(),
                        conversation: None,
                    },
                );
                Ok(recorded.requester_side)
            }
            Recipient::Remote(address) => {
                let remote = self.remote_actors.resolve(&address).await?;
                Friendship::requestable(
                    self.graph
                        .between(caller.id, &remote.actor_uri)
                        .await?
                        .as_ref(),
                )?;
                let side = self
                    .graph
                    .record_outgoing(caller.id, &remote.actor_uri, remote.avatar_url.as_deref())
                    .await?;
                // After the side is stored; delivery never fails the request.
                self.federation.send_follow(&caller, &remote);
                Ok(side)
            }
        }
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
