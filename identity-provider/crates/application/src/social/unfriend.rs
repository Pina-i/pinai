use std::sync::Arc;

use domain::UserId;
use domain::identity::{Account, Accounts, ActorUri, RemoteActors};
use domain::social::{
    FriendPresence, FriendshipEvent, SocialError, SocialFederation, SocialGraph, SocialNotifier,
};

/// `DELETE /api/friends/{actor_uri}`: end a friendship, or withdraw a request the caller sent.
/// The DM conversation is kept; the friend's clients only refresh, it is never announced.
pub struct Unfriend {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    graph: Arc<dyn SocialGraph>,
    notifier: Arc<dyn SocialNotifier>,
    federation: Arc<dyn SocialFederation>,
    presence: Arc<dyn FriendPresence>,
}

impl Unfriend {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        graph: Arc<dyn SocialGraph>,
        notifier: Arc<dyn SocialNotifier>,
        federation: Arc<dyn SocialFederation>,
        presence: Arc<dyn FriendPresence>,
    ) -> Self {
        Self {
            accounts,
            remote_actors,
            graph,
            notifier,
            federation,
            presence,
        }
    }

    pub async fn execute(&self, caller: UserId, friend: ActorUri) -> Result<(), SocialError> {
        let caller = self.caller(caller).await?;
        let unfriended = self
            .graph
            .unfriend(&caller, &friend)
            .await?
            .ok_or(SocialError::NotFriends)?;

        if let Some(local_friend) = self.accounts.find_by_uri(&friend).await? {
            if let Some(their_side) = unfriended.reverse {
                self.notifier.friend_removed(
                    local_friend.id,
                    &FriendshipEvent {
                        friendship: their_side.id,
                        actor_uri: caller.actor_uri.clone(),
                        username: caller.username.clone(),
                        display_name: caller.display_name.clone(),
                        conversation: None,
                    },
                );
            }
        } else if let Some(remote) = self.remote_actors.find(&friend).await? {
            self.federation.send_undo_follow(&caller, &remote);
        }
        // Presence is watched per instance: stop only once no local account befriends them.
        if !self.graph.befriended_by_anyone(&friend).await? {
            self.presence.release(&friend);
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
