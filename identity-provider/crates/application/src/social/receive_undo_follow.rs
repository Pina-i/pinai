use std::sync::Arc;

use domain::UserId;
use domain::identity::{Account, Accounts, ActorUri, RemoteActors};
use domain::social::{FriendPresence, FriendshipEvent, SocialError, SocialGraph, SocialNotifier};

use super::names::name_of;

/// An inbound `Undo{Follow}`: a remote actor ended the friendship, or withdrew their request. The
/// owner's clients only refresh on it; a redelivered Undo changes nothing.
pub struct ReceiveUndoFollow {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    graph: Arc<dyn SocialGraph>,
    notifier: Arc<dyn SocialNotifier>,
    presence: Arc<dyn FriendPresence>,
}

impl ReceiveUndoFollow {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        graph: Arc<dyn SocialGraph>,
        notifier: Arc<dyn SocialNotifier>,
        presence: Arc<dyn FriendPresence>,
    ) -> Self {
        Self {
            accounts,
            remote_actors,
            graph,
            notifier,
            presence,
        }
    }

    pub async fn execute(&self, owner: UserId, follower: ActorUri) -> Result<(), SocialError> {
        let owner = self.owner(owner).await?;
        let Some(unfriended) = self.graph.unfriend(&owner, &follower).await? else {
            return Ok(());
        };
        let (username, display_name) =
            name_of(&*self.accounts, &*self.remote_actors, &follower).await?;
        self.notifier.friend_removed(
            owner.id,
            &FriendshipEvent {
                friendship: unfriended.removed.id,
                actor_uri: follower.clone(),
                username,
                display_name,
                conversation: None,
            },
        );
        if !self.graph.befriended_by_anyone(&follower).await? {
            self.presence.release(&follower);
        }
        Ok(())
    }

    async fn owner(&self, id: UserId) -> Result<Account, SocialError> {
        self.accounts
            .find(id)
            .await?
            .ok_or_else(|| SocialError::Unexpected(anyhow::anyhow!("the inbox owner is gone")))
    }
}

#[cfg(test)]
mod tests;
