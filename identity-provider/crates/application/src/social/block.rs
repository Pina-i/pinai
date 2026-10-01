use std::sync::Arc;

use domain::identity::{Account, Accounts, ActorUri, RemoteActors};
use domain::social::{
    BlockedActor, Ending, FriendPresence, FriendshipEvent, SocialError, SocialFederation,
    SocialGraph, SocialNotifier, room_for,
};
use domain::{FriendshipId, UserId};

/// `POST /api/blocks`: block an actor. The friendship with them ends as an unfriend — or, for a
/// request they sent, a decline — would end it, and is announced the same way: a block is never
/// told to the blocked account, nor to its instance.
pub struct Block {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    graph: Arc<dyn SocialGraph>,
    notifier: Arc<dyn SocialNotifier>,
    federation: Arc<dyn SocialFederation>,
    presence: Arc<dyn FriendPresence>,
}

impl Block {
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

    pub async fn execute(&self, caller: UserId, actor: ActorUri) -> Result<(), SocialError> {
        let caller = self.accounts.find(caller).await?.ok_or_else(|| {
            SocialError::Unexpected(anyhow::anyhow!("the caller's account is gone"))
        })?;
        if actor == caller.actor_uri {
            return Err(SocialError::SelfBlock);
        }
        room_for(&self.graph.blocked(caller.id).await?, &actor)?;
        if let Some(ended) = self.graph.block(&caller, &actor).await? {
            let ending = Ending::of(&ended.removed);
            if let Some(local) = self.accounts.find_by_uri(&actor).await? {
                if let (Ending::Unfriend, Some(their_side)) = (ending, ended.reverse) {
                    self.notifier
                        .friend_removed(local.id, &removed(&caller, their_side.id));
                }
            } else if let Some(remote) = self.remote_actors.find(&actor).await? {
                match ending {
                    Ending::Unfriend => self.federation.send_undo_follow(&caller, &remote),
                    Ending::Decline => {
                        self.federation
                            .send_reject(&caller, &remote, ended.removed.id)
                    }
                }
            }
            // Presence is watched per instance: stop only once no local account befriends them.
            if !self.graph.befriended_by_anyone(&actor).await? {
                self.presence.release(&actor);
            }
        }
        self.notifier.blocks_updated(caller.id);
        Ok(())
    }
}

/// As `Unfriend` tells it: the other side refreshes, and learns nothing more.
fn removed(caller: &Account, their_side: FriendshipId) -> FriendshipEvent {
    FriendshipEvent {
        friendship: their_side,
        actor_uri: caller.actor_uri.clone(),
        username: caller.username.clone(),
        display_name: caller.display_name.clone(),
        conversation: None,
    }
}

/// `DELETE /api/blocks/{actor_uri}`: lift a block, and nothing else — the friendship it ended
/// stays ended.
pub struct Unblock {
    graph: Arc<dyn SocialGraph>,
    notifier: Arc<dyn SocialNotifier>,
}

impl Unblock {
    pub fn new(graph: Arc<dyn SocialGraph>, notifier: Arc<dyn SocialNotifier>) -> Self {
        Self { graph, notifier }
    }

    pub async fn execute(&self, caller: UserId, actor: ActorUri) -> Result<(), SocialError> {
        if !self.graph.unblock(caller, &actor).await? {
            return Err(SocialError::NotBlocked);
        }
        self.notifier.blocks_updated(caller);
        Ok(())
    }
}

/// `GET /api/blocks`.
pub struct ListBlocks {
    graph: Arc<dyn SocialGraph>,
}

impl ListBlocks {
    pub fn new(graph: Arc<dyn SocialGraph>) -> Self {
        Self { graph }
    }

    pub async fn execute(&self, caller: UserId) -> Result<Vec<BlockedActor>, SocialError> {
        Ok(self.graph.blocked(caller).await?)
    }
}

#[cfg(test)]
mod tests;
