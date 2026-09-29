use std::sync::Arc;

use domain::identity::{Account, Accounts, ActorUri, RemoteActors};
use domain::social::{FriendPresence, FriendshipEvent, SocialError, SocialGraph, SocialNotifier};
use domain::{ConversationId, UserId};

use super::names::name_of;

/// An inbound `Accept`: a remote actor accepted the inbox owner's request. Keyed on the inbox it
/// reached, never on the activity's content; a redelivered Accept changes nothing.
pub struct ReceiveAccept {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    graph: Arc<dyn SocialGraph>,
    notifier: Arc<dyn SocialNotifier>,
    presence: Arc<dyn FriendPresence>,
}

impl ReceiveAccept {
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

    /// `advertised`: the DM id the accepter's instance chose, so both file it the same way.
    pub async fn execute(
        &self,
        owner: UserId,
        accepter: ActorUri,
        advertised: Option<ConversationId>,
    ) -> Result<(), SocialError> {
        let owner = self.owner(owner).await?;
        let Some((side, dm)) = self
            .graph
            .accept_outgoing(&owner, &accepter, advertised)
            .await?
        else {
            return Ok(());
        };
        let (username, display_name) =
            name_of(&*self.accounts, &*self.remote_actors, &accepter).await?;
        self.notifier.friend_accepted(
            owner.id,
            &FriendshipEvent {
                friendship: side.id,
                actor_uri: accepter.clone(),
                username,
                display_name,
                conversation: Some(dm),
            },
        );
        self.presence.watch(&accepter);
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
