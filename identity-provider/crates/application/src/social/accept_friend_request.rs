use std::sync::Arc;

use domain::identity::{Account, Accounts, RemoteActors};
use domain::profile::{ProfileFederation, Profiles};
use domain::social::{
    FriendPresence, FriendshipEvent, SocialError, SocialFederation, SocialGraph, SocialNotifier,
};
use domain::{FriendshipId, UserId};

use crate::profile::introduce;

/// `POST /api/friends/{id}/accept`: accept a request the caller received.
pub struct AcceptFriendRequest {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    graph: Arc<dyn SocialGraph>,
    notifier: Arc<dyn SocialNotifier>,
    federation: Arc<dyn SocialFederation>,
    presence: Arc<dyn FriendPresence>,
    profiles: Arc<dyn Profiles>,
    profile_federation: Arc<dyn ProfileFederation>,
}

impl AcceptFriendRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        graph: Arc<dyn SocialGraph>,
        notifier: Arc<dyn SocialNotifier>,
        federation: Arc<dyn SocialFederation>,
        presence: Arc<dyn FriendPresence>,
        profiles: Arc<dyn Profiles>,
        profile_federation: Arc<dyn ProfileFederation>,
    ) -> Self {
        Self {
            accounts,
            remote_actors,
            graph,
            notifier,
            federation,
            presence,
            profiles,
            profile_federation,
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
        let conversation = self.graph.accept(&request, &caller).await?;

        if let Some(requester) = self.accounts.find_by_uri(&request.friend).await? {
            self.notifier.friend_accepted(
                requester.id,
                &FriendshipEvent {
                    friendship: request.id,
                    actor_uri: caller.actor_uri.clone(),
                    username: caller.username.clone(),
                    display_name: caller.display_name.clone(),
                    conversation: Some(conversation),
                },
            );
        } else if let Some(requester) = self.remote_actors.find(&request.friend).await? {
            self.federation
                .send_accept(&caller, &requester, request.id, conversation);
            introduce(
                &*self.profiles,
                &*self.profile_federation,
                caller.id,
                &requester,
            )
            .await;
        }
        self.presence.watch(&request.friend);
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
