use std::sync::Arc;

use domain::UserId;
use domain::identity::{Account, Accounts, ActorUri, RemoteActors};
use domain::social::{
    FriendshipEvent, FriendshipStatus, SocialError, SocialFederation, SocialGraph, SocialNotifier,
};

/// An inbound `Follow`: someone asks the inbox owner to become friends. Peers deliver at least
/// once, so a redelivered Follow must change nothing.
pub struct ReceiveFollow {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    graph: Arc<dyn SocialGraph>,
    notifier: Arc<dyn SocialNotifier>,
    federation: Arc<dyn SocialFederation>,
}

impl ReceiveFollow {
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

    pub async fn execute(&self, recipient: UserId, follower: ActorUri) -> Result<(), SocialError> {
        let recipient = self.recipient(recipient).await?;

        if let Some(existing) = self.graph.between(recipient.id, &follower).await?
            && existing.status == FriendshipStatus::Accepted
        {
            // The peer still asks: it missed our Accept. Answer again rather than ignore it,
            // or its side stays pending forever. The friendship itself is left as it is.
            if let Some(remote) = self.remote_actors.find(&follower).await?
                && let Some(dm) = self
                    .graph
                    .dm_between(&recipient.actor_uri, &follower)
                    .await?
            {
                self.federation
                    .send_accept(&recipient, &remote, existing.id, dm);
            }
            return Ok(());
        }

        let (side, username, display_name) =
            if let Some(local) = self.accounts.find_by_uri(&follower).await? {
                let recorded = self.graph.record_local_request(&local, &recipient).await?;
                (recorded.target_side, local.username, local.display_name)
            } else {
                let remote = self.remote_actors.discover(&follower).await?;
                let side = self.graph.record_incoming(recipient.id, &follower).await?;
                let username = follower
                    .federated_address()
                    .map(|address| address.user().to_owned())
                    .unwrap_or_else(|| "unknown".to_owned());
                (side, username, remote.display_name)
            };
        self.notifier.friend_request(
            recipient.id,
            &FriendshipEvent {
                friendship: side.id,
                actor_uri: follower,
                username,
                display_name,
                conversation: None,
            },
        );
        Ok(())
    }

    async fn recipient(&self, id: UserId) -> Result<Account, SocialError> {
        self.accounts
            .find(id)
            .await?
            .ok_or_else(|| SocialError::Unexpected(anyhow::anyhow!("the inbox owner is gone")))
    }
}

#[cfg(test)]
mod tests;
