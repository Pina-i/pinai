use std::sync::Arc;

use domain::identity::{Accounts, ActorUri, RemoteActors};
use domain::social::{SocialError, SocialGraph};
use domain::{FriendshipId, UserId};

use super::names::name_of;

/// A request the caller received and may answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingRequest {
    pub friendship: FriendshipId,
    pub actor_uri: ActorUri,
    pub username: String,
    pub display_name: Option<String>,
}

/// `GET /api/friends/incoming`.
pub struct ListIncomingRequests {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    graph: Arc<dyn SocialGraph>,
}

impl ListIncomingRequests {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        graph: Arc<dyn SocialGraph>,
    ) -> Self {
        Self {
            accounts,
            remote_actors,
            graph,
        }
    }

    pub async fn execute(&self, owner: UserId) -> Result<Vec<IncomingRequest>, SocialError> {
        let mut incoming = Vec::new();
        for side in self.graph.incoming_requests(owner).await? {
            let (username, display_name) =
                name_of(&*self.accounts, &*self.remote_actors, &side.friend).await?;
            incoming.push(IncomingRequest {
                friendship: side.id,
                actor_uri: side.friend,
                username,
                display_name,
            });
        }
        Ok(incoming)
    }
}

#[cfg(test)]
mod tests;
