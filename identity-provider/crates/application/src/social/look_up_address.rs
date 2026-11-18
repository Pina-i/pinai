use std::sync::Arc;

use domain::UserId;
use domain::identity::{Recipient, RemoteActors, RemoteActorsError};
use domain::social::{FoundPerson, PeopleSearch, SocialError};

/// `GET /api/users/lookup` — see identity-provider/specs/identity.md § 7.
pub struct LookUpAddress {
    people: Arc<dyn PeopleSearch>,
    remote_actors: Arc<dyn RemoteActors>,
}

impl LookUpAddress {
    pub fn new(people: Arc<dyn PeopleSearch>, remote_actors: Arc<dyn RemoteActors>) -> Self {
        Self {
            people,
            remote_actors,
        }
    }

    /// `None` when no account answers to the address. Another instance's is asked anew, never
    /// taken from the cache, and remembered.
    pub async fn execute(
        &self,
        caller: UserId,
        address: &Recipient,
    ) -> Result<Option<FoundPerson>, SocialError> {
        let address = match address {
            Recipient::Local(handle) => return Ok(self.people.local(caller, handle).await?),
            Recipient::Remote(address) => address,
        };
        let actor = match self.remote_actors.resolve(address).await {
            Ok(actor) => actor,
            Err(RemoteActorsError::NotFound) => return Ok(None),
            // To the person looking, an instance this one may not ask is one that can't be reached.
            Err(RemoteActorsError::Refused(reason)) => {
                return Err(SocialError::PeerUnavailable(reason));
            }
            Err(other) => return Err(other.into()),
        };
        let ties = self.people.ties(caller, &actor.actor_uri).await?;
        Ok(Some(FoundPerson {
            actor: actor.actor_uri,
            address: address.clone(),
            display_name: actor.display_name,
            avatar_url: actor.avatar_url,
            ties,
        }))
    }
}

#[cfg(test)]
mod tests;
