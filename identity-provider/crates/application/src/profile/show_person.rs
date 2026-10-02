use std::sync::Arc;

use domain::identity::{Account, Accounts, ActorUri, InstanceOrigin};
use domain::profile::{ProfileError, Profiles, Pronouns};

/// An account as peers read it: how it is addressed, and the pronouns and bio it shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub account: Account,
    pub pronouns: Option<Pronouns>,
    pub bio: Option<String>,
}

/// `GET /users/{slug}`: the account's `Person`, the source a peer's cache refills from.
pub struct ShowPerson {
    origin: InstanceOrigin,
    accounts: Arc<dyn Accounts>,
    profiles: Arc<dyn Profiles>,
}

impl ShowPerson {
    pub fn new(
        origin: InstanceOrigin,
        accounts: Arc<dyn Accounts>,
        profiles: Arc<dyn Profiles>,
    ) -> Self {
        Self {
            origin,
            accounts,
            profiles,
        }
    }

    /// By the URI the slug makes, as `FindAccount` reaches it.
    pub async fn execute(&self, slug: &str) -> Result<Option<Person>, ProfileError> {
        let Ok(uri) = ActorUri::parse(&format!("{}/users/{slug}", self.origin.base_url())) else {
            return Ok(None);
        };
        let Some(account) = self
            .accounts
            .find_by_uri(&uri)
            .await
            .map_err(|e| ProfileError::Unexpected(e.into()))?
        else {
            return Ok(None);
        };
        let shown = self.profiles.find(account.id).await?;
        Ok(Some(Person {
            pronouns: shown.as_ref().and_then(|p| p.pronouns),
            bio: shown.and_then(|p| p.bio),
            account,
        }))
    }
}

#[cfg(test)]
mod tests;
