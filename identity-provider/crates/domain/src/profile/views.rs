use crate::UserId;
use crate::identity::{Account, ActorUri};

use super::{Bio, DisplayName, Pronouns};

/// A local account as its owner sees it: what `/userinfo` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnProfile {
    pub id: UserId,
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub totp_enabled: bool,
    /// `None` on an account older than actor URIs.
    pub actor_uri: Option<ActorUri>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub pronouns: Option<Pronouns>,
    pub bio: Option<String>,
}

impl OwnProfile {
    /// What other accounts see of it — `None` without an actor URI.
    pub fn public(&self) -> Option<PublicProfile> {
        Some(PublicProfile {
            actor: self.actor_uri.clone()?,
            display_name: self.display_name.clone(),
            avatar_url: self.avatar_url.clone(),
            pronouns: self.pronouns,
            bio: self.bio.clone(),
        })
    }

    /// The account as other accounts address it — `None` without an actor URI.
    pub fn account(&self) -> Option<Account> {
        Some(Account {
            id: self.id,
            actor_uri: self.actor_uri.clone()?,
            username: self.username.clone(),
            display_name: self.display_name.clone(),
            avatar_url: self.avatar_url.clone(),
        })
    }
}

/// What other accounts see of one — its name, avatar, pronouns and bio — and are told when any
/// of them changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicProfile {
    pub actor: ActorUri,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub pronouns: Option<Pronouns>,
    pub bio: Option<String>,
}

impl PublicProfile {
    /// The longest avatar URL taken from a peer.
    pub const MAX_AVATAR_URL: usize = 2048;

    /// What this instance takes of a peer's account: a name and a bio within the rules its own
    /// accounts follow, and an avatar at an http(s) URL — which every client of the account's
    /// friends then loads. Anything else is taken as not given.
    pub fn within_limits(self) -> Self {
        let display_name = self
            .display_name
            .and_then(|name| DisplayName::parse(&name).ok())
            .map(|name| name.as_str().to_owned());
        let avatar_url = self.avatar_url.filter(|url| is_web_url(url));
        let bio = self
            .bio
            .filter(|bio| !bio.trim().is_empty())
            .and_then(|bio| Bio::parse(&bio).ok())
            .map(|bio| bio.as_str().to_owned());
        Self {
            actor: self.actor,
            display_name,
            avatar_url,
            pronouns: self.pronouns,
            bio,
        }
    }
}

fn is_web_url(raw: &str) -> bool {
    raw.len() <= PublicProfile::MAX_AVATAR_URL
        && url::Url::parse(raw).is_ok_and(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some_and(|host| !host.is_empty())
        })
}

#[cfg(test)]
mod tests;
