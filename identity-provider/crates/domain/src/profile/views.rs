use crate::UserId;
use crate::identity::{Account, ActorUri};

use super::{DisplayName, Pronouns};

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

/// What other accounts see of one — its name and avatar — and are told when either changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicProfile {
    pub actor: ActorUri,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

impl PublicProfile {
    /// The longest avatar URL taken from a peer.
    pub const MAX_AVATAR_URL: usize = 2048;

    /// What this instance takes of a peer's account: a name within the display-name rules, and
    /// an avatar at an http(s) URL — which every client of the account's friends then loads.
    /// Anything else is taken as not given.
    pub fn within_limits(self) -> Self {
        let display_name = self
            .display_name
            .and_then(|name| DisplayName::parse(&name).ok())
            .map(|name| name.as_str().to_owned());
        let avatar_url = self.avatar_url.filter(|url| is_web_url(url));
        Self {
            actor: self.actor,
            display_name,
            avatar_url,
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

impl From<&Account> for PublicProfile {
    fn from(account: &Account) -> Self {
        Self {
            actor: account.actor_uri.clone(),
            display_name: account.display_name.clone(),
            avatar_url: account.avatar_url.clone(),
        }
    }
}

#[cfg(test)]
mod tests;
