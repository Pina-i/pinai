use crate::{UserId, ValidationError};

use super::ActorUri;

/// A local account, as other contexts see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub id: UserId,
    pub actor_uri: ActorUri,
    pub username: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

/// An account on another instance, as far as this one knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteActor {
    pub actor_uri: ActorUri,
    pub inbox: url::Url,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

impl RemoteActor {
    /// A peer's inbox URL as this instance stores it: `http(s)`, held to an actor URI's 2 KiB, as
    /// every writer stores what a peer hands it.
    pub fn parse_inbox(raw: &str) -> Result<url::Url, ValidationError> {
        let refuse = || ValidationError::new("inbox", "an http(s) URL of 2 KiB at most");
        let url = url::Url::parse(raw).map_err(|_| refuse())?;
        if matches!(url.scheme(), "http" | "https") && url.as_str().len() <= ActorUri::MAX_BYTES {
            Ok(url)
        } else {
            Err(refuse())
        }
    }
}

#[cfg(test)]
mod tests;
