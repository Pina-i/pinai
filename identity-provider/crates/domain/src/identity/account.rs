use crate::UserId;

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
