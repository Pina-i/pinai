use crate::UserId;
use crate::identity::{Account, ActorUri, RemoteActor};

use super::{
    AvatarImage, CardFacts, ImageKind, OwnProfile, ProfileEdit, ProfileError, PublicProfile,
};

/// Local accounts' profiles, as their owners edit them.
#[async_trait::async_trait]
pub trait Profiles: Send + Sync {
    async fn find(&self, user: UserId) -> Result<Option<OwnProfile>, ProfileError>;
    /// Writes every field of the edit and answers the account as it now is; `None` when it is
    /// gone.
    async fn edit(
        &self,
        user: UserId,
        edit: &ProfileEdit,
    ) -> Result<Option<OwnProfile>, ProfileError>;
    /// The avatar the account shows, or none.
    async fn set_avatar(&self, user: UserId, url: Option<&str>) -> Result<(), ProfileError>;
}

/// What this instance keeps of other instances' accounts: the name and avatar it caches, and
/// the avatar each friendship with one keeps.
#[async_trait::async_trait]
pub trait PeerProfiles: Send + Sync {
    async fn record(&self, profile: &PublicProfile) -> Result<(), ProfileError>;
}

/// What the profile card reads of an account, for one viewer.
#[async_trait::async_trait]
pub trait ProfileCards: Send + Sync {
    /// `None` when the account is neither one of this instance's nor one it caches.
    async fn facts(
        &self,
        viewer: &Account,
        actor: &ActorUri,
    ) -> Result<Option<CardFacts>, ProfileError>;
}

/// Asks another instance for one of its accounts again, off the request that found it stale.
pub trait ProfileRefresh: Send + Sync {
    fn refresh(&self, actor: &ActorUri);
}

/// Who hears of an account's profile.
#[async_trait::async_trait]
pub trait ProfileAudience: Send + Sync {
    /// The local accounts that count `actor` among their friends.
    async fn friends_here(&self, actor: &ActorUri) -> Result<Vec<UserId>, ProfileError>;
    /// The friends `user` has on other instances.
    async fn friends_elsewhere(&self, user: UserId) -> Result<Vec<RemoteActor>, ProfileError>;
}

/// Where avatars are served from.
#[async_trait::async_trait]
pub trait AvatarStore: Send + Sync {
    /// Stores the account's image and answers the URL it is served at.
    async fn put(&self, user: UserId, image: &AvatarImage) -> Result<String, ProfileError>;
    /// Removes the account's images, but for the one of `keep`'s kind.
    async fn remove(&self, user: UserId, keep: Option<ImageKind>) -> Result<(), ProfileError>;
}

/// Tells a local account's live sessions that a friend's name or avatar changed.
pub trait ProfileNotifier: Send + Sync {
    fn friend_profile_updated(&self, to: UserId, profile: &PublicProfile);
}

/// Tells a friend on another instance the whole profile the account shows, in the background,
/// signed as the account.
pub trait ProfileFederation: Send + Sync {
    fn send_update(&self, from: &Account, profile: &PublicProfile, to: &RemoteActor);
}
