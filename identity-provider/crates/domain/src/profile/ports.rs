use crate::UserId;
use crate::identity::{Account, ActorUri, RemoteActor};

use super::{AvatarImage, ImageKind, OwnProfile, ProfileEdit, ProfileError, PublicProfile};

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

/// Tells a friend on another instance the account's name and avatar, in the background.
pub trait ProfileFederation: Send + Sync {
    fn send_update(&self, from: &Account, to: &RemoteActor);
}
