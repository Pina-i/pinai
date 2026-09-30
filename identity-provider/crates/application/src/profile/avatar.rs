use std::sync::Arc;

use domain::UserId;
use domain::profile::{
    AvatarImage, AvatarStore, ImageKind, ProfileAudience, ProfileError, ProfileFederation,
    ProfileNotifier, Profiles, published_url,
};
use time::OffsetDateTime;

use super::Friends;

/// `PUT /api/avatar`: store the image, show it, tell the friends; answers the published URL.
/// The old image goes only once the new one is shown: the account never points at a removed one.
pub struct SetAvatar {
    avatars: Arc<dyn AvatarStore>,
    friends: Friends,
}

impl SetAvatar {
    pub fn new(
        profiles: Arc<dyn Profiles>,
        avatars: Arc<dyn AvatarStore>,
        audience: Arc<dyn ProfileAudience>,
        notifier: Arc<dyn ProfileNotifier>,
        federation: Arc<dyn ProfileFederation>,
    ) -> Self {
        Self {
            avatars,
            friends: Friends {
                profiles,
                audience,
                notifier,
                federation,
            },
        }
    }

    pub async fn execute(
        &self,
        user: UserId,
        image: AvatarImage,
        now: OffsetDateTime,
    ) -> Result<String, ProfileError> {
        let stored = self.avatars.put(user, &image).await?;
        let url = published_url(&stored, now);
        self.friends.profiles.set_avatar(user, Some(&url)).await?;
        leave_only(self.avatars.as_ref(), user, Some(image.kind())).await;
        self.friends.tell(user).await;
        Ok(url)
    }
}

/// `DELETE /api/avatar`: the image goes once the account no longer shows it.
pub struct ClearAvatar {
    avatars: Arc<dyn AvatarStore>,
    friends: Friends,
}

impl ClearAvatar {
    pub fn new(
        profiles: Arc<dyn Profiles>,
        avatars: Arc<dyn AvatarStore>,
        audience: Arc<dyn ProfileAudience>,
        notifier: Arc<dyn ProfileNotifier>,
        federation: Arc<dyn ProfileFederation>,
    ) -> Self {
        Self {
            avatars,
            friends: Friends {
                profiles,
                audience,
                notifier,
                federation,
            },
        }
    }

    pub async fn execute(&self, user: UserId) -> Result<(), ProfileError> {
        self.friends.profiles.set_avatar(user, None).await?;
        leave_only(self.avatars.as_ref(), user, None).await;
        self.friends.tell(user).await;
        Ok(())
    }
}

/// An image left behind is shown nowhere, and the next upload removes it: not worth failing a
/// change already made.
async fn leave_only(avatars: &dyn AvatarStore, user: UserId, keep: Option<ImageKind>) {
    if let Err(e) = avatars.remove(user, keep).await {
        tracing::warn!(user_id = %user, error = ?e, "old avatar images not removed");
    }
}

#[cfg(test)]
mod tests;
