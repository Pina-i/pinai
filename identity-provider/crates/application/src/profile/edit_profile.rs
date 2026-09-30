use std::sync::Arc;

use domain::UserId;
use domain::identity::InstanceOrigin;
use domain::profile::{
    ProfileAudience, ProfileEdit, ProfileError, ProfileFederation, ProfileNotifier, Profiles,
};
use domain::settings::SettingsStore;

use super::{Friends, Userinfo, userinfo};

/// `PATCH /api/profile`: save the form, tell the friends, answer the account as it now is.
pub struct EditProfile {
    origin: InstanceOrigin,
    settings: Arc<dyn SettingsStore>,
    friends: Friends,
}

impl EditProfile {
    pub fn new(
        origin: InstanceOrigin,
        profiles: Arc<dyn Profiles>,
        settings: Arc<dyn SettingsStore>,
        audience: Arc<dyn ProfileAudience>,
        notifier: Arc<dyn ProfileNotifier>,
        federation: Arc<dyn ProfileFederation>,
    ) -> Self {
        Self {
            origin,
            settings,
            friends: Friends {
                profiles,
                audience,
                notifier,
                federation,
            },
        }
    }

    pub async fn execute(&self, user: UserId, edit: ProfileEdit) -> Result<Userinfo, ProfileError> {
        let edited = self
            .friends
            .profiles
            .edit(user, &edit)
            .await?
            .ok_or(ProfileError::UnknownUser)?;
        self.friends.tell(user).await;
        userinfo(&self.origin, self.settings.as_ref(), edited).await
    }
}

#[cfg(test)]
mod tests;
