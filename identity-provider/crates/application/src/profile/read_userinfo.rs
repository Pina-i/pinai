use std::sync::Arc;

use domain::UserId;
use domain::identity::InstanceOrigin;
use domain::profile::{ProfileError, Profiles};
use domain::settings::SettingsStore;

use super::{Userinfo, userinfo};

/// `GET /userinfo`.
pub struct ReadUserinfo {
    origin: InstanceOrigin,
    profiles: Arc<dyn Profiles>,
    settings: Arc<dyn SettingsStore>,
}

impl ReadUserinfo {
    pub fn new(
        origin: InstanceOrigin,
        profiles: Arc<dyn Profiles>,
        settings: Arc<dyn SettingsStore>,
    ) -> Self {
        Self {
            origin,
            profiles,
            settings,
        }
    }

    pub async fn execute(&self, user: UserId) -> Result<Userinfo, ProfileError> {
        let profile = self
            .profiles
            .find(user)
            .await?
            .ok_or(ProfileError::UnknownUser)?;
        userinfo(&self.origin, self.settings.as_ref(), profile).await
    }
}

#[cfg(test)]
mod tests;
