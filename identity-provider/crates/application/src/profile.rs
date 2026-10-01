//! What an account shows of itself, and how a change reaches its friends — see
//! identity-provider/specs/01-identity-federation.md § 1.5 and § 2.

mod avatar;
mod edit_profile;
mod read_userinfo;
mod receive_profile_update;
#[cfg(test)]
mod world;

pub use avatar::{ClearAvatar, SetAvatar};
pub use edit_profile::EditProfile;
pub use read_userinfo::ReadUserinfo;
pub use receive_profile_update::ReceiveProfileUpdate;

use std::sync::Arc;

use domain::UserId;
use domain::identity::InstanceOrigin;
use domain::profile::{
    OwnProfile, ProfileAudience, ProfileError, ProfileFederation, ProfileNotifier, Profiles,
    PublicProfile,
};
use domain::settings::{SettingsDocument, SettingsStore};
use domain::social::{ContactPolicies, ContactPolicy};

/// `/userinfo`: the account as its owner sees it, how other accounts address it, its settings,
/// and who may reach it.
#[derive(Debug, Clone, PartialEq)]
pub struct Userinfo {
    pub profile: OwnProfile,
    /// `handle@domain`.
    pub address: String,
    pub actor_uri: String,
    pub settings: SettingsDocument,
    pub contact_policy: ContactPolicy,
}

pub(crate) async fn userinfo(
    origin: &InstanceOrigin,
    settings: &dyn SettingsStore,
    contact_policies: &dyn ContactPolicies,
    profile: OwnProfile,
) -> Result<Userinfo, ProfileError> {
    let address = format!("{}@{}", profile.username, origin.domain());
    let actor_uri = profile.actor_uri.as_ref().map_or_else(
        || format!("{}/users/{}", origin.base_url(), profile.username),
        |uri| uri.to_string(),
    );
    let settings = settings
        .load(profile.id)
        .await?
        .unwrap_or_else(SettingsDocument::empty);
    let contact_policy = contact_policies.get(profile.id).await?;
    Ok(Userinfo {
        profile,
        address,
        actor_uri,
        settings,
        contact_policy,
    })
}

/// Who is told of an account's name and avatar: its friends here, live, and those elsewhere by
/// an `Update{Person}`.
pub(crate) struct Friends {
    pub profiles: Arc<dyn Profiles>,
    pub audience: Arc<dyn ProfileAudience>,
    pub notifier: Arc<dyn ProfileNotifier>,
    pub federation: Arc<dyn ProfileFederation>,
}

impl Friends {
    /// Best effort: the change is saved whatever becomes of this, and a peer that missed it
    /// catches up with the next change, which carries the whole profile.
    pub(crate) async fn tell(&self, user: UserId) {
        if let Err(e) = self.try_tell(user).await {
            tracing::warn!(user_id = %user, error = ?e, "profile change not told to friends");
        }
    }

    async fn try_tell(&self, user: UserId) -> Result<(), ProfileError> {
        let Some(account) = self.profiles.find(user).await?.and_then(|p| p.account()) else {
            tracing::warn!(user_id = %user, "profile change: no actor URI to tell it under");
            return Ok(());
        };
        let shown = PublicProfile::from(&account);
        for friend in self.audience.friends_here(&account.actor_uri).await? {
            self.notifier.friend_profile_updated(friend, &shown);
        }
        for friend in self.audience.friends_elsewhere(user).await? {
            self.federation.send_update(&account, &friend);
        }
        Ok(())
    }
}
