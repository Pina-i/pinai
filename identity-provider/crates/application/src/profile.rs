//! What an account shows of itself, and how a change reaches its friends — see
//! identity-provider/specs/profile-and-settings.md § 1 and § 3.

mod avatar;
mod edit_profile;
mod read_profile;
mod read_userinfo;
mod receive_profile_update;
mod show_person;
#[cfg(test)]
mod world;

pub use avatar::{ClearAvatar, ServeAvatar, SetAvatar};
pub use edit_profile::EditProfile;
pub use read_profile::ReadProfile;
pub use read_userinfo::ReadUserinfo;
pub use receive_profile_update::ReceiveProfileUpdate;
pub use show_person::{Person, ShowPerson};

use std::sync::Arc;

use domain::UserId;
use domain::identity::{Account, InstanceOrigin, RemoteActor};
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
        let Some((account, shown)) = shown(&*self.profiles, user).await? else {
            tracing::warn!(user_id = %user, "profile change: no actor URI to tell it under");
            return Ok(());
        };
        for friend in self.audience.friends_here(&account.actor_uri).await? {
            self.notifier.friend_profile_updated(friend, &shown);
        }
        for friend in self.audience.friends_elsewhere(user).await? {
            self.federation.send_update(&account, &shown, &friend);
        }
        Ok(())
    }
}

/// The account and the profile it shows; `None` without an actor URI to show it under.
async fn shown(
    profiles: &dyn Profiles,
    user: UserId,
) -> Result<Option<(Account, PublicProfile)>, ProfileError> {
    let own = profiles.find(user).await?;
    Ok(own.and_then(|p| Some((p.account()?, p.public()?))))
}

/// Sends `user`'s profile to a friend just made elsewhere, whose instance only heard it while the
/// request was pending. Best effort, like `Friends::tell`.
pub(crate) async fn introduce(
    profiles: &dyn Profiles,
    federation: &dyn ProfileFederation,
    user: UserId,
    friend: &RemoteActor,
) {
    match shown(profiles, user).await {
        Ok(Some((account, profile))) => federation.send_update(&account, &profile, friend),
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(user_id = %user, error = ?e, "profile not sent to a new friend");
        }
    }
}
