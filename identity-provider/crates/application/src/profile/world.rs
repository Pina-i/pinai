//! The profile use cases over fakes, sharing them so tests can look behind each flow.

use std::sync::Arc;

use domain::identity::testing::{InMemoryAccounts, remote_actor};
use domain::identity::{InstanceOrigin, RemoteActor};
use domain::profile::OwnProfile;
use domain::profile::testing::{
    InMemoryAvatars, InMemoryProfiles, ProfileSeeds, RecordingProfileFederation,
    RecordingProfileNotifier, RecordingProfileRefresh, own_profile,
};
use domain::settings::testing::InMemorySettingsStore;
use domain::social::testing::InMemoryContactPolicies;
use time::OffsetDateTime;

use super::{ClearAvatar, EditProfile, ReadProfile, ReadUserinfo, ReceiveProfileUpdate, SetAvatar};

pub struct World {
    /// A local account with a friend here, `bob`, and one elsewhere, `carol`.
    pub alice: OwnProfile,
    pub bob: OwnProfile,
    pub carol: RemoteActor,
    pub origin: InstanceOrigin,
    pub profiles: Arc<InMemoryProfiles>,
    pub settings: Arc<InMemorySettingsStore>,
    pub contact_policies: Arc<InMemoryContactPolicies>,
    pub avatars: Arc<InMemoryAvatars>,
    pub notifier: Arc<RecordingProfileNotifier>,
    pub federation: Arc<RecordingProfileFederation>,
    pub refresh: Arc<RecordingProfileRefresh>,
}

pub fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

pub async fn world() -> World {
    let (alice, bob) = (own_profile("alice"), own_profile("bob"));
    let carol = remote_actor("carol_k2m9x@idp.carol.test");
    let profiles = Arc::new(InMemoryProfiles::default());
    profiles.sign_up(&alice).await;
    profiles.sign_up(&bob).await;
    profiles.remember(&carol).await;
    let alice_uri = alice.actor_uri.clone().unwrap();
    profiles.befriend(bob.id, &alice_uri, true, None).await;
    profiles
        .befriend(
            alice.id,
            &carol.actor_uri,
            true,
            Some("http://old/carol.png"),
        )
        .await;
    World {
        alice,
        bob,
        carol,
        origin: InstanceOrigin::parse("http://localhost:8080").unwrap(),
        profiles,
        settings: Arc::new(InMemorySettingsStore::default()),
        contact_policies: Arc::new(InMemoryContactPolicies::default()),
        avatars: Arc::new(InMemoryAvatars::default()),
        notifier: Arc::new(RecordingProfileNotifier::default()),
        federation: Arc::new(RecordingProfileFederation::default()),
        refresh: Arc::new(RecordingProfileRefresh::default()),
    }
}

impl World {
    pub fn read_userinfo(&self) -> ReadUserinfo {
        ReadUserinfo::new(
            self.origin.clone(),
            self.profiles.clone(),
            self.settings.clone(),
            self.contact_policies.clone(),
        )
    }

    pub fn edit_profile(&self) -> EditProfile {
        EditProfile::new(
            self.origin.clone(),
            self.profiles.clone(),
            self.settings.clone(),
            self.contact_policies.clone(),
            self.profiles.clone(),
            self.notifier.clone(),
            self.federation.clone(),
        )
    }

    pub fn set_avatar(&self) -> SetAvatar {
        SetAvatar::new(
            self.profiles.clone(),
            self.avatars.clone(),
            self.profiles.clone(),
            self.notifier.clone(),
            self.federation.clone(),
        )
    }

    pub fn clear_avatar(&self) -> ClearAvatar {
        ClearAvatar::new(
            self.profiles.clone(),
            self.avatars.clone(),
            self.profiles.clone(),
            self.notifier.clone(),
            self.federation.clone(),
        )
    }

    pub fn read_profile(&self) -> ReadProfile {
        let accounts = [&self.alice, &self.bob].map(|p| p.account().unwrap());
        ReadProfile::new(
            Arc::new(InMemoryAccounts::with(accounts)),
            self.profiles.clone(),
            self.refresh.clone(),
        )
    }

    pub fn receive_update(&self) -> ReceiveProfileUpdate {
        ReceiveProfileUpdate::new(
            self.origin.clone(),
            self.profiles.clone(),
            self.profiles.clone(),
            self.notifier.clone(),
        )
    }
}
