//! In-memory fakes of the profile ports and the contract every store must satisfy.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::UserId;
use crate::identity::testing::account;
use crate::identity::{Account, ActorUri, RemoteActor};

use super::{
    AvatarImage, AvatarStore, ImageKind, OwnProfile, PeerProfiles, ProfileAudience, ProfileEdit,
    ProfileError, ProfileFederation, ProfileNotifier, Profiles, PublicProfile,
};

/// A confirmed local account on `http://localhost:8080` showing its name only, as
/// `domain::identity::testing::account` makes it.
pub fn own_profile(name: &str) -> OwnProfile {
    let account = account(name);
    OwnProfile {
        id: account.id,
        email: format!("{name}@idp.test"),
        email_verified: true,
        totp_enabled: false,
        actor_uri: Some(account.actor_uri),
        username: account.username,
        display_name: account.display_name,
        avatar_url: None,
        pronouns: None,
        bio: None,
    }
}

/// Seeds what the profile stores read — accounts, remote actors and friendships are written by
/// other contexts — and shows what they keep of a remote actor.
#[async_trait::async_trait]
pub trait ProfileSeeds: Send + Sync {
    async fn sign_up(&self, profile: &OwnProfile);
    /// A remote actor this instance caches.
    async fn remember(&self, actor: &RemoteActor);
    /// `owner` counts `friend` among its friends — accepted, or only asked — keeping
    /// `avatar_url` for it.
    async fn befriend(
        &self,
        owner: UserId,
        friend: &ActorUri,
        accepted: bool,
        avatar_url: Option<&str>,
    );
    /// The name and avatar cached for `actor`, and the avatar each friendship with it keeps.
    async fn shown(&self, actor: &ActorUri) -> (Option<PublicProfile>, Vec<Option<String>>);
}

struct Friendship {
    owner: UserId,
    friend: ActorUri,
    accepted: bool,
    avatar_url: Option<String>,
}

#[derive(Default)]
struct World {
    accounts: Vec<OwnProfile>,
    remote: Vec<RemoteActor>,
    friendships: Vec<Friendship>,
}

/// The accounts, the remote actors and the friendships between them, behind every store port.
#[derive(Default)]
pub struct InMemoryProfiles {
    world: Mutex<World>,
    refusing_writes: AtomicBool,
}

impl InMemoryProfiles {
    /// Every edit of an account fails from now on.
    pub fn refuse_writes(&self) {
        self.refusing_writes.store(true, Ordering::SeqCst);
    }

    fn writable(&self) -> Result<(), ProfileError> {
        refused_if(&self.refusing_writes, "the account store refuses writes")
    }
}

fn refused_if(refusing: &AtomicBool, reason: &'static str) -> Result<(), ProfileError> {
    if refusing.load(Ordering::SeqCst) {
        return Err(ProfileError::Unexpected(anyhow::anyhow!(reason)));
    }
    Ok(())
}

#[async_trait::async_trait]
impl Profiles for InMemoryProfiles {
    async fn find(&self, user: UserId) -> Result<Option<OwnProfile>, ProfileError> {
        let world = self.world.lock().unwrap();
        Ok(world.accounts.iter().find(|a| a.id == user).cloned())
    }

    async fn edit(
        &self,
        user: UserId,
        edit: &ProfileEdit,
    ) -> Result<Option<OwnProfile>, ProfileError> {
        self.writable()?;
        let mut world = self.world.lock().unwrap();
        Ok(world
            .accounts
            .iter_mut()
            .find(|a| a.id == user)
            .map(|account| {
                account.display_name = Some(edit.display_name.as_str().to_owned());
                account.pronouns = edit.pronouns;
                account.bio = edit.bio.as_ref().map(|bio| bio.as_str().to_owned());
                account.clone()
            }))
    }

    async fn set_avatar(&self, user: UserId, url: Option<&str>) -> Result<(), ProfileError> {
        self.writable()?;
        let mut world = self.world.lock().unwrap();
        if let Some(account) = world.accounts.iter_mut().find(|a| a.id == user) {
            account.avatar_url = url.map(str::to_owned);
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl PeerProfiles for InMemoryProfiles {
    async fn record(&self, profile: &PublicProfile) -> Result<(), ProfileError> {
        let mut world = self.world.lock().unwrap();
        for actor in world
            .remote
            .iter_mut()
            .filter(|a| a.actor_uri == profile.actor)
        {
            actor.display_name = profile.display_name.clone();
            actor.avatar_url = profile.avatar_url.clone();
        }
        for friendship in world
            .friendships
            .iter_mut()
            .filter(|f| f.friend == profile.actor)
        {
            friendship.avatar_url = profile.avatar_url.clone();
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl ProfileAudience for InMemoryProfiles {
    async fn friends_here(&self, actor: &ActorUri) -> Result<Vec<UserId>, ProfileError> {
        let world = self.world.lock().unwrap();
        Ok(world
            .friendships
            .iter()
            .filter(|f| f.accepted && &f.friend == actor)
            .map(|f| f.owner)
            .collect())
    }

    async fn friends_elsewhere(&self, user: UserId) -> Result<Vec<RemoteActor>, ProfileError> {
        let world = self.world.lock().unwrap();
        Ok(world
            .friendships
            .iter()
            .filter(|f| f.accepted && f.owner == user)
            .filter_map(|f| world.remote.iter().find(|a| a.actor_uri == f.friend))
            .cloned()
            .collect())
    }
}

#[async_trait::async_trait]
impl ProfileSeeds for InMemoryProfiles {
    async fn sign_up(&self, profile: &OwnProfile) {
        self.world.lock().unwrap().accounts.push(profile.clone());
    }

    async fn remember(&self, actor: &RemoteActor) {
        self.world.lock().unwrap().remote.push(actor.clone());
    }

    async fn befriend(
        &self,
        owner: UserId,
        friend: &ActorUri,
        accepted: bool,
        avatar_url: Option<&str>,
    ) {
        self.world.lock().unwrap().friendships.push(Friendship {
            owner,
            friend: friend.clone(),
            accepted,
            avatar_url: avatar_url.map(str::to_owned),
        });
    }

    async fn shown(&self, actor: &ActorUri) -> (Option<PublicProfile>, Vec<Option<String>>) {
        let world = self.world.lock().unwrap();
        let cached = world
            .remote
            .iter()
            .find(|a| &a.actor_uri == actor)
            .map(|a| PublicProfile {
                actor: a.actor_uri.clone(),
                display_name: a.display_name.clone(),
                avatar_url: a.avatar_url.clone(),
            });
        let kept = world
            .friendships
            .iter()
            .filter(|f| &f.friend == actor)
            .map(|f| f.avatar_url.clone())
            .collect();
        (cached, kept)
    }
}

/// Serves each account's images by kind from `http://s3.test/avatars/`.
#[derive(Default)]
pub struct InMemoryAvatars {
    stored: Mutex<Vec<(UserId, ImageKind)>>,
    refusing_uploads: AtomicBool,
    refusing_removals: AtomicBool,
}

impl InMemoryAvatars {
    /// Every upload fails from now on.
    pub fn refuse_uploads(&self) {
        self.refusing_uploads.store(true, Ordering::SeqCst);
    }

    /// Every removal fails from now on.
    pub fn refuse_removals(&self) {
        self.refusing_removals.store(true, Ordering::SeqCst);
    }

    pub fn stored(&self, user: UserId) -> Vec<ImageKind> {
        let stored = self.stored.lock().unwrap();
        stored
            .iter()
            .filter(|(owner, _)| *owner == user)
            .map(|(_, kind)| *kind)
            .collect()
    }
}

#[async_trait::async_trait]
impl AvatarStore for InMemoryAvatars {
    async fn put(&self, user: UserId, image: &AvatarImage) -> Result<String, ProfileError> {
        refused_if(&self.refusing_uploads, "the avatar store refuses uploads")?;
        let kind = image.kind();
        let mut stored = self.stored.lock().unwrap();
        if !stored.contains(&(user, kind)) {
            stored.push((user, kind));
        }
        let extension = kind.mime().trim_start_matches("image/");
        Ok(format!("http://s3.test/avatars/{user}.{extension}"))
    }

    async fn remove(&self, user: UserId, keep: Option<ImageKind>) -> Result<(), ProfileError> {
        refused_if(&self.refusing_removals, "the avatar store refuses removals")?;
        self.stored
            .lock()
            .unwrap()
            .retain(|(owner, kind)| *owner != user || Some(*kind) == keep);
        Ok(())
    }
}

/// Records every notification, in order.
#[derive(Default)]
pub struct RecordingProfileNotifier {
    notified: Mutex<Vec<(UserId, PublicProfile)>>,
}

impl RecordingProfileNotifier {
    pub fn notified(&self) -> Vec<(UserId, PublicProfile)> {
        self.notified.lock().unwrap().clone()
    }
}

impl ProfileNotifier for RecordingProfileNotifier {
    fn friend_profile_updated(&self, to: UserId, profile: &PublicProfile) {
        self.notified.lock().unwrap().push((to, profile.clone()));
    }
}

/// Records every `Update{Person}` sent: the sender as it was, and the friend it went to.
#[derive(Default)]
pub struct RecordingProfileFederation {
    sent: Mutex<Vec<(Account, ActorUri)>>,
}

impl RecordingProfileFederation {
    pub fn sent(&self) -> Vec<(Account, ActorUri)> {
        self.sent.lock().unwrap().clone()
    }
}

impl ProfileFederation for RecordingProfileFederation {
    fn send_update(&self, from: &Account, to: &RemoteActor) {
        self.sent
            .lock()
            .unwrap()
            .push((from.clone(), to.actor_uri.clone()));
    }
}

/// What every profile store must do.
pub mod contract {
    use super::*;
    use crate::identity::testing::remote_actor;
    use crate::profile::Pronouns;

    pub async fn an_account_is_found_with_its_profile(
        profiles: &dyn Profiles,
        seeds: &dyn ProfileSeeds,
    ) {
        let alice = OwnProfile {
            avatar_url: Some("http://s3.test/avatars/alice.png?v=1".to_owned()),
            pronouns: Some(Pronouns::NonBinary),
            bio: Some("kia ora".to_owned()),
            totp_enabled: true,
            ..own_profile("alice")
        };
        let bob = OwnProfile {
            email_verified: false,
            display_name: None,
            ..own_profile("bob")
        };
        seeds.sign_up(&alice).await;
        seeds.sign_up(&bob).await;

        assert_eq!(profiles.find(alice.id).await.unwrap(), Some(alice));
        assert_eq!(profiles.find(bob.id).await.unwrap(), Some(bob));
        assert_eq!(profiles.find(UserId::generate()).await.unwrap(), None);
    }

    pub async fn an_edit_writes_every_field(profiles: &dyn Profiles, seeds: &dyn ProfileSeeds) {
        let alice = own_profile("alice");
        seeds.sign_up(&alice).await;
        let full = ProfileEdit::parse(Some("Aroha"), Some("she"), Some("kia ora")).unwrap();
        let bare = ProfileEdit::parse(Some("Aroha M."), None, None).unwrap();

        let edited = profiles.edit(alice.id, &full).await.unwrap();
        let cleared = profiles.edit(alice.id, &bare).await.unwrap();

        let expected = OwnProfile {
            display_name: Some("Aroha".to_owned()),
            pronouns: Some(Pronouns::She),
            bio: Some("kia ora".to_owned()),
            ..alice.clone()
        };
        assert_eq!(edited, Some(expected));
        let expected = OwnProfile {
            display_name: Some("Aroha M.".to_owned()),
            ..alice.clone()
        };
        assert_eq!(cleared.as_ref(), Some(&expected));
        assert_eq!(profiles.find(alice.id).await.unwrap(), cleared);
        assert_eq!(
            profiles.edit(UserId::generate(), &bare).await.unwrap(),
            None
        );
    }

    pub async fn an_avatar_is_shown_until_cleared(
        profiles: &dyn Profiles,
        seeds: &dyn ProfileSeeds,
    ) {
        let alice = own_profile("alice");
        seeds.sign_up(&alice).await;
        let url = "http://s3.test/avatars/alice.webp?v=2";

        profiles.set_avatar(alice.id, Some(url)).await.unwrap();
        let shown = profiles.find(alice.id).await.unwrap().unwrap();
        profiles.set_avatar(alice.id, None).await.unwrap();
        let cleared = profiles.find(alice.id).await.unwrap().unwrap();

        assert_eq!(shown.avatar_url.as_deref(), Some(url));
        assert_eq!(cleared.avatar_url, None);
    }

    pub async fn a_peers_profile_is_cached_and_kept_by_every_friendship_with_it(
        peers: &dyn PeerProfiles,
        seeds: &dyn ProfileSeeds,
    ) {
        let (alice, bob) = (own_profile("alice"), own_profile("bob"));
        let carol = remote_actor("carol_k2m9x@idp.carol.test");
        let dave = remote_actor("dave_k2m9x@idp.carol.test");
        for profile in [&alice, &bob] {
            seeds.sign_up(profile).await;
        }
        seeds.remember(&carol).await;
        seeds.remember(&dave).await;
        seeds
            .befriend(alice.id, &carol.actor_uri, true, Some("http://old/carol"))
            .await;
        seeds.befriend(bob.id, &carol.actor_uri, false, None).await;
        seeds
            .befriend(alice.id, &dave.actor_uri, true, Some("http://old/dave"))
            .await;
        let update = PublicProfile {
            actor: carol.actor_uri.clone(),
            display_name: Some("Carol R.".to_owned()),
            avatar_url: Some("http://idp.carol.test/avatars/carol.png?v=3".to_owned()),
        };

        peers.record(&update).await.unwrap();

        let (cached, kept) = seeds.shown(&carol.actor_uri).await;
        assert_eq!(cached, Some(update.clone()));
        assert_eq!(kept, vec![update.avatar_url.clone(); 2]);
        let (_, untouched) = seeds.shown(&dave.actor_uri).await;
        assert_eq!(untouched, vec![Some("http://old/dave".to_owned())]);
    }

    pub async fn an_actor_is_heard_of_by_the_accounts_that_befriended_it(
        audience: &dyn ProfileAudience,
        seeds: &dyn ProfileSeeds,
    ) {
        let (alice, bob) = (own_profile("alice"), own_profile("bob"));
        let carol = remote_actor("carol_k2m9x@idp.carol.test");
        for profile in [&alice, &bob] {
            seeds.sign_up(profile).await;
        }
        seeds.remember(&carol).await;
        seeds.befriend(alice.id, &carol.actor_uri, true, None).await;
        seeds.befriend(bob.id, &carol.actor_uri, false, None).await;

        let heard_by = audience.friends_here(&carol.actor_uri).await.unwrap();

        assert_eq!(heard_by, vec![alice.id]);
        let alice_uri = alice.actor_uri.clone().unwrap();
        assert!(audience.friends_here(&alice_uri).await.unwrap().is_empty());
    }

    pub async fn an_account_reaches_its_accepted_friends_on_other_instances(
        audience: &dyn ProfileAudience,
        seeds: &dyn ProfileSeeds,
    ) {
        let (alice, bob) = (own_profile("alice"), own_profile("bob"));
        let carol = remote_actor("carol_k2m9x@idp.carol.test");
        let dave = remote_actor("dave_k2m9x@idp.dave.test");
        for profile in [&alice, &bob] {
            seeds.sign_up(profile).await;
        }
        seeds.remember(&carol).await;
        seeds.remember(&dave).await;
        seeds.befriend(alice.id, &carol.actor_uri, true, None).await;
        seeds.befriend(alice.id, &dave.actor_uri, false, None).await;
        let bob_uri = bob.actor_uri.clone().unwrap();
        seeds.befriend(alice.id, &bob_uri, true, None).await;

        let reached = audience.friends_elsewhere(alice.id).await.unwrap();

        assert_eq!(reached, vec![carol]);
        assert!(audience.friends_elsewhere(bob.id).await.unwrap().is_empty());
    }
}

#[cfg(test)]
mod tests;
