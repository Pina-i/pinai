//! `Update{Person}`, delivered best-effort — see
//! identity-provider/specs/event-delivery.md § 2 — and a stale cached profile, asked for again.

use std::sync::Arc;

use activitypub::Activity;
use domain::identity::{Account, ActorUri, RemoteActor, RemoteActors};
use domain::profile::{ProfileFederation, ProfileRefresh, Pronouns, PublicProfile};
use federation_transport::UrlPolicy;
use jwt_utils::EdKeyPair;
use serde_json::Value;

use super::delivery::SignedDelivery;

/// Signs the profile the account shows as the account and posts it to the friend's inbox in the
/// background.
pub struct ApProfileFederation {
    delivery: SignedDelivery,
}

impl ApProfileFederation {
    pub fn new(keypair: Arc<EdKeyPair>, policy: UrlPolicy) -> Self {
        Self {
            delivery: SignedDelivery::new(keypair, policy),
        }
    }
}

impl ProfileFederation for ApProfileFederation {
    fn send_update(&self, from: &Account, profile: &PublicProfile, to: &RemoteActor) {
        self.delivery
            .post_in_background(&from.actor_uri, &to.inbox, update_person(from, profile));
    }
}

/// Rediscovers the account in the background, so the card that found it stale is answered from
/// the cache at once.
pub struct BackgroundProfileRefresh {
    actors: Arc<dyn RemoteActors>,
}

impl BackgroundProfileRefresh {
    pub fn new(actors: Arc<dyn RemoteActors>) -> Self {
        Self { actors }
    }
}

impl ProfileRefresh for BackgroundProfileRefresh {
    fn refresh(&self, actor: &ActorUri) {
        let (actors, actor) = (Arc::clone(&self.actors), actor.clone());
        tokio::spawn(async move {
            if let Err(e) = actors.discover(&actor).await {
                tracing::warn!(%actor, error = %e, "profile refresh failed");
            }
        });
    }
}

fn update_person(account: &Account, profile: &PublicProfile) -> Value {
    let activity = Activity::update_person(
        account.actor_uri.as_str(),
        &account.username,
        profile.display_name.as_deref(),
        profile.avatar_url.as_deref(),
        profile.bio.as_deref(),
        profile.pronouns.map(Pronouns::as_str),
    );
    serde_json::to_value(activity).expect("an activity is plain JSON")
}

#[cfg(test)]
mod tests;
