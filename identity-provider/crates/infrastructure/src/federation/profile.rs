//! `Update{Person}`, delivered best-effort — see
//! identity-provider/specs/event-delivery.md § 2 — and a stale cached profile, asked for again.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// How long after asking for an actor's profile it is asked for again, whatever came of it.
const RETRY_AFTER: Duration = Duration::from_secs(60 * 60);

/// Rediscovers the account in the background, so the card that found it stale is answered from
/// the cache at once. An account is asked for at most once an hour: a dead peer's profile stays
/// stale, and must not cost a fetch on every view of its card.
pub struct BackgroundProfileRefresh {
    actors: Arc<dyn RemoteActors>,
    retry_after: Duration,
    asked: Mutex<HashMap<ActorUri, Instant>>,
}

impl BackgroundProfileRefresh {
    pub fn new(actors: Arc<dyn RemoteActors>) -> Self {
        Self {
            actors,
            retry_after: RETRY_AFTER,
            asked: Mutex::default(),
        }
    }

    /// Whether `actor` may be asked for now, counting this ask if so.
    fn may_ask(&self, actor: &ActorUri) -> bool {
        let mut asked = self.asked.lock().unwrap();
        asked.retain(|_, at| at.elapsed() < self.retry_after);
        if asked.contains_key(actor) {
            return false;
        }
        asked.insert(actor.clone(), Instant::now());
        true
    }
}

impl ProfileRefresh for BackgroundProfileRefresh {
    fn refresh(&self, actor: &ActorUri) {
        if !self.may_ask(actor) {
            return;
        }
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
