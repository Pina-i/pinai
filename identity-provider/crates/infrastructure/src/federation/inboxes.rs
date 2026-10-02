use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use domain::identity::{ActorUri, InstanceOrigin, RemoteActors};

/// How long an actor that couldn't be resolved is left alone.
const RETRY_AFTER: Duration = Duration::from_secs(10 * 60);

/// How many instances one send may ask. A group's roster comes from whichever member's instance
/// last sent it, so it may name accounts nobody here has met — or made-up ones.
pub(crate) const LOOKUPS_PER_SEND: usize = 10;

/// Where to deliver to a remote actor: the inbox this instance cached, else the one the actor's
/// own instance names over WebFinger, cached from then on. One that couldn't be resolved isn't
/// asked for again for a while, so a dead or made-up member costs one lookup.
pub struct Inboxes {
    origin: InstanceOrigin,
    remote_actors: Arc<dyn RemoteActors>,
    retry_after: Duration,
    unresolved: Mutex<HashMap<ActorUri, Instant>>,
}

impl Inboxes {
    pub fn new(origin: InstanceOrigin, remote_actors: Arc<dyn RemoteActors>) -> Self {
        Self {
            origin,
            remote_actors,
            retry_after: RETRY_AFTER,
            unresolved: Mutex::default(),
        }
    }

    /// `lookups` is how many instances the send may still ask; asking one spends one.
    pub(crate) async fn of(&self, actor: &ActorUri, lookups: &mut usize) -> Option<url::Url> {
        if self.origin.owns(actor) {
            return None;
        }
        match self.remote_actors.find(actor).await {
            Ok(Some(known)) => return Some(known.inbox),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(%actor, error = %e, "remote actor cache unavailable");
                return None;
            }
        }
        if *lookups == 0 || self.recently_unresolved(actor) {
            return None;
        }
        let address = actor.federated_address()?;
        *lookups -= 1;
        match self.remote_actors.resolve(&address).await {
            // A WebFinger answer naming another actor is no proof this one exists.
            Ok(found) if found.actor_uri == *actor => return Some(found.inbox),
            Ok(found) => {
                tracing::debug!(%actor, named = %found.actor_uri, "remote member resolved as someone else")
            }
            Err(e) => tracing::debug!(%actor, error = %e, "remote member unresolved"),
        }
        self.unresolved
            .lock()
            .unwrap()
            .insert(actor.clone(), Instant::now());
        None
    }

    fn recently_unresolved(&self, actor: &ActorUri) -> bool {
        let mut unresolved = self.unresolved.lock().unwrap();
        unresolved.retain(|_, at| at.elapsed() < self.retry_after);
        unresolved.contains_key(actor)
    }
}

#[cfg(test)]
mod tests;
