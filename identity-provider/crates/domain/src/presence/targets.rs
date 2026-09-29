use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use crate::identity::{ActorUri, Domain, InstanceOrigin};
use crate::social::FriendPresence;

/// The remote friends whose presence this instance polls their instances for, by instance. In
/// memory, filled from the friendships at startup and kept by the social context after.
pub struct PollTargets {
    origin: InstanceOrigin,
    targets: Mutex<HashMap<Domain, HashSet<ActorUri>>>,
}

impl PollTargets {
    pub fn new(origin: InstanceOrigin) -> Self {
        Self {
            origin,
            targets: Mutex::default(),
        }
    }

    /// Every instance to poll, with its actors.
    pub fn snapshot(&self) -> HashMap<Domain, Vec<ActorUri>> {
        self.targets
            .lock()
            .unwrap()
            .iter()
            .map(|(domain, actors)| (domain.clone(), actors.iter().cloned().collect()))
            .collect()
    }
}

impl FriendPresence for PollTargets {
    /// A local friend's presence is known here already.
    fn watch(&self, friend: &ActorUri) {
        if self.origin.owns(friend) {
            return;
        }
        self.targets
            .lock()
            .unwrap()
            .entry(friend.domain().clone())
            .or_default()
            .insert(friend.clone());
    }

    fn release(&self, friend: &ActorUri) {
        let mut targets = self.targets.lock().unwrap();
        if let Some(actors) = targets.get_mut(friend.domain()) {
            actors.remove(friend);
            if actors.is_empty() {
                targets.remove(friend.domain());
            }
        }
    }
}

#[cfg(test)]
mod tests;
