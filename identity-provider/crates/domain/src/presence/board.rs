use std::collections::HashMap;
use std::sync::Mutex;

use crate::identity::ActorUri;

use super::PresenceState;

/// The last presence state heard for every actor, local or remote. In memory: presence is never
/// persisted, and after a restart every actor reads `offline` until it is heard of again.
#[derive(Default)]
pub struct PresenceBoard {
    states: Mutex<HashMap<ActorUri, PresenceState>>,
}

impl PresenceBoard {
    /// `offline` for an actor never heard of.
    pub fn state(&self, actor: &ActorUri) -> PresenceState {
        self.heard(actor).unwrap_or(PresenceState::Offline)
    }

    /// `None` for an actor never heard of.
    pub fn heard(&self, actor: &ActorUri) -> Option<PresenceState> {
        self.states.lock().unwrap().get(actor).copied()
    }

    pub fn set(&self, actor: &ActorUri, state: PresenceState) {
        self.states.lock().unwrap().insert(actor.clone(), state);
    }
}

#[cfg(test)]
mod tests;
