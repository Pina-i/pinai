use std::time::Instant;

use dashmap::DashMap;

use super::types::PresenceState;

/// In-memory presence state store.
///
/// Keyed by `actor_uri` (works for both local and remote actors).
/// Updated by the Redis `presence:<domain>` subscriber and by batch polls.
/// No persistence — on server restart all actors are `offline` until they reconnect.
pub struct PresenceStore {
    states: DashMap<String, (PresenceState, Instant)>,
}

impl Default for PresenceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PresenceStore {
    pub fn new() -> Self {
        Self {
            states: DashMap::new(),
        }
    }

    /// Update the presence state for an actor.
    pub fn set(&self, actor_uri: &str, state: PresenceState) {
        self.states
            .insert(actor_uri.to_string(), (state, Instant::now()));
    }

    /// Get the current presence state for an actor.
    /// Returns `Offline` if the actor has no entry.
    pub fn get(&self, actor_uri: &str) -> PresenceState {
        self.states
            .get(actor_uri)
            .map(|entry| entry.0)
            .unwrap_or(PresenceState::Offline)
    }

    /// Get presence states for multiple actors.
    pub fn get_many(&self, actor_uris: &[String]) -> Vec<(String, PresenceState)> {
        actor_uris
            .iter()
            .map(|uri| (uri.clone(), self.get(uri)))
            .collect()
    }

    /// Remove an actor from the store (e.g. when they go offline).
    pub fn remove(&self, actor_uri: &str) {
        self.states.remove(actor_uri);
    }

    /// Get all entries (used for SSE reconnect replay).
    /// Returns only entries that match the given actor URIs.
    pub fn snapshot(&self, actor_uris: &[String]) -> Vec<(String, PresenceState, Instant)> {
        actor_uris
            .iter()
            .filter_map(|uri| {
                self.states
                    .get(uri)
                    .map(|entry| (uri.clone(), entry.0, entry.1))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
