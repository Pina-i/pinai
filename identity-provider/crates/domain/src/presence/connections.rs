use std::collections::HashMap;
use std::sync::Mutex;

use time::{Duration, OffsetDateTime};

use crate::identity::ActorUri;
use crate::{ConnectionId, UserId};

/// How long without a heartbeat before a connection is idle.
pub const AWAY_AFTER: Duration = Duration::minutes(10);

/// The live connections of this process, and when each last sent a heartbeat. In memory: a
/// restart has no connection to remember.
#[derive(Default)]
pub struct ConnectionTracker {
    connections: Mutex<HashMap<(UserId, ConnectionId), (ActorUri, OffsetDateTime)>>,
}

impl ConnectionTracker {
    pub fn register(
        &self,
        user: UserId,
        connection: ConnectionId,
        actor: ActorUri,
        now: OffsetDateTime,
    ) {
        self.connections
            .lock()
            .unwrap()
            .insert((user, connection), (actor, now));
    }

    pub fn touch(&self, user: UserId, connection: ConnectionId, now: OffsetDateTime) {
        if let Some(entry) = self
            .connections
            .lock()
            .unwrap()
            .get_mut(&(user, connection))
        {
            entry.1 = now;
        }
    }

    pub fn unregister(&self, user: UserId, connection: ConnectionId) {
        self.connections.lock().unwrap().remove(&(user, connection));
    }

    /// The accounts whose every connection has been silent for [`AWAY_AFTER`] — one device
    /// left open in a drawer does not make an account in use elsewhere idle.
    pub fn idle_actors(&self, now: OffsetDateTime) -> Vec<ActorUri> {
        let cutoff = now - AWAY_AFTER;
        let mut latest: HashMap<ActorUri, OffsetDateTime> = HashMap::new();
        for (actor, last_beat) in self.connections.lock().unwrap().values() {
            let beat = latest.entry(actor.clone()).or_insert(*last_beat);
            *beat = (*beat).max(*last_beat);
        }
        let mut idle: Vec<ActorUri> = latest
            .into_iter()
            .filter(|(_, last_beat)| *last_beat < cutoff)
            .map(|(actor, _)| actor)
            .collect();
        idle.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        idle
    }
}

#[cfg(test)]
mod tests;
