//! Heartbeat sweep — background task that detects idle connections and publishes `away` events.
//!
//! Also provides the `HeartbeatTracker` shared struct for tracking per-connection heartbeat timestamps.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use idp_broker::EventBroker;
use tracing::{debug, warn};
use uuid::Uuid;

use super::store::PresenceStore;
use super::types::{PresenceEvent, PresenceState};

/// How long since the last heartbeat before marking a connection as `away`.
const AWAY_THRESHOLD: Duration = Duration::from_secs(600); // 10 minutes

/// How often the sweep task runs.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Tracks per-connection heartbeat timestamps.
///
/// Key: `(user_id, conn_id)` — matching the WsHub connection model.
/// Value: `(actor_uri, last_heartbeat_instant)`.
pub struct HeartbeatTracker {
    connections: DashMap<(Uuid, Uuid), (String, Instant)>,
}

impl HeartbeatTracker {
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
        }
    }

    /// Register a new connection. Called when a WebSocket upgrades.
    pub fn register(&self, user_id: Uuid, conn_id: Uuid, actor_uri: String) {
        self.connections
            .insert((user_id, conn_id), (actor_uri, Instant::now()));
    }

    /// Update the heartbeat timestamp for a connection.
    pub fn touch(&self, user_id: Uuid, conn_id: Uuid) {
        if let Some(mut entry) = self.connections.get_mut(&(user_id, conn_id)) {
            entry.1 = Instant::now();
        }
    }

    /// Unregister a connection. Called when a WebSocket disconnects.
    pub fn unregister(&self, user_id: Uuid, conn_id: Uuid) {
        self.connections.remove(&(user_id, conn_id));
    }

    /// Returns all connections whose last heartbeat is older than `AWAY_THRESHOLD`.
    /// Returns `(user_id, actor_uri)` pairs, deduplicated by actor_uri.
    fn stale_connections(&self) -> Vec<(Uuid, String)> {
        let cutoff = Instant::now() - AWAY_THRESHOLD;
        let mut stale = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for entry in self.connections.iter() {
            let ((user_id, _conn_id), (actor_uri, last_hb)) = entry.pair();
            if *last_hb < cutoff && seen.insert(actor_uri.clone()) {
                stale.push((*user_id, actor_uri.clone()));
            }
        }

        stale
    }
}

/// Run the heartbeat sweep as a long-lived background task.
///
/// Every 60 seconds, scans the `HeartbeatTracker` for connections whose last heartbeat
/// is older than 10 minutes. For each such user, publishes an `away` presence event
/// if they are currently `online`.
pub async fn run_heartbeat_sweep(
    tracker: Arc<HeartbeatTracker>,
    store: Arc<PresenceStore>,
    broker: Arc<dyn EventBroker>,
    domain: String,
) {
    let channel = format!("presence:{domain}");

    loop {
        tokio::time::sleep(SWEEP_INTERVAL).await;

        let stale = tracker.stale_connections();
        if stale.is_empty() {
            continue;
        }

        debug!(
            count = stale.len(),
            "heartbeat sweep found stale connections"
        );

        for (_user_id, actor_uri) in stale {
            // Only transition online → away (don't re-publish if already away/offline)
            let current = store.get(&actor_uri);
            if current != PresenceState::Online {
                continue;
            }

            let event = PresenceEvent {
                kind: "presence".to_string(),
                event: PresenceState::Away,
                actor_uri: actor_uri.clone(),
                timestamp: time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            };

            let payload = match serde_json::to_string(&event) {
                Ok(p) => p,
                Err(e) => {
                    warn!("failed to serialize away event: {e}");
                    continue;
                }
            };

            if let Err(e) = broker.publish_presence(&channel, &payload).await {
                warn!(actor_uri = %actor_uri, "failed to publish away event: {e}");
            }
        }
    }
}
