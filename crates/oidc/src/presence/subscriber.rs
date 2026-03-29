//! Background task that subscribes to Redis presence and typing pub-sub channels,
//! updates the PresenceStore, and calls fan-out to deliver events to local WebSocket clients.

use std::sync::Arc;

use idp_db::PgPool;
use tracing::{info, warn};

use crate::ws::WsHub;

use super::fanout;
use super::store::PresenceStore;
use super::types::{PresenceEvent, TypingEvent};

/// Run the presence subscriber as a long-lived background task.
///
/// Subscribes to:
/// - `presence:<domain>` — exact channel for local presence events
/// - `typing:*` — pattern subscription for all typing channels
///
/// On each message:
/// - Presence events: update the `PresenceStore` + fan out to local friends
/// - Typing events: fan out to local conversation members (except sender)
pub async fn run_presence_subscriber(
    redis_url: &str,
    domain: &str,
    store: Arc<PresenceStore>,
    pool: PgPool,
    hub: Arc<WsHub>,
) {
    let presence_channel = format!("presence:{domain}");

    let mut rx = match idp_broker::subscribe_channels(
        redis_url,
        &[presence_channel.as_str()],
        &["typing:*"],
    )
    .await
    {
        Ok(rx) => rx,
        Err(e) => {
            tracing::error!("failed to subscribe to presence channels: {e}");
            return;
        }
    };

    info!(channel = %presence_channel, "presence subscriber started");

    while let Some(msg) = rx.recv().await {
        if msg.channel.starts_with("presence:") {
            match serde_json::from_str::<PresenceEvent>(&msg.payload) {
                Ok(event) => {
                    store.set(&event.actor_uri, event.event);
                    fanout::fanout_presence(&event, &pool, &hub).await;
                }
                Err(e) => {
                    warn!(channel = %msg.channel, "invalid presence event: {e}");
                }
            }
        } else if msg.channel.starts_with("typing:") {
            match serde_json::from_str::<TypingEvent>(&msg.payload) {
                Ok(event) => {
                    fanout::fanout_typing(&event, &pool, &hub).await;
                }
                Err(e) => {
                    warn!(channel = %msg.channel, "invalid typing event: {e}");
                }
            }
        }
    }

    warn!("presence subscriber ended unexpectedly");
}
