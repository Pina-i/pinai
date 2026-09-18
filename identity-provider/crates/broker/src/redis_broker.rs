use futures_util::StreamExt;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Client};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::traits::{BrokerError, EventBroker, PubSubMessage, StreamEntry};

/// Maximum number of entries kept per user stream (approximate trimming).
const STREAM_MAXLEN: usize = 10_000;

/// Redis-backed event broker.
///
/// - **Durable events**: per-user Redis Streams (`user:{id}:events`) with MAXLEN trimming.
/// - **Ephemeral events**: Redis pub-sub channels (for presence).
pub struct RedisBroker {
    conn: ConnectionManager,
}

impl RedisBroker {
    /// Connect to Redis and return a new broker instance.
    /// The `ConnectionManager` handles automatic reconnection.
    pub async fn connect(redis_url: &str) -> Result<Self, BrokerError> {
        let client = Client::open(redis_url)?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self { conn })
    }

    fn stream_key(user_id: Uuid) -> String {
        format!("user:{user_id}:events")
    }
}

/// Subscribe to specific Redis pub-sub channels and a pattern, returning messages on an mpsc channel.
///
/// This creates a **dedicated** Redis connection (separate from the `ConnectionManager`
/// used for publishing) because Redis requires a dedicated connection for SUBSCRIBE.
///
/// `channels` — exact channel names to SUBSCRIBE to (e.g. `["presence:idp.alice.com"]`).
/// `patterns` — patterns to PSUBSCRIBE to (e.g. `["typing:*"]`).
///
/// Returns a receiver that yields `PubSubMessage` for each received message.
/// The background task runs until the returned receiver is dropped.
pub async fn subscribe_channels(
    redis_url: &str,
    channels: &[&str],
    patterns: &[&str],
) -> Result<mpsc::UnboundedReceiver<PubSubMessage>, BrokerError> {
    let client = Client::open(redis_url)?;
    let mut pubsub = client.get_async_pubsub().await?;

    for ch in channels {
        pubsub.subscribe(*ch).await?;
    }
    for pat in patterns {
        pubsub.psubscribe(*pat).await?;
    }

    let (tx, rx) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        loop {
            let msg = match pubsub.on_message().next().await {
                Some(msg) => msg,
                None => break,
            };

            let channel: String = msg.get_channel_name().to_string();
            let payload: String = match msg.get_payload() {
                Ok(p) => p,
                Err(_) => continue,
            };

            if tx.send(PubSubMessage { channel, payload }).is_err() {
                break; // receiver dropped
            }
        }
    });

    Ok(rx)
}

#[async_trait::async_trait]
impl EventBroker for RedisBroker {
    async fn publish(&self, user_id: Uuid, payload: &str) -> Result<String, BrokerError> {
        let key = Self::stream_key(user_id);
        let mut conn = self.conn.clone();

        // XADD user:{id}:events MAXLEN ~ 10000 * payload <json>
        let id: String = redis::cmd("XADD")
            .arg(&key)
            .arg("MAXLEN")
            .arg("~")
            .arg(STREAM_MAXLEN)
            .arg("*")
            .arg("payload")
            .arg(payload)
            .query_async(&mut conn)
            .await?;

        tracing::debug!(%user_id, %id, "event published to stream");
        Ok(id)
    }

    async fn read_after(
        &self,
        user_id: Uuid,
        last_id: &str,
    ) -> Result<Vec<StreamEntry>, BrokerError> {
        let key = Self::stream_key(user_id);
        let mut conn = self.conn.clone();

        // XRANGE user:{id}:events (last_id +  COUNT 1000
        // The "(" prefix makes the start exclusive (entries strictly after last_id).
        let exclusive_start = format!("({last_id}");

        let results: Vec<redis::Value> = redis::cmd("XRANGE")
            .arg(&key)
            .arg(&exclusive_start)
            .arg("+")
            .arg("COUNT")
            .arg(1000)
            .query_async(&mut conn)
            .await?;

        let entries = parse_stream_entries(results);
        tracing::debug!(%user_id, count = entries.len(), "read events from stream");
        Ok(entries)
    }

    async fn publish_presence(&self, channel: &str, payload: &str) -> Result<(), BrokerError> {
        let mut conn = self.conn.clone();
        conn.publish::<_, _, ()>(channel, payload).await?;
        Ok(())
    }
}

/// Parse the raw Redis XRANGE response into typed StreamEntry values.
///
/// XRANGE returns an array of [id, [field, value, ...]] pairs. Each entry
/// has a single "payload" field containing the JSON-serialized event.
fn parse_stream_entries(values: Vec<redis::Value>) -> Vec<StreamEntry> {
    let mut entries = Vec::new();

    for value in values {
        if let redis::Value::Array(pair) = value {
            if pair.len() < 2 {
                continue;
            }

            // First element: entry ID (e.g. "1678886400000-0")
            let id = match &pair[0] {
                redis::Value::BulkString(b) => String::from_utf8_lossy(b).into_owned(),
                _ => continue,
            };

            // Second element: array of [field, value, field, value, ...]
            let payload = match &pair[1] {
                redis::Value::Array(fields) => extract_payload(fields),
                _ => continue,
            };

            if let Some(payload) = payload {
                entries.push(StreamEntry { id, payload });
            }
        }
    }

    entries
}

/// Extract the "payload" field value from a flat [key, val, key, val, ...] array.
fn extract_payload(fields: &[redis::Value]) -> Option<String> {
    for chunk in fields.chunks(2) {
        if chunk.len() < 2 {
            continue;
        }
        let key = match &chunk[0] {
            redis::Value::BulkString(b) => String::from_utf8_lossy(b),
            _ => continue,
        };
        if key == "payload" {
            if let redis::Value::BulkString(b) = &chunk[1] {
                return Some(String::from_utf8_lossy(b).into_owned());
            }
        }
    }
    None
}
