use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Client};
use uuid::Uuid;

use crate::traits::{BrokerError, EventBroker, StreamEntry};

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
