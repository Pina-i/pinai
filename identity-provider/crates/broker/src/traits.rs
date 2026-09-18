use uuid::Uuid;

/// A message received from a Redis pub-sub channel.
#[derive(Debug, Clone)]
pub struct PubSubMessage {
    /// The channel name the message was received on.
    pub channel: String,
    /// The message payload (JSON string).
    pub payload: String,
}

/// A durable event read from a user's stream.
#[derive(Debug, Clone)]
pub struct StreamEntry {
    /// Redis Stream entry ID (e.g. "1678886400000-0").
    /// Clients send this back on reconnect so the server can replay missed events.
    pub id: String,
    /// JSON-serialized event payload.
    pub payload: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Transport-agnostic event broker.
///
/// Durable events use per-user streams (Redis Streams) for at-least-once delivery
/// and catch-up on reconnect. Ephemeral events use pub-sub for presence.
///
/// This trait is the abstraction layer that allows migrating from Redis Streams
/// to NATS JetStream later without changing business logic.
#[async_trait::async_trait]
pub trait EventBroker: Send + Sync + 'static {
    /// Publish a durable event to a user's personal stream.
    /// Returns the stream entry ID.
    async fn publish(&self, user_id: Uuid, payload: &str) -> Result<String, BrokerError>;

    /// Read events from a user's stream after the given entry ID.
    /// Used for catch-up on WebSocket reconnect.
    async fn read_after(
        &self,
        user_id: Uuid,
        last_id: &str,
    ) -> Result<Vec<StreamEntry>, BrokerError>;

    /// Publish an ephemeral event via pub-sub (for presence: online/offline/typing).
    async fn publish_presence(&self, channel: &str, payload: &str) -> Result<(), BrokerError>;
}
