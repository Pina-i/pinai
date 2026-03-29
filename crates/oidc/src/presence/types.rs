use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Presence states: online, away, offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresenceState {
    Online,
    Away,
    Offline,
}

impl std::fmt::Display for PresenceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Online => write!(f, "online"),
            Self::Away => write!(f, "away"),
            Self::Offline => write!(f, "offline"),
        }
    }
}

// ─── Redis pub-sub envelopes ─────────────────────────────────────────────────

/// Presence event published to `presence:<domain>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceEvent {
    #[serde(rename = "type")]
    pub kind: String, // always "presence"
    pub event: PresenceState,
    pub actor_uri: String,
    pub timestamp: String,
}

/// Typing event published to `typing:<conversation_id>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypingEvent {
    #[serde(rename = "type")]
    pub kind: String, // always "typing"
    pub actor_uri: String,
    pub conversation_id: Uuid,
    pub timestamp: String,
}

// ─── HTTP request/response types ─────────────────────────────────────────────

/// Query params for `GET /api/presence?actors[]=...`.
#[derive(Debug, Deserialize)]
pub struct PresenceQuery {
    #[serde(default, rename = "actors[]")]
    pub actors: Vec<String>,
}

/// Request body for `POST /api/presence/batch`.
#[derive(Debug, Serialize, Deserialize)]
pub struct PresenceBatchRequest {
    pub actors: Vec<String>,
}

/// A single actor's presence state in API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActorPresence {
    pub actor_uri: String,
    pub state: PresenceState,
}

/// Response for presence endpoints.
#[derive(Debug, Serialize, Deserialize)]
pub struct PresenceResponse {
    pub presence: Vec<ActorPresence>,
}

// ─── SSE types ───────────────────────────────────────────────────────────────

/// Query params for `GET /api/presence/stream?actors[]=...`.
#[derive(Debug, Deserialize)]
pub struct PresenceStreamQuery {
    #[serde(default, rename = "actors[]")]
    pub actors: Vec<String>,
}
