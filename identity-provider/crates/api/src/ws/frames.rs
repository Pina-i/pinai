//! What a client sends over its WebSocket: each frame `{ "type", "data" }`.

use serde::Deserialize;
use uuid::Uuid;

/// Client-to-server messages received over WebSocket.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", content = "data")]
#[serde(rename_all = "snake_case")]
pub enum WsClientMessage {
    SendDm(SendDmPayload),
    Heartbeat,
    TypingStart(TypingStartPayload),
    /// User opened a conversation; ensure outbound SSE for any remote member's domain.
    WatchConversation(WatchConversationPayload),
    /// User closed a conversation; release outbound SSE if no other watchers.
    UnwatchConversation(UnwatchConversationPayload),
    /// User explicitly chose a presence state from the UI (online / away / dnd / offline).
    SetPresence(SetPresencePayload),
}

#[derive(Debug, Deserialize)]
pub struct SetPresencePayload {
    /// Lower-case wire form: `"online" | "away" | "offline" | "dnd"`.
    pub state: String,
}

#[derive(Debug, Deserialize)]
pub struct SendDmPayload {
    pub recipient_address: String,
    /// Pre-encrypted MLSMessage body, base64-encoded. Server never inspects.
    pub mls_ciphertext: String,
    /// Optional sender-side correlation token. Echoed back to the sender on the
    /// resulting `new_dm` event so the client can reconcile its optimistic message.
    #[serde(default)]
    pub client_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypingStartPayload {
    pub conversation_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchConversationPayload {
    pub conversation_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnwatchConversationPayload {
    pub conversation_id: Uuid,
}

/// The answer to a `heartbeat`, as the events pushed from `infrastructure::realtime` are shaped.
pub const HEARTBEAT_ACK: &str = r#"{"type":"heartbeat_ack","data":{}}"#;

#[cfg(test)]
mod tests;
