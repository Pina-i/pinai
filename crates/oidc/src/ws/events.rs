use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Server-to-client events pushed over WebSocket.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data")]
#[serde(rename_all = "snake_case")]
pub enum WsEvent {
    NewDm(DmPayload),
    MessageEdited(EditedDmPayload),
    FriendRequest(FriendshipPayload),
    FriendAccepted(FriendshipPayload),
    FriendRemoved(FriendshipPayload),
    FriendProfileUpdated(ProfileUpdatePayload),
    MessageReactionAdded(ReactionPayload),
    MessageReactionRemoved(ReactionPayload),
    PresenceUpdate(PresenceUpdatePayload),
    Typing(TypingPayload),
    HeartbeatAck(HeartbeatAckPayload),
}

#[derive(Debug, Clone, Serialize)]
pub struct DmPayload {
    pub message_id: Uuid,
    pub conversation_id: Uuid,
    pub kind: String,
    pub sender_address: String,
    pub sender_display_name: Option<String>,
    pub content: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_sender: Option<String>,
    /// Echoed back to the sender only, so the client can swap an optimistic
    /// message for the persisted one. Never set on payloads delivered to recipients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EditedDmPayload {
    pub message_id: Uuid,
    pub new_content: String,
    #[serde(with = "time::serde::rfc3339")]
    pub edited_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize)]
pub struct FriendshipPayload {
    pub friendship_id: Uuid,
    pub actor_uri: String,
    pub username: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileUpdatePayload {
    pub actor_uri: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReactionPayload {
    pub message_id: Uuid,
    pub reactor_actor_uri: String,
    pub emoji: String,
}

// ─── Presence payloads ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceUpdatePayload {
    pub actor_uri: String,
    pub state: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypingPayload {
    pub actor_uri: String,
    pub conversation_id: Uuid,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeartbeatAckPayload {}

// ─── Client-to-server messages ───────────────────────────────────────────────

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
}

#[derive(Debug, Deserialize)]
pub struct SendDmPayload {
    pub recipient_address: String,
    pub content: String,
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
