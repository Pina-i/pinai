use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Server-to-client events pushed over WebSocket.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data")]
#[serde(rename_all = "snake_case")]
pub enum WsEvent {
    NewDm(DmPayload),
    FriendRequest(FriendshipPayload),
    FriendAccepted(FriendshipPayload),
    FriendRemoved(FriendshipPayload),
    FriendProfileUpdated(ProfileUpdatePayload),
}

#[derive(Debug, Clone, Serialize)]
pub struct DmPayload {
    pub message_id: Uuid,
    pub sender_address: String,
    pub content: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
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

/// Client-to-server messages received over WebSocket.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", content = "data")]
#[serde(rename_all = "snake_case")]
pub enum WsClientMessage {
    SendDm(SendDmPayload),
}

#[derive(Debug, Deserialize)]
pub struct SendDmPayload {
    pub recipient_address: String,
    pub content: String,
}
