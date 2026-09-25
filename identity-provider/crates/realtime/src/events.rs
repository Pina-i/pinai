use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Server-to-client events pushed over WebSocket.
///
/// Phase 3 dropped `MessageReactionAdded` / `MessageReactionRemoved` —
/// reactions are now MLS application messages of `kind = "reaction"`,
/// indistinguishable from text on the wire and reconstructed by clients
/// from their decrypted stream.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data")]
#[serde(rename_all = "snake_case")]
pub enum WsEvent {
    NewDm(DmPayload),
    MessageEdited(EditedDmPayload),
    /// The sender's IdP could not deliver a DM to the recipient's IdP. Sent to
    /// the sender only, always after the `NewDm` echo of the same message.
    DmDeliveryFailed(DmDeliveryFailedPayload),
    FriendRequest(FriendshipPayload),
    FriendAccepted(FriendshipPayload),
    FriendRemoved(FriendshipPayload),
    FriendProfileUpdated(ProfileUpdatePayload),
    PresenceUpdate(PresenceUpdatePayload),
    Typing(TypingPayload),
    HeartbeatAck(HeartbeatAckPayload),
    /// New MLS commit landed for a conversation the recipient is in.
    /// Clients pull missing commits via REST when this event arrives ahead
    /// of their cached epoch.
    MlsCommit(MlsCommitPayload),
    /// Welcome bundle waiting for one of the recipient's devices. Clients
    /// fetch+consume the actual blob via `GET /api/mls/welcomes`.
    MlsWelcomeReady(MlsWelcomeReadyPayload),
    /// A new device of the recipient's account just registered. Other live
    /// sessions add its leaf to every group they're in.
    DeviceJoined(DeviceJoinedPayload),
    /// A group conversation was created with the recipient as a member.
    GroupCreated(GroupCreatedPayload),
    /// A member was added to a group the recipient belongs to.
    MemberAdded(MemberAddedPayload),
    /// A member was removed from (or left) a group the recipient belongs to.
    MemberRemoved(MemberRemovedPayload),
    /// A member's role changed (promoted to / demoted from admin).
    MemberRoleChanged(MemberRoleChangedPayload),
    /// A group was renamed.
    GroupRenamed(GroupRenamedPayload),
}

/// Slim attachment projection carried on the wire alongside DM events.
///
/// Mirrors `messaging::AttachmentMetadata` so the realtime crate can stay
/// dependency-free of `messaging`. The shape is intentionally identical to
/// the REST response for client parsing parity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsAttachment {
    pub id: Uuid,
    pub mime_type: String,
    pub byte_size: i64,
    pub original_filename: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DmPayload {
    pub message_id: Uuid,
    pub conversation_id: Uuid,
    pub kind: String,
    pub sender_address: String,
    pub sender_display_name: Option<String>,
    /// TLS-encoded MLSMessage body, base64-encoded over the wire. Server
    /// never inspects; client decrypts to recover the application message.
    pub mls_ciphertext: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Server-visible parent-message ID for thread routing. The reply
    /// preview (text, sender display) lives inside the encrypted body and
    /// is reconstructed client-side from the decrypted stream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_id: Option<Uuid>,
    /// Empty for messages without attachments; omit-on-empty would force the
    /// client into `?? []` defensive code at every read site.
    #[serde(default)]
    pub attachments: Vec<WsAttachment>,
    /// Echoed back to the sender only, so the client can swap an optimistic
    /// message for the persisted one. Never set on payloads delivered to recipients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EditedDmPayload {
    pub message_id: Uuid,
    /// Replacement TLS-encoded MLSMessage, base64-encoded.
    pub new_mls_ciphertext: String,
    #[serde(with = "time::serde::rfc3339")]
    pub edited_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize)]
pub struct DmDeliveryFailedPayload {
    pub message_id: Uuid,
    pub conversation_id: Uuid,
}

#[derive(Debug, Clone, Serialize)]
pub struct FriendshipPayload {
    pub friendship_id: Uuid,
    pub actor_uri: String,
    pub username: String,
    pub display_name: Option<String>,
    /// DM conversation id for the friendship. Set on `FriendAccepted`
    /// (the accepter's IdP creates the DM in the same transaction as
    /// `set_status('accepted')` and surfaces the id here so the
    /// receiving client can route to the conversation immediately).
    /// `None` on `FriendRequest` (no DM until accepted) and
    /// `FriendRemoved` (the conversation row stays, but the event
    /// doesn't need to mention it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileUpdatePayload {
    pub actor_uri: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
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

// ─── MLS Delivery Service payloads ───────────────────────────────────────────
//
// Both payloads carry the blob inline as base64 so a client whose local MLS
// state is current can apply commits without a follow-up REST round-trip.
// Welcomes are larger, but we still ship them inline — the alternative
// "ready" notification would force a REST fetch on every welcome event.

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MlsCommitPayload {
    pub conversation_id: Uuid,
    pub epoch: i64,
    pub proposer_actor_uri: String,
    /// TLS-encoded MLS Commit message, base64-encoded.
    pub commit_blob: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MlsWelcomeReadyPayload {
    pub conversation_id: Uuid,
    pub recipient_device_id: Uuid,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceJoinedPayload {
    pub actor_uri: String,
    pub device_id: Uuid,
    /// Standard-base64-encoded Ed25519 public key (32 bytes raw). Receiving
    /// devices use it to look up the new device when targeting MLS Add commits.
    pub drk_public_key: String,
}

// ─── Group membership payloads ─────────────────────────────────────────────────
//
// Membership changes are tracked server-side in `conversation_members` and
// pushed to every *local* member so sidebars and member panels update without
// a refresh. Key material still travels through the MLS commit/welcome path.

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupCreatedPayload {
    pub conversation_id: Uuid,
    pub name: Option<String>,
    pub creator_actor_uri: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberAddedPayload {
    pub conversation_id: Uuid,
    pub actor_uri: String,
    pub role: String,
    pub added_by_actor_uri: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberRemovedPayload {
    pub conversation_id: Uuid,
    pub actor_uri: String,
    /// `None` when the member left on their own; otherwise the admin who removed them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed_by_actor_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberRoleChangedPayload {
    pub conversation_id: Uuid,
    pub actor_uri: String,
    pub role: String,
    pub changed_by_actor_uri: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupRenamedPayload {
    pub conversation_id: Uuid,
    pub name: Option<String>,
    pub renamed_by_actor_uri: String,
}

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

#[cfg(test)]
mod tests;
