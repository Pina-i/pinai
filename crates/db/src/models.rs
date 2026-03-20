use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)] // never expose the hash
    pub password_hash: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub actor_uri: Option<String>,
    pub inbox_url: Option<String>,
    pub outbox_url: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl User {
    /// Returns the federated address: "@username@domain" (e.g. "@alice@idp.example.com").
    pub fn federated_address(&self, domain: &str) -> String {
        format!("{}@{}", self.username, domain)
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OAuthClient {
    pub id: Uuid,
    pub client_id: String,
    pub redirect_uris: Vec<String>, // TEXT[] maps to Vec<String> via SQLx
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub is_public: bool,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthCode {
    pub id: Uuid,
    pub code: String,
    pub client_id: String,
    pub user_id: Uuid,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub scope: String,
    pub nonce: Option<String>,
    pub expires_at: OffsetDateTime,
    pub used: bool,
    pub created_at: OffsetDateTime,
}

/// Slim user representation returned by /userinfo and /register.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub sub: String,
    pub email: String,
    pub preferred_username: String,
}

// ─── RemoteActor ─────────────────────────────────────────────────────────────

/// Cache of a remote user fetched via ActivityPub / WebFinger from another IdP instance.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct RemoteActor {
    pub id: Uuid,
    pub actor_uri: String,
    pub inbox_url: Option<String>,
    pub instance: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub fetched_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

// ─── Friendship ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct Friendship {
    pub id: Uuid,
    pub owner_user_id: Uuid,
    pub friend_actor_uri: String,
    pub friend_avatar_url: Option<String>,
    /// "pending" | "accepted"
    pub status: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Result of the friends list JOIN query across users + remote_actors.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct FriendListEntry {
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub friend_actor_uri: String,
    pub instance: Option<String>,
}

// ─── DirectMessage ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct DirectMessage {
    pub id: Uuid,
    pub sender_actor_uri: String,
    pub recipient_actor_uri: String,
    pub content: String,
    pub activity_uri: String,
    pub federation_status: String,
    pub created_at: OffsetDateTime,
    pub edited_at: Option<OffsetDateTime>,
    pub deleted_at: Option<OffsetDateTime>,
    pub reply_to_id: Option<Uuid>,
}

/// Enriched DM row with LEFT JOIN on the parent message for reply previews.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DirectMessageWithReply {
    pub id: Uuid,
    pub sender_actor_uri: String,
    pub recipient_actor_uri: String,
    pub content: String,
    pub activity_uri: String,
    pub federation_status: String,
    pub created_at: OffsetDateTime,
    pub edited_at: Option<OffsetDateTime>,
    pub deleted_at: Option<OffsetDateTime>,
    pub reply_to_id: Option<Uuid>,
    /// Content of the parent message (NULL if not a reply or parent deleted).
    pub reply_to_content: Option<String>,
    /// Sender actor URI of the parent message.
    pub reply_to_sender: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct MessageReaction {
    pub id: Uuid,
    pub message_id: Uuid,
    pub reactor_actor_uri: String,
    pub emoji: String,
    pub created_at: OffsetDateTime,
}
