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
    /// Stored as `'he' | 'she' | 'non-binary'` (DB-enforced via CHECK).
    pub pronouns: Option<String>,
    pub bio: Option<String>,
    pub actor_uri: Option<String>,
    pub inbox_url: Option<String>,
    pub outbox_url: Option<String>,
    pub email_verified_at: Option<OffsetDateTime>,
    #[serde(skip_serializing)]
    pub totp_secret: Option<Vec<u8>>,
    pub totp_enabled: bool,
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

// ─── EmailVerificationCode ────────────────────────────────────────────────────

/// Signup confirmation OTP row. Plaintext code is never stored — only its
/// peppered HMAC-SHA256. Single-use; resending invalidates the prior row in
/// the same transaction.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EmailVerificationCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code_hash: Vec<u8>,
    pub expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
    pub attempts: i32,
    pub created_at: OffsetDateTime,
}

// ─── TOTP 2FA: enrollment / login tickets / recovery codes ───────────────────

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PendingTotpEnrollment {
    pub user_id: Uuid,
    pub secret: Vec<u8>,
    pub created_at: OffsetDateTime,
}

/// "Password was correct, now show me a TOTP / recovery code" ticket.
/// Carries the OIDC params server-side so the URL only exposes an opaque id.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PendingTotpLogin {
    pub id: Uuid,
    pub user_id: Uuid,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub oauth_state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
    pub expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
    pub attempts: i32,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RecoveryCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code_hash: Vec<u8>,
    pub consumed_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
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

// ─── Conversation ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct Conversation {
    pub id: Uuid,
    pub kind: String,
    pub name: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct ConversationMember {
    pub conversation_id: Uuid,
    pub actor_uri: String,
    pub joined_at: OffsetDateTime,
    pub left_at: Option<OffsetDateTime>,
    /// `'member'` | `'admin'` — only meaningful for groups; DMs stay `'member'`.
    pub role: String,
}

// ─── DirectMessage ────────────────────────────────────────────────────────────

/// Every DM row carries an opaque MLS ciphertext after Phase 3. The plaintext
/// `content` column was dropped; replies, reactions, and edits now travel as
/// MLS application messages inside the encrypted body.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct DirectMessage {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub sender_actor_uri: String,
    /// TLS-encoded MLSMessage. Server never decrypts or inspects.
    pub mls_ciphertext: Vec<u8>,
    pub activity_uri: String,
    pub federation_status: String,
    pub created_at: OffsetDateTime,
    pub edited_at: Option<OffsetDateTime>,
    pub deleted_at: Option<OffsetDateTime>,
    pub reply_to_id: Option<Uuid>,
}

// ─── Attachment ───────────────────────────────────────────────────────────────

/// An attachment on a direct message. Two phases:
///
/// - **Orphan** (`message_id IS NULL`) — uploaded but not yet linked to a message;
///   reaped by the orphan-sweep task after the configured TTL.
/// - **Linked** (`message_id IS NOT NULL`) — attached to a message, lifecycle
///   tied to that message (hard-deleted when the message is soft-deleted).
///
/// For remote attachments received via federation, `remote_origin_url` is set
/// and `storage_key` exists for uniformity but no object lives in this IdP's bucket.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct Attachment {
    pub id: Uuid,
    pub message_id: Option<Uuid>,
    pub uploaded_by_actor_uri: String,
    pub storage_key: String,
    pub mime_type: String,
    pub byte_size: i64,
    pub original_filename: String,
    pub remote_origin_url: Option<String>,
    pub created_at: OffsetDateTime,
}

// ─── User device (Phase 6b) ───────────────────────────────────────────────────

/// Per-device metadata for the Settings → Devices view. One row per
/// `device_id` UUID the user has ever published a KeyPackage from. The
/// `display_name` + `kind` are auto-detected from the User-Agent header
/// at first publish; `last_seen_at` is touched on every subsequent
/// KP publish from that device. `revoked_at` is set by the Devices UI's
/// per-device "Sign out" action and is the directory-level flag —
/// actual exclusion from MLS groups happens client-side via Remove commits.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct UserDevice {
    pub device_id: Uuid,
    pub user_id: Uuid,
    pub display_name: String,
    /// `'laptop' | 'phone' | 'tablet' | 'unknown'` — DB-CHECK enforced.
    pub kind: String,
    pub paired_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    // IdP-attested Device Root Key. NULL until first `POST /api/keys/devices`.
    pub drk_public_key: Option<Vec<u8>>,
    pub attestation_signature: Option<Vec<u8>>,
    pub attestation_kid: Option<String>,
    pub attestation_issued_at: Option<OffsetDateTime>,
    pub attestation_expires_at: Option<OffsetDateTime>,
}
