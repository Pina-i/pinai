use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub handle_suffix: String,
    pub email: String,
    #[serde(skip_serializing)] // never expose the hash
    pub password_hash: String,
    pub avatar_url: Option<String>,
    pub created_at: OffsetDateTime,
}

impl User {
    /// Returns the full handle: "username-SUFFIX" (e.g. "alex-7G4K").
    /// Used internally for ActivityPub URL paths (`/users/alex-7G4K`).
    pub fn handle(&self) -> String {
        format!("{}-{}", self.username, self.handle_suffix)
    }

    /// Returns the federated address: "username-SUFFIX@domain" (e.g. "alex-7G4K@idp.example.com").
    /// This is the canonical user identifier exposed in all APIs.
    pub fn address(&self, domain: &str) -> String {
        format!("{}@{}", self.handle(), domain)
    }
}

/// Extract the local handle from an address like "alice-7G4K@domain".
/// Returns the full string if no `@` is present.
pub fn handle_from_address(address: &str) -> &str {
    address.split_once('@').map(|(h, _)| h).unwrap_or(address)
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

// ─── Follow ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct Follow {
    pub id: Uuid,
    pub follower_id: Uuid,
    pub following_id: Uuid,
    /// "pending" | "accepted" | "rejected"
    pub state: String,
    pub ap_activity_id: Option<String>,
    pub created_at: OffsetDateTime,
}

// ─── DirectMessage ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct DirectMessage {
    pub id: Uuid,
    pub sender_id: Uuid,
    pub recipient_id: Uuid,
    pub content: String,
    pub ap_id: Option<String>,
    pub created_at: OffsetDateTime,
}
