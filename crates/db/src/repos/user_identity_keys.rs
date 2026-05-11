//! Repository for `user_identity_keys` — one row per user holding the public
//! parts of the user's MSK / SSK / USK + the SSK/USK self-signatures.
//!
//! All material is public. Private keys live exclusively on user devices.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserIdentityKeys {
    pub user_id: Uuid,
    pub msk_public: Vec<u8>,
    pub ssk_public: Vec<u8>,
    pub ssk_signature: Vec<u8>,
    pub usk_public: Vec<u8>,
    pub usk_signature: Vec<u8>,
    pub published_at: OffsetDateTime,
    pub rotated_at: OffsetDateTime,
}

/// Insert or replace the caller's identity-keys row.
///
/// Replacement bumps `rotated_at`; `published_at` is preserved on update so
/// long-lived users keep their original publication timestamp for audit.
pub async fn upsert(
    pool: &PgPool,
    user_id: Uuid,
    msk_public: &[u8],
    ssk_public: &[u8],
    ssk_signature: &[u8],
    usk_public: &[u8],
    usk_signature: &[u8],
) -> Result<UserIdentityKeys, sqlx::Error> {
    sqlx::query_as::<_, UserIdentityKeys>(
        r#"
        INSERT INTO user_identity_keys
            (user_id, msk_public, ssk_public, ssk_signature, usk_public, usk_signature)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (user_id) DO UPDATE SET
            msk_public    = EXCLUDED.msk_public,
            ssk_public    = EXCLUDED.ssk_public,
            ssk_signature = EXCLUDED.ssk_signature,
            usk_public    = EXCLUDED.usk_public,
            usk_signature = EXCLUDED.usk_signature,
            rotated_at    = now()
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(msk_public)
    .bind(ssk_public)
    .bind(ssk_signature)
    .bind(usk_public)
    .bind(usk_signature)
    .fetch_one(pool)
    .await
}

pub async fn find_by_user_id(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<UserIdentityKeys>, sqlx::Error> {
    sqlx::query_as::<_, UserIdentityKeys>(
        "SELECT * FROM user_identity_keys WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
}
