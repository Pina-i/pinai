//! Repository for `recovery_blobs` — opt-in passphrase-wrapped MSK backup.
//!
//! The wrapped blob is opaque to the server. The Argon2id-derived KEK is
//! never seen by the IdP; only the user's device knows the passphrase.

use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RecoveryBlob {
    pub user_id: Uuid,
    pub wrapped_msk: Vec<u8>,
    pub salt: Vec<u8>,
    pub argon2_params: Value,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Insert or replace the caller's recovery blob.
pub async fn upsert(
    pool: &PgPool,
    user_id: Uuid,
    wrapped_msk: &[u8],
    salt: &[u8],
    argon2_params: &Value,
) -> Result<RecoveryBlob, sqlx::Error> {
    sqlx::query_as::<_, RecoveryBlob>(
        r#"
        INSERT INTO recovery_blobs (user_id, wrapped_msk, salt, argon2_params)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (user_id) DO UPDATE SET
            wrapped_msk   = EXCLUDED.wrapped_msk,
            salt          = EXCLUDED.salt,
            argon2_params = EXCLUDED.argon2_params,
            updated_at    = now()
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(wrapped_msk)
    .bind(salt)
    .bind(argon2_params)
    .fetch_one(pool)
    .await
}

pub async fn find_by_user_id(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<RecoveryBlob>, sqlx::Error> {
    sqlx::query_as::<_, RecoveryBlob>("SELECT * FROM recovery_blobs WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
}

/// Returns true when a row was actually deleted (so the handler can return
/// `204` or `404` accordingly).
pub async fn delete(pool: &PgPool, user_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM recovery_blobs WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
