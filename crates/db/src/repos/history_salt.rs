//! `users.history_archive_salt` repo — per-user random salt for Argon2id
//! derivation of the History Archive Key (Phase 7, Layer B).
//!
//! Set-once semantics: the first device to register a salt wins; subsequent
//! POSTs from the user's other devices receive the same salt back (idempotent).

use sqlx::PgPool;
use uuid::Uuid;

/// Idempotent: store the salt only if currently NULL. Returns whatever is in
/// the column afterwards. Used by multiple devices racing — the loser gets
/// back the winning device's salt.
pub async fn set_if_unset(
    pool: &PgPool,
    user_id: Uuid,
    salt: &[u8],
) -> Result<Vec<u8>, sqlx::Error> {
    let row: (Vec<u8>,) = sqlx::query_as(
        r#"
        UPDATE users
        SET history_archive_salt = COALESCE(history_archive_salt, $2)
        WHERE id = $1
        RETURNING history_archive_salt
        "#,
    )
    .bind(user_id)
    .bind(salt)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn get(pool: &PgPool, user_id: Uuid) -> Result<Option<Vec<u8>>, sqlx::Error> {
    let row: (Option<Vec<u8>>,) = sqlx::query_as(
        "SELECT history_archive_salt FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}
