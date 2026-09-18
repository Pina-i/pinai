//! Per-user salt for Argon2id derivation of the History Archive Key.
//! Set-once: first device wins, subsequent POSTs receive that salt back.

use sqlx::PgPool;
use uuid::Uuid;

/// `COALESCE`-based set-once. Returns whatever's now stored.
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
    let row: (Option<Vec<u8>>,) =
        sqlx::query_as("SELECT history_archive_salt FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await?;
    Ok(row.0)
}
