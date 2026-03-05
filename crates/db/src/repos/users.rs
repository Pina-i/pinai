use sqlx::PgPool;
use uuid::Uuid;

use crate::models::User;

/// Generate a 4-char base36 (0-9 A-Z) suffix from the UUID's first 4 bytes.
/// Deterministic — always produces the same suffix for the same UUID.
pub fn generate_handle_suffix(id: Uuid) -> String {
    const CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let bytes = id.as_bytes();
    let n = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let mut n = n % 1_679_616u32; // mod 36^4 → 0..1_679_615
    let mut result = [0u8; 4];
    for i in (0..4).rev() {
        result[i] = CHARS[(n % 36) as usize];
        n /= 36;
    }
    String::from_utf8(result.to_vec()).unwrap()
}

pub async fn create_user(
    pool: &PgPool,
    username: &str,
    email: &str,
    password_hash: &str,
    handle_suffix: &str,
) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (username, email, password_hash, handle_suffix)
        VALUES ($1, $2, $3, $4)
        RETURNING *
        "#,
    )
    .bind(username)
    .bind(email)
    .bind(password_hash)
    .bind(handle_suffix)
    .fetch_one(pool)
    .await
}

/// Insert a user with a pre-generated UUID (lets callers derive the handle suffix from the ID).
pub async fn create_user_with_id(
    pool: &PgPool,
    id: Uuid,
    username: &str,
    email: &str,
    password_hash: &str,
    handle_suffix: &str,
) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (id, username, email, password_hash, handle_suffix)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(username)
    .bind(email)
    .bind(password_hash)
    .bind(handle_suffix)
    .fetch_one(pool)
    .await
}

pub async fn find_by_username(pool: &PgPool, username: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await
}

pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(pool)
        .await
}

pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// Find a user by their full handle ("username-SUFFIX", e.g. "alex-7G4K").
/// Splits on the last '-' to separate username from suffix.
pub async fn find_by_handle(pool: &PgPool, handle: &str) -> Result<Option<User>, sqlx::Error> {
    let (username, suffix) = match handle.rsplit_once('-') {
        Some(pair) => pair,
        None => return Ok(None),
    };
    sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE username = $1 AND handle_suffix = $2",
    )
    .bind(username)
    .bind(suffix)
    .fetch_optional(pool)
    .await
}

/// Set the avatar URL for a user.
pub async fn update_avatar_url(
    pool: &PgPool,
    user_id: Uuid,
    avatar_url: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET avatar_url = $1 WHERE id = $2")
        .bind(avatar_url)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Clear the avatar URL for a user.
pub async fn clear_avatar_url(pool: &PgPool, user_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET avatar_url = NULL WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Search users by username prefix (case-insensitive), up to `limit` results.
pub async fn search_by_username(
    pool: &PgPool,
    query: &str,
    limit: i64,
) -> Result<Vec<User>, sqlx::Error> {
    sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE username ILIKE $1 ORDER BY username LIMIT $2",
    )
    .bind(format!("%{}%", query))
    .bind(limit)
    .fetch_all(pool)
    .await
}
