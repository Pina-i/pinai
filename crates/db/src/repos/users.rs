use sqlx::PgPool;
use uuid::Uuid;

use crate::models::User;

#[allow(clippy::too_many_arguments)]
pub async fn create_user(
    pool: &PgPool,
    username: &str,
    display_name: &str,
    email: &str,
    password_hash: &str,
    actor_uri: &str,
    inbox_url: &str,
    outbox_url: &str,
) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (username, email, password_hash, actor_uri, inbox_url, outbox_url, display_name)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
        "#,
    )
    .bind(username)
    .bind(email)
    .bind(password_hash)
    .bind(actor_uri)
    .bind(inbox_url)
    .bind(outbox_url)
    .bind(display_name)
    .fetch_one(pool)
    .await
}

/// Insert a user with a pre-generated UUID.
#[allow(clippy::too_many_arguments)]
pub async fn create_user_with_id(
    pool: &PgPool,
    id: Uuid,
    username: &str,
    display_name: &str,
    email: &str,
    password_hash: &str,
    actor_uri: &str,
    inbox_url: &str,
    outbox_url: &str,
) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (id, username, email, password_hash, actor_uri, inbox_url, outbox_url, display_name)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(username)
    .bind(email)
    .bind(password_hash)
    .bind(actor_uri)
    .bind(inbox_url)
    .bind(outbox_url)
    .bind(display_name)
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

/// Find a user by their actor URI (e.g. "https://idp.alice.com/users/alice").
pub async fn find_by_actor_uri(
    pool: &PgPool,
    actor_uri: &str,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE actor_uri = $1")
        .bind(actor_uri)
        .fetch_optional(pool)
        .await
}

/// Set the avatar URL for a user.
pub async fn update_avatar_url(
    pool: &PgPool,
    user_id: Uuid,
    avatar_url: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET avatar_url = $1, updated_at = now() WHERE id = $2")
        .bind(avatar_url)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Clear the avatar URL for a user.
pub async fn clear_avatar_url(pool: &PgPool, user_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET avatar_url = NULL, updated_at = now() WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Update the display name for a user.
pub async fn update_display_name(
    pool: &PgPool,
    user_id: Uuid,
    display_name: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET display_name = $1, updated_at = now() WHERE id = $2")
        .bind(display_name)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Update the human-editable profile fields in a single statement.
/// Each `Option` represents the value to write — `None` clears the column.
/// Returns the updated row.
pub async fn update_profile(
    pool: &PgPool,
    user_id: Uuid,
    display_name: Option<&str>,
    pronouns: Option<&str>,
    bio: Option<&str>,
) -> Result<User, sqlx::Error> {
    sqlx::query_as::<_, User>(
        r#"
        UPDATE users
        SET display_name = $2,
            pronouns     = $3,
            bio          = $4,
            updated_at   = now()
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(display_name)
    .bind(pronouns)
    .bind(bio)
    .fetch_one(pool)
    .await
}

/// Commit a verified TOTP secret to the user row and flip `totp_enabled = true`.
pub async fn set_totp_secret_and_enable(
    pool: &PgPool,
    user_id: Uuid,
    secret: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE users
           SET totp_secret  = $2,
               totp_enabled = TRUE,
               updated_at   = now()
         WHERE id = $1
        "#,
    )
    .bind(user_id)
    .bind(secret)
    .execute(pool)
    .await?;
    Ok(())
}

/// Clear TOTP state — used by `POST /api/totp/disable` and during recovery.
pub async fn disable_totp(pool: &PgPool, user_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE users
           SET totp_secret  = NULL,
               totp_enabled = FALSE,
               updated_at   = now()
         WHERE id = $1
        "#,
    )
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
