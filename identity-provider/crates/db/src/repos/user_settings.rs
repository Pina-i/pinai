//! The account's settings document (`user_settings`). Bound and returned as
//! JSON text — the database merges it as `jsonb`, the caller parses it.

use sqlx::PgPool;
use uuid::Uuid;

/// The user's settings as JSON text, or `None` if they never saved any.
pub async fn get(pool: &PgPool, user_id: Uuid) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT settings::text FROM user_settings WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
}

/// Replace the top-level sections present in `sections` (a JSON object) and
/// keep every other one, in a single statement. Returns the merged document.
pub async fn merge_sections(
    pool: &PgPool,
    user_id: Uuid,
    sections: &str,
) -> Result<String, sqlx::Error> {
    sqlx::query_scalar(
        r#"
        INSERT INTO user_settings (user_id, settings)
        VALUES ($1, $2::jsonb)
        ON CONFLICT (user_id) DO UPDATE
        SET settings = user_settings.settings || EXCLUDED.settings, updated_at = now()
        RETURNING settings::text
        "#,
    )
    .bind(user_id)
    .bind(sections)
    .fetch_one(pool)
    .await
}
