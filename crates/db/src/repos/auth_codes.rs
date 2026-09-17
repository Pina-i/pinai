use sqlx::PgPool;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::models::AuthCode;

#[allow(clippy::too_many_arguments)]
pub async fn create_code(
    pool: &PgPool,
    code: &str,
    client_id: &str,
    user_id: Uuid,
    redirect_uri: &str,
    code_challenge: &str,
    code_challenge_method: &str, // must be "S256"
    scope: &str,
    nonce: Option<&str>,
) -> Result<AuthCode, sqlx::Error> {
    let expires_at = OffsetDateTime::now_utc() + Duration::minutes(10);

    sqlx::query_as::<_, AuthCode>(
        r#"
        INSERT INTO authorization_codes
            (code, client_id, user_id, redirect_uri,
             code_challenge, code_challenge_method, scope, nonce, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *
        "#,
    )
    .bind(code)
    .bind(client_id)
    .bind(user_id)
    .bind(redirect_uri)
    .bind(code_challenge)
    .bind(code_challenge_method)
    .bind(scope)
    .bind(nonce)
    .bind(expires_at)
    .fetch_one(pool)
    .await
}

/// Atomically fetch and mark an authorization code as used.
///
/// Returns None if the code does not exist, is already used, or has expired.
/// The single UPDATE ... RETURNING prevents TOCTOU replay attacks — both
/// "find" and "consume" happen atomically under PostgreSQL row-level locking.
pub async fn consume_code(pool: &PgPool, code: &str) -> Result<Option<AuthCode>, sqlx::Error> {
    sqlx::query_as::<_, AuthCode>(
        r#"
        UPDATE authorization_codes
        SET used = true
        WHERE code       = $1
          AND used       = false
          AND expires_at > now()
        RETURNING *
        "#,
    )
    .bind(code)
    .fetch_optional(pool)
    .await
}
