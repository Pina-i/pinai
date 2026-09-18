use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::models::PendingTotpLogin;

#[derive(Debug, Clone)]
pub struct NewPendingLogin<'a> {
    pub user_id: Uuid,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub oauth_state: &'a str,
    pub code_challenge: &'a str,
    pub code_challenge_method: &'a str,
    pub nonce: Option<&'a str>,
    pub expires_at: OffsetDateTime,
}

/// Create a TOTP-challenge ticket. Consumes any prior unconsumed ticket for
/// the same user so only the latest one is honoured (defends against ticket
/// recycling from a failed attempt window).
pub async fn create(
    pool: &PgPool,
    new: NewPendingLogin<'_>,
) -> Result<PendingTotpLogin, sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query(
        r#"
        UPDATE pending_totp_logins
           SET consumed_at = now()
         WHERE user_id = $1 AND consumed_at IS NULL
        "#,
    )
    .bind(new.user_id)
    .execute(&mut *tx)
    .await?;

    let row = sqlx::query_as::<_, PendingTotpLogin>(
        r#"
        INSERT INTO pending_totp_logins
            (user_id, client_id, redirect_uri, scope, oauth_state,
             code_challenge, code_challenge_method, nonce, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *
        "#,
    )
    .bind(new.user_id)
    .bind(new.client_id)
    .bind(new.redirect_uri)
    .bind(new.scope)
    .bind(new.oauth_state)
    .bind(new.code_challenge)
    .bind(new.code_challenge_method)
    .bind(new.nonce)
    .bind(new.expires_at)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(row)
}

pub async fn find_active(pool: &PgPool, id: Uuid) -> Result<Option<PendingTotpLogin>, sqlx::Error> {
    sqlx::query_as::<_, PendingTotpLogin>(
        r#"
        SELECT *
          FROM pending_totp_logins
         WHERE id = $1
           AND consumed_at IS NULL
           AND expires_at > now()
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn increment_attempts(pool: &PgPool, id: Uuid) -> Result<i32, sqlx::Error> {
    let (attempts,): (i32,) = sqlx::query_as(
        r#"
        UPDATE pending_totp_logins
           SET attempts = attempts + 1
         WHERE id = $1
        RETURNING attempts
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    Ok(attempts)
}

pub async fn consume(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        r#"
        UPDATE pending_totp_logins
           SET consumed_at = now()
         WHERE id = $1 AND consumed_at IS NULL
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Drop consumed-or-expired tickets older than the cutoff.
pub async fn reap_expired(pool: &PgPool, older_than_secs: i64) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(
        r#"
        DELETE FROM pending_totp_logins
         WHERE (consumed_at IS NOT NULL OR expires_at < now())
           AND created_at < now() - make_interval(secs => $1)
        "#,
    )
    .bind(older_than_secs as f64)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
