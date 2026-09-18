use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::models::EmailVerificationCode;

/// Insert a fresh OTP row, atomically invalidating any prior unconsumed code
/// for the same user so only the latest one can succeed.
pub async fn insert(
    pool: &PgPool,
    user_id: Uuid,
    code_hash: &[u8],
    expires_at: OffsetDateTime,
) -> Result<EmailVerificationCode, sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query(
        r#"
        UPDATE email_verification_codes
           SET consumed_at = now()
         WHERE user_id = $1 AND consumed_at IS NULL
        "#,
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

    let row = sqlx::query_as::<_, EmailVerificationCode>(
        r#"
        INSERT INTO email_verification_codes (user_id, code_hash, expires_at)
        VALUES ($1, $2, $3)
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(code_hash)
    .bind(expires_at)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(row)
}

/// Latest unconsumed, unexpired OTP for a user.
pub async fn find_active_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<EmailVerificationCode>, sqlx::Error> {
    sqlx::query_as::<_, EmailVerificationCode>(
        r#"
        SELECT *
          FROM email_verification_codes
         WHERE user_id = $1
           AND consumed_at IS NULL
           AND expires_at > now()
         ORDER BY created_at DESC
         LIMIT 1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

pub async fn increment_attempts(pool: &PgPool, id: Uuid) -> Result<i32, sqlx::Error> {
    let (attempts,): (i32,) = sqlx::query_as(
        r#"
        UPDATE email_verification_codes
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

/// Mark the code consumed and flip the user's `email_verified_at` in one tx.
/// Returns `false` if a concurrent request already consumed it.
pub async fn consume_and_verify_user(
    pool: &PgPool,
    code_id: Uuid,
    user_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let affected = sqlx::query(
        r#"
        UPDATE email_verification_codes
           SET consumed_at = now()
         WHERE id = $1 AND consumed_at IS NULL
        "#,
    )
    .bind(code_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if affected == 0 {
        tx.rollback().await?;
        return Ok(false);
    }

    sqlx::query(
        r#"
        UPDATE users
           SET email_verified_at = now(),
               updated_at        = now()
         WHERE id = $1
        "#,
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(true)
}

/// Count codes issued for a user within the last `window_secs` seconds — used
/// to enforce the resend rate limit.
pub async fn count_recent_for_user(
    pool: &PgPool,
    user_id: Uuid,
    window_secs: i64,
) -> Result<i64, sqlx::Error> {
    let (n,): (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)::BIGINT
          FROM email_verification_codes
         WHERE user_id = $1
           AND created_at > now() - make_interval(secs => $2)
        "#,
    )
    .bind(user_id)
    .bind(window_secs as f64)
    .fetch_one(pool)
    .await?;
    Ok(n)
}

/// Drop consumed-or-expired rows older than the cutoff. Returns rows deleted.
pub async fn reap_expired(pool: &PgPool, older_than_secs: i64) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(
        r#"
        DELETE FROM email_verification_codes
         WHERE (consumed_at IS NOT NULL OR expires_at < now())
           AND created_at < now() - make_interval(secs => $1)
        "#,
    )
    .bind(older_than_secs as f64)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
