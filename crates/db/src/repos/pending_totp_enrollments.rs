use sqlx::PgPool;
use uuid::Uuid;

use crate::models::PendingTotpEnrollment;

/// Upsert the in-flight secret for a user. Re-enrollment replaces the prior row.
pub async fn upsert(
    pool: &PgPool,
    user_id: Uuid,
    secret: &[u8],
) -> Result<PendingTotpEnrollment, sqlx::Error> {
    sqlx::query_as::<_, PendingTotpEnrollment>(
        r#"
        INSERT INTO pending_totp_enrollments (user_id, secret)
        VALUES ($1, $2)
        ON CONFLICT (user_id) DO UPDATE
        SET secret     = EXCLUDED.secret,
            created_at = now()
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(secret)
    .fetch_one(pool)
    .await
}

pub async fn find_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<PendingTotpEnrollment>, sqlx::Error> {
    sqlx::query_as::<_, PendingTotpEnrollment>(
        "SELECT * FROM pending_totp_enrollments WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

pub async fn delete_for_user(pool: &PgPool, user_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM pending_totp_enrollments WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}
