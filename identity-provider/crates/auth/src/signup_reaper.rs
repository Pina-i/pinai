//! Background task that cleans up signup-verification debris:
//! consumed/expired OTP rows and unverified accounts that never finished signup.

use std::time::Duration;

use idp_db::repos::{email_verification_codes, pending_totp_logins};
use idp_db::PgPool;

/// Cadence — controls how stale the table can get between passes.
const SWEEP_INTERVAL: Duration = Duration::from_secs(3600); // 1 hour
/// Consumed/expired OTP rows kept this long for forensics, then dropped.
const OTP_RETENTION_SECS: i64 = 86_400; // 24 h
/// Unverified accounts older than this get deleted, freeing the email +
/// username for re-registration. Generous so a user finishing signup a week
/// late still works.
const UNVERIFIED_USER_TTL_SECS: i64 = 7 * 86_400;

pub async fn run_signup_reaper(pool: PgPool) {
    tracing::info!(
        interval_secs = SWEEP_INTERVAL.as_secs(),
        otp_retention_secs = OTP_RETENTION_SECS,
        unverified_user_ttl_secs = UNVERIFIED_USER_TTL_SECS,
        "signup reaper started"
    );

    loop {
        tokio::time::sleep(SWEEP_INTERVAL).await;

        match email_verification_codes::reap_expired(&pool, OTP_RETENTION_SECS).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(reaped = n, "expired OTP rows reaped"),
            Err(e) => tracing::warn!("OTP reap query failed: {e}"),
        }

        match pending_totp_logins::reap_expired(&pool, OTP_RETENTION_SECS).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(reaped = n, "expired TOTP login tickets reaped"),
            Err(e) => tracing::warn!("TOTP login reap query failed: {e}"),
        }

        match reap_unverified_users(&pool, UNVERIFIED_USER_TTL_SECS).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(reaped = n, "abandoned unverified users reaped"),
            Err(e) => tracing::warn!("unverified-user reap query failed: {e}"),
        }
    }
}

/// Delete `users` rows where `email_verified_at IS NULL` and `created_at` is
/// older than `older_than_secs`. Cascades into related tables via FK
/// `ON DELETE CASCADE`.
async fn reap_unverified_users(pool: &PgPool, older_than_secs: i64) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(
        r#"
        DELETE FROM users
         WHERE email_verified_at IS NULL
           AND created_at < now() - make_interval(secs => $1)
        "#,
    )
    .bind(older_than_secs as f64)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
