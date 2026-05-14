//! `user_devices` repo — per-device metadata for the Settings → Devices view.
//!
//! Phase 6b. Inserted on first `POST /api/keys/packages` per
//! `(user_id, device_id)`, `last_seen_at` touched on every subsequent
//! publish. `mark_revoked` flips `revoked_at = now()` and is idempotent
//! (a second call is a no-op).

use sqlx::PgPool;
use uuid::Uuid;

use crate::models::UserDevice;

/// Insert a row for this `(user_id, device_id)` pair if it doesn't
/// exist, else just bump `last_seen_at`. The `display_name` and `kind`
/// are only persisted on the insert path — re-publishing under a new
/// browser/UA does NOT overwrite an earlier auto-detected name. This
/// matters once the rename UX lands in a follow-up: we don't want the
/// user's chosen name to be silently clobbered.
pub async fn upsert_device(
    pool: &PgPool,
    user_id: Uuid,
    device_id: Uuid,
    display_name: &str,
    kind: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO user_devices (device_id, user_id, display_name, kind)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (device_id) DO UPDATE
            SET last_seen_at = NOW()
        "#,
    )
    .bind(device_id)
    .bind(user_id)
    .bind(display_name)
    .bind(kind)
    .execute(pool)
    .await?;
    Ok(())
}

/// List every device for `user_id`, active rows first
/// (`revoked_at IS NULL` then `revoked_at NOT NULL`), each bucket
/// ordered by `last_seen_at DESC` so the most recently active device
/// surfaces at the top.
pub async fn list_user_devices(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<UserDevice>, sqlx::Error> {
    sqlx::query_as::<_, UserDevice>(
        r#"
        SELECT device_id, user_id, display_name, kind,
               paired_at, last_seen_at, revoked_at
        FROM user_devices
        WHERE user_id = $1
        ORDER BY (revoked_at IS NOT NULL), last_seen_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

/// Flag the row revoked. No-op if it's already revoked, or if the
/// `(user_id, device_id)` pair doesn't exist. Returns the number of
/// rows actually transitioned so handlers can 404 on cross-user
/// attempts.
pub async fn mark_revoked(
    pool: &PgPool,
    user_id: Uuid,
    device_id: Uuid,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE user_devices
        SET revoked_at = NOW()
        WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL
        "#,
    )
    .bind(device_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Returns true iff `(user_id, device_id)` exists. Used by the revoke
/// handler to disambiguate "already revoked" (200) from "not yours"
/// (404) when `mark_revoked` reports 0 rows.
pub async fn exists(
    pool: &PgPool,
    user_id: Uuid,
    device_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let row: Option<(i32,)> = sqlx::query_as(
        r#"
        SELECT 1
        FROM user_devices
        WHERE device_id = $1 AND user_id = $2
        "#,
    )
    .bind(device_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}
