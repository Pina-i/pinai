//! Per-device metadata for Settings → Devices. Inserted on first KP
//! publish per `(user_id, device_id)`; `last_seen_at` bumped on later
//! publishes. `mark_revoked` is idempotent.

use sqlx::PgPool;
use time::OffsetDateTime;
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
               paired_at, last_seen_at, revoked_at,
               drk_public_key, attestation_signature, attestation_kid,
               attestation_issued_at, attestation_expires_at
        FROM user_devices
        WHERE user_id = $1
        ORDER BY (revoked_at IS NOT NULL), last_seen_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

/// Persist the IdP-signed Device Root Key attestation for a device.
pub async fn set_attestation(
    pool: &PgPool,
    device_id: Uuid,
    drk_public_key: &[u8],
    attestation_signature: &[u8],
    attestation_kid: &str,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE user_devices
        SET drk_public_key         = $2,
            attestation_signature  = $3,
            attestation_kid        = $4,
            attestation_issued_at  = $5,
            attestation_expires_at = $6
        WHERE device_id = $1
        "#,
    )
    .bind(device_id)
    .bind(drk_public_key)
    .bind(attestation_signature)
    .bind(attestation_kid)
    .bind(issued_at)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Fetch a device row including its attestation columns.
pub async fn find_with_attestation(
    pool: &PgPool,
    device_id: Uuid,
) -> Result<Option<UserDevice>, sqlx::Error> {
    sqlx::query_as::<_, UserDevice>(
        r#"
        SELECT device_id, user_id, display_name, kind,
               paired_at, last_seen_at, revoked_at,
               drk_public_key, attestation_signature, attestation_kid,
               attestation_issued_at, attestation_expires_at
        FROM user_devices
        WHERE device_id = $1
        "#,
    )
    .bind(device_id)
    .fetch_optional(pool)
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
