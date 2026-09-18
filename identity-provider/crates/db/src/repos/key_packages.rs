//! Repository for `key_packages` — single-use MLS KeyPackage bundles.
//!
//! Each row is consumed exactly once by `claim_one` (atomic via
//! `FOR UPDATE SKIP LOCKED`). The orphan-sweep deletes consumed and expired
//! rows on a schedule.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct KeyPackage {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub key_package: Vec<u8>,
    pub expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

/// One uploadable bundle: the bytes + the desired expiry.
pub struct PendingPackage<'a> {
    pub key_package: &'a [u8],
    pub expires_at: OffsetDateTime,
}

/// Bulk-insert a batch of KeyPackages for one device.
///
/// The caller is responsible for enforcing the per-device cap (the handler
/// does this via `count_available` before inserting).
pub async fn insert_batch(
    pool: &PgPool,
    user_id: Uuid,
    device_id: Uuid,
    packages: &[PendingPackage<'_>],
) -> Result<Vec<KeyPackage>, sqlx::Error> {
    if packages.is_empty() {
        return Ok(Vec::new());
    }

    // Build a single UNNEST-driven INSERT so the round-trip cost is constant
    // regardless of batch size.
    let blobs: Vec<&[u8]> = packages.iter().map(|p| p.key_package).collect();
    let expires: Vec<OffsetDateTime> = packages.iter().map(|p| p.expires_at).collect();

    sqlx::query_as::<_, KeyPackage>(
        r#"
        INSERT INTO key_packages (user_id, device_id, key_package, expires_at)
        SELECT $1, $2, blob, expires
        FROM UNNEST($3::bytea[], $4::timestamptz[]) AS t(blob, expires)
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .bind(blobs)
    .bind(expires)
    .fetch_all(pool)
    .await
}

/// Count unconsumed, unexpired KeyPackages for a single device.
pub async fn count_available(
    pool: &PgPool,
    user_id: Uuid,
    device_id: Uuid,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*) FROM key_packages
        WHERE user_id = $1
          AND device_id = $2
          AND consumed_at IS NULL
          AND expires_at > now()
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_one(pool)
    .await
}

/// Per-device counts for a single user — used by `GET /api/keys/packages/status`.
pub async fn count_per_device(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<(Uuid, i64)>, sqlx::Error> {
    sqlx::query_as::<_, (Uuid, i64)>(
        r#"
        SELECT device_id, COUNT(*) AS available
        FROM key_packages
        WHERE user_id = $1
          AND consumed_at IS NULL
          AND expires_at > now()
        GROUP BY device_id
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

/// Atomically reserve and return one available KeyPackage for `(user, device)`.
///
/// Uses `FOR UPDATE SKIP LOCKED` so concurrent claimers never serialize on
/// the same candidate row. Returns `None` if the device has no unconsumed
/// unexpired KeyPackages — caller responds with `503` and asks the peer to
/// retry after the user's client refreshes the stash.
pub async fn claim_one(
    pool: &PgPool,
    user_id: Uuid,
    device_id: Uuid,
) -> Result<Option<KeyPackage>, sqlx::Error> {
    sqlx::query_as::<_, KeyPackage>(
        r#"
        UPDATE key_packages
        SET consumed_at = now()
        WHERE id = (
            SELECT id FROM key_packages
            WHERE user_id = $1
              AND device_id = $2
              AND consumed_at IS NULL
              AND expires_at > now()
            ORDER BY created_at
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        )
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_optional(pool)
    .await
}

/// Atomically reserve and return one available KeyPackage for `user_id`,
/// picking *any* device that has spare capacity. Used by the cross-IdP
/// add-to-group path where the calling IdP doesn't know which of the
/// target user's devices to ask for.
///
/// Same FOR UPDATE SKIP LOCKED pattern as [`claim_one`]; the caller
/// receives the device_id back via the row, so the welcome can target
/// the right leaf.
pub async fn claim_one_any_device(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<KeyPackage>, sqlx::Error> {
    sqlx::query_as::<_, KeyPackage>(
        r#"
        UPDATE key_packages
        SET consumed_at = now()
        WHERE id = (
            SELECT id FROM key_packages
            WHERE user_id = $1
              AND consumed_at IS NULL
              AND expires_at > now()
            ORDER BY created_at
            LIMIT 1
            FOR UPDATE SKIP LOCKED
        )
        RETURNING *
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

/// Garbage-collect rows that are either expired or consumed > 1 day ago.
/// Called from the existing orphan-sweep background task.
pub async fn delete_old(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        DELETE FROM key_packages
        WHERE expires_at < now()
           OR consumed_at < now() - interval '1 day'
        "#,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
