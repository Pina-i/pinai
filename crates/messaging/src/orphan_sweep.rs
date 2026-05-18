//! Background task that reaps three kinds of stale rows on the same cadence:
//!
//! - **Orphan attachments** — rows whose `message_id` is still `NULL` after
//!   `attachment_orphan_ttl` (ie. uploaded but never linked to a message).
//! - **Stale `key_packages`** — rows past their `expires_at`, or rows
//!   `consumed_at > 1 day` ago (the consumed grace window protects against
//!   late retries that re-fetch a just-claimed bundle).
//! - **Stale `mls_welcomes`** — same `consumed_at > 1 day` grace window so
//!   a client with a flaky connection that re-fetches mid-read sees an
//!   empty list rather than receiving the same bundle twice.
//!
//! Mirrors the lifecycle of presence's `run_heartbeat_sweep`:
//! a single long-running task spawned from `server::main`, sleeping between
//! passes, logging on error and continuing.

use std::sync::Arc;
use std::time::Duration;

use idp_config::Config;
use idp_db::PgPool;
use idp_storage::StorageClient;
use time::OffsetDateTime;

use crate::attachments::delete_attachment_with_object;

/// How often the sweep runs. Independent of `attachment_orphan_ttl` — the
/// sweep cadence just controls how soon expired orphans are noticed.
const SWEEP_INTERVAL: Duration = Duration::from_secs(300); // 5 min

/// Run forever, deleting orphan attachments older than `config.attachment_orphan_ttl`.
///
/// Storage may be `None` if object storage isn't configured — DB rows are
/// still cleaned up; storage objects (which won't exist anyway in that case)
/// are silently skipped.
pub async fn run_orphan_sweep(
    pool: PgPool,
    storage: Option<StorageClient>,
    config: Arc<Config>,
) {
    tracing::info!(
        interval_secs = SWEEP_INTERVAL.as_secs(),
        ttl_secs = config.attachment_orphan_ttl.as_secs(),
        "attachment orphan sweep started"
    );

    loop {
        tokio::time::sleep(SWEEP_INTERVAL).await;

        let cutoff = OffsetDateTime::now_utc()
            - time::Duration::seconds(config.attachment_orphan_ttl.as_secs() as i64);

        match idp_db::repos::attachments::find_orphans_older_than(&pool, cutoff).await {
            Ok(rows) => {
                if !rows.is_empty() {
                    tracing::info!(count = rows.len(), "reaping orphan attachments");
                    for row in &rows {
                        delete_attachment_with_object(&pool, storage.as_ref(), row).await;
                    }
                }
            }
            Err(e) => {
                tracing::warn!("orphan attachment sweep query failed: {e}");
            }
        }

        // Garbage-collect expired / long-consumed KeyPackages. Independent
        // pass — failures here don't block the attachment cleanup above.
        match idp_db::repos::key_packages::delete_old(&pool).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(count = n, "reaped stale key_packages rows"),
            Err(e) => tracing::warn!("key_packages sweep failed: {e}"),
        }

        // Garbage-collect long-consumed MLS welcomes. Same grace window as
        // KeyPackages so a flaky-connection re-fetch can't be told "here's
        // your Welcome again".
        match idp_db::repos::mls_welcomes::delete_old(&pool).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(count = n, "reaped stale mls_welcomes rows"),
            Err(e) => tracing::warn!("mls_welcomes sweep failed: {e}"),
        }
    }
}
