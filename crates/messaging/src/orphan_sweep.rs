//! Background task that reaps orphan attachments — rows whose `message_id` is
//! still NULL after `attachment_orphan_ttl`.
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
                if rows.is_empty() {
                    continue;
                }
                tracing::info!(count = rows.len(), "reaping orphan attachments");
                for row in &rows {
                    delete_attachment_with_object(&pool, storage.as_ref(), row).await;
                }
            }
            Err(e) => {
                tracing::warn!("orphan sweep query failed: {e}");
            }
        }
    }
}
