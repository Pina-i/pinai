use std::sync::Arc;

use domain::messaging::{AttachmentError, Attachments, ObjectStore};
use time::{Duration, OffsetDateTime};

/// Uploads never sent within `ttl` are deleted, bytes and record.
pub struct SweepOrphanAttachments {
    ttl: Duration,
    attachments: Arc<dyn Attachments>,
    objects: Arc<dyn ObjectStore>,
}

impl SweepOrphanAttachments {
    pub fn new(
        ttl: Duration,
        attachments: Arc<dyn Attachments>,
        objects: Arc<dyn ObjectStore>,
    ) -> Self {
        Self {
            ttl,
            attachments,
            objects,
        }
    }

    /// How many orphans were reaped.
    pub async fn execute(&self, now: OffsetDateTime) -> Result<usize, AttachmentError> {
        let orphans = self.attachments.orphans_older_than(now - self.ttl).await?;
        for orphan in &orphans {
            // A failed object delete leaves bytes nothing points at: harmless, and logged.
            if orphan.remote_url.is_none()
                && let Err(e) = self.objects.delete(orphan.id).await
            {
                tracing::warn!(attachment = %orphan.id, error = ?e, "orphan's object not deleted");
            }
            self.attachments.delete(orphan.id).await?;
        }
        Ok(orphans.len())
    }
}
