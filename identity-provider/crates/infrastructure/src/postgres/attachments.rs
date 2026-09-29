use anyhow::Context;
use domain::AttachmentId;
use domain::identity::ActorUri;
use domain::messaging::{Attachment, Attachments, MessageStoreError};
use sqlx::PgPool;
use time::OffsetDateTime;

/// `message_attachments`.
pub struct PgAttachments {
    pool: PgPool,
}

impl PgAttachments {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct AttachmentRow {
    id: uuid::Uuid,
    message_id: Option<uuid::Uuid>,
    uploaded_by_actor_uri: String,
    mime_type: String,
    byte_size: i64,
    original_filename: String,
    remote_origin_url: Option<String>,
}

impl TryFrom<AttachmentRow> for Attachment {
    type Error = anyhow::Error;

    fn try_from(row: AttachmentRow) -> Result<Self, Self::Error> {
        Ok(Attachment {
            id: row.id.into(),
            uploader: ActorUri::parse(&row.uploaded_by_actor_uri)
                .context("message_attachments.uploaded_by_actor_uri")?,
            message: row.message_id.map(Into::into),
            mime_type: row.mime_type,
            byte_size: row.byte_size,
            original_filename: row.original_filename,
            remote_url: row.remote_origin_url,
        })
    }
}

const COLUMNS: &str = "id, message_id, uploaded_by_actor_uri, mime_type, byte_size, \
     original_filename, remote_origin_url";

#[async_trait::async_trait]
impl Attachments for PgAttachments {
    async fn find(&self, id: AttachmentId) -> Result<Option<Attachment>, MessageStoreError> {
        let row: Option<AttachmentRow> = sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM message_attachments WHERE id = $1"
        ))
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .context("find an attachment")?;
        Ok(row.map(Attachment::try_from).transpose()?)
    }

    async fn record_upload(&self, upload: &Attachment) -> Result<bool, MessageStoreError> {
        // The object's key is the attachment's id, which clients bind into its encryption.
        let recorded = sqlx::query(
            "INSERT INTO message_attachments \
                (id, uploaded_by_actor_uri, storage_key, mime_type, byte_size, original_filename) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
        )
        .bind(upload.id.as_uuid())
        .bind(upload.uploader.as_str())
        .bind(upload.id.to_string())
        .bind(&upload.mime_type)
        .bind(upload.byte_size)
        .bind(&upload.original_filename)
        .execute(&self.pool)
        .await
        .context("record an upload")?;
        Ok(recorded.rows_affected() == 1)
    }

    async fn delete(&self, id: AttachmentId) -> Result<(), MessageStoreError> {
        sqlx::query("DELETE FROM message_attachments WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&self.pool)
            .await
            .context("delete an attachment")?;
        Ok(())
    }

    async fn orphans_older_than(
        &self,
        cutoff: OffsetDateTime,
    ) -> Result<Vec<Attachment>, MessageStoreError> {
        let rows: Vec<AttachmentRow> = sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM message_attachments \
             WHERE message_id IS NULL AND created_at < $1"
        ))
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await
        .context("list orphan attachments")?;
        rows.into_iter()
            .map(|row| Attachment::try_from(row).map_err(MessageStoreError::from))
            .collect()
    }
}
