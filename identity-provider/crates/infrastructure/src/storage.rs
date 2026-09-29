//! The object store for attachment bytes, over the legacy S3 client (`idp-storage`).

use anyhow::Context;
use domain::AttachmentId;
use domain::messaging::{ByteStream, ObjectStore, ObjectStoreError};
use idp_storage::StorageClient;

/// `None` when no object storage is configured: every call then fails, as uploads cannot work.
pub struct S3ObjectStore {
    storage: Option<StorageClient>,
}

impl S3ObjectStore {
    pub fn new(storage: Option<StorageClient>) -> Self {
        Self { storage }
    }

    fn client(&self) -> Result<&StorageClient, ObjectStoreError> {
        Ok(self
            .storage
            .as_ref()
            .context("object storage is not configured")?)
    }
}

#[async_trait::async_trait]
impl ObjectStore for S3ObjectStore {
    async fn put(
        &self,
        id: AttachmentId,
        bytes: Vec<u8>,
        mime_type: &str,
    ) -> Result<(), ObjectStoreError> {
        self.client()?
            .upload_attachment(&id.to_string(), bytes, mime_type)
            .await
            .context("store an attachment's bytes")?;
        Ok(())
    }

    async fn get(&self, id: AttachmentId) -> Result<ByteStream, ObjectStoreError> {
        let (chunks, length) = self
            .client()?
            .fetch_attachment_stream(&id.to_string())
            .await
            .context("read an attachment's bytes")?;
        Ok(ByteStream {
            length: length.and_then(|n| u64::try_from(n).ok()),
            chunks: Box::pin(chunks),
        })
    }

    async fn delete(&self, id: AttachmentId) -> Result<(), ObjectStoreError> {
        self.client()?
            .delete_attachment(&id.to_string())
            .await
            .context("delete an attachment's bytes")?;
        Ok(())
    }
}
