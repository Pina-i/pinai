//! The object stores for attachment bytes and avatars, over an S3-compatible server (RustFS).

mod client;
mod error;

pub use client::{StorageClient, StorageConfig};
pub use error::StorageError;

use anyhow::Context;
use domain::messaging::{ByteStream, ObjectStore, ObjectStoreError};
use domain::profile::{AvatarImage, AvatarStore, ImageKind, ProfileError};
use domain::{AttachmentId, UserId};

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

/// Avatars, in the public-read bucket browsers load them from.
pub struct S3AvatarStore {
    storage: Option<StorageClient>,
}

impl S3AvatarStore {
    pub fn new(storage: Option<StorageClient>) -> Self {
        Self { storage }
    }

    fn client(&self) -> Result<&StorageClient, ProfileError> {
        Ok(self
            .storage
            .as_ref()
            .context("object storage is not configured")?)
    }
}

#[async_trait::async_trait]
impl AvatarStore for S3AvatarStore {
    async fn put(&self, user: UserId, image: &AvatarImage) -> Result<String, ProfileError> {
        let url = self
            .client()?
            .upload_avatar(user.as_uuid(), image.bytes().to_vec(), image.kind().mime())
            .await
            .context("store an avatar")?;
        Ok(url)
    }

    async fn remove(&self, user: UserId, keep: Option<ImageKind>) -> Result<(), ProfileError> {
        self.client()?
            .delete_avatar(user.as_uuid(), keep.map(ImageKind::mime))
            .await
            .context("remove an account's avatars")?;
        Ok(())
    }
}
