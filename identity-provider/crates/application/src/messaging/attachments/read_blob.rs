use std::sync::Arc;

use domain::AttachmentId;
use domain::messaging::{
    AttachmentError, Attachments, BlobTokenError, BlobTokens, ObjectStore, RemoteFiles,
};

use super::Blob;

/// `GET /api/attachments/{id}/blob?token=`: the bytes, streamed through this instance whether it
/// holds them or another instance does. The token is the only authorisation.
pub struct ReadBlob {
    attachments: Arc<dyn Attachments>,
    tokens: Arc<dyn BlobTokens>,
    objects: Arc<dyn ObjectStore>,
    remote: Arc<dyn RemoteFiles>,
}

impl ReadBlob {
    pub fn new(
        attachments: Arc<dyn Attachments>,
        tokens: Arc<dyn BlobTokens>,
        objects: Arc<dyn ObjectStore>,
        remote: Arc<dyn RemoteFiles>,
    ) -> Self {
        Self {
            attachments,
            tokens,
            objects,
            remote,
        }
    }

    pub async fn execute(&self, id: AttachmentId, token: &str) -> Result<Blob, AttachmentError> {
        let (_, named) = self.tokens.verify(token).map_err(|e| match e {
            BlobTokenError::Expired => AttachmentError::TokenExpired,
            BlobTokenError::Invalid => AttachmentError::TokenInvalid,
        })?;
        // The path alone is never trusted: only the attachment the token names.
        if named != id {
            return Err(AttachmentError::TokenMismatch);
        }
        let attachment = self
            .attachments
            .find(id)
            .await?
            .ok_or(AttachmentError::NotFound)?;
        let bytes = match &attachment.remote_url {
            // A peer declared the size when it sent the message; it gets no more through here.
            Some(url) => self
                .remote
                .fetch(url)
                .await?
                .limited_to(u64::try_from(attachment.byte_size).unwrap_or(0)),
            None => self.objects.get(id).await?,
        };
        Ok(Blob {
            mime_type: attachment.mime_type,
            original_filename: attachment.original_filename,
            bytes,
        })
    }
}
