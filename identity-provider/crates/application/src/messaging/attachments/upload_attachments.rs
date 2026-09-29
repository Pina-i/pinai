use std::sync::Arc;

use domain::identity::Accounts;
use domain::messaging::{
    Attachment, AttachmentError, AttachmentLimits, AttachmentView, Attachments, ObjectStore,
    UploadFile,
};
use domain::{AttachmentId, UserId};

/// `POST /api/attachments`: files the uploader will attach to a message, recorded as orphans
/// until then.
pub struct UploadAttachments {
    limits: AttachmentLimits,
    accounts: Arc<dyn Accounts>,
    attachments: Arc<dyn Attachments>,
    objects: Arc<dyn ObjectStore>,
}

impl UploadAttachments {
    pub fn new(
        limits: AttachmentLimits,
        accounts: Arc<dyn Accounts>,
        attachments: Arc<dyn Attachments>,
        objects: Arc<dyn ObjectStore>,
    ) -> Self {
        Self {
            limits,
            accounts,
            attachments,
            objects,
        }
    }

    /// `chosen` is the id a client picked for a single file: it binds it into the encryption.
    pub async fn execute(
        &self,
        uploader: UserId,
        files: Vec<UploadFile>,
        chosen: Option<AttachmentId>,
    ) -> Result<Vec<AttachmentView>, AttachmentError> {
        self.limits.check_batch(files.len(), chosen.is_some())?;
        let uploader =
            self.accounts.find(uploader).await?.ok_or_else(|| {
                AttachmentError::Unexpected(anyhow::anyhow!("the uploader is gone"))
            })?;
        let mut stored = Vec::new();
        let mut recorded = Vec::new();
        let mut views = Vec::new();
        for file in files {
            let upload = Attachment {
                id: chosen.unwrap_or_else(AttachmentId::generate),
                uploader: uploader.actor_uri.clone(),
                message: None,
                mime_type: file.mime_type().to_owned(),
                byte_size: file.len() as i64,
                original_filename: file.filename().to_owned(),
                remote_url: None,
            };
            // The record first: an id already taken — a client may choose it — must never reach
            // the object store, where it would replace the other attachment's bytes.
            match self.attachments.record_upload(&upload).await {
                Ok(true) => recorded.push(upload.id),
                Ok(false) => {
                    self.roll_back(&stored, &recorded).await;
                    return Err(AttachmentError::IdTaken);
                }
                Err(e) => {
                    self.roll_back(&stored, &recorded).await;
                    return Err(e.into());
                }
            }
            let mime_type = upload.mime_type.clone();
            if let Err(e) = self
                .objects
                .put(upload.id, file.into_bytes(), &mime_type)
                .await
            {
                self.roll_back(&stored, &recorded).await;
                return Err(e.into());
            }
            stored.push(upload.id);
            views.push(upload.view());
        }
        Ok(views)
    }

    /// Best effort: the orphan sweep reaps whatever this leaves.
    async fn roll_back(&self, stored: &[AttachmentId], recorded: &[AttachmentId]) {
        for id in stored {
            if let Err(e) = self.objects.delete(*id).await {
                tracing::warn!(attachment = %id, error = ?e, "rollback: object not deleted");
            }
        }
        for id in recorded {
            if let Err(e) = self.attachments.delete(*id).await {
                tracing::warn!(attachment = %id, error = ?e, "rollback: record not deleted");
            }
        }
    }
}
