use std::sync::Arc;

use domain::AttachmentId;
use domain::identity::ActorUri;
use domain::messaging::{
    AttachmentError, Attachments, Conversations, Messages, ObjectStore, peer_may_fetch,
};

use super::Blob;

/// `GET /api/attachments/{id}/content`: another instance fetches, for its members, the bytes of an
/// attachment uploaded here.
pub struct ServePeerContent {
    attachments: Arc<dyn Attachments>,
    messages: Arc<dyn Messages>,
    conversations: Arc<dyn Conversations>,
    objects: Arc<dyn ObjectStore>,
}

impl ServePeerContent {
    pub fn new(
        attachments: Arc<dyn Attachments>,
        messages: Arc<dyn Messages>,
        conversations: Arc<dyn Conversations>,
        objects: Arc<dyn ObjectStore>,
    ) -> Self {
        Self {
            attachments,
            messages,
            conversations,
            objects,
        }
    }

    /// `peer` is the actor whose key signed the request.
    pub async fn execute(
        &self,
        peer: &ActorUri,
        id: AttachmentId,
    ) -> Result<Blob, AttachmentError> {
        let attachment = self
            .attachments
            .find(id)
            .await?
            .ok_or(AttachmentError::NotFound)?;
        // Only the instance an upload was made on serves it.
        if attachment.remote_url.is_some() {
            return Err(AttachmentError::NotHostedHere);
        }
        let message = attachment.message.ok_or(AttachmentError::Unlinked)?;
        let message = self
            .messages
            .find(message)
            .await?
            .ok_or(AttachmentError::MessageMissing)?;
        let members = self.conversations.members(message.conversation).await?;
        if !peer_may_fetch(&members, peer) {
            return Err(AttachmentError::PeerNotInConversation);
        }
        Ok(Blob {
            bytes: self.objects.get(id).await?,
            mime_type: attachment.mime_type,
            original_filename: attachment.original_filename,
        })
    }
}
