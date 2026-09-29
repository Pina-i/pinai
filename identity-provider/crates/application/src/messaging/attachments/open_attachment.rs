use std::sync::Arc;

use domain::identity::Accounts;
use domain::messaging::{
    Attachment, AttachmentError, Attachments, BlobTokens, Conversations, Messages,
};
use domain::{AttachmentId, UserId};
use time::OffsetDateTime;

pub struct OpenedAttachment {
    pub attachment: Attachment,
    /// A short-lived capability to its bytes.
    pub token: String,
    pub expires_at: OffsetDateTime,
}

/// `GET /api/attachments/{id}`: for its uploader, and the conversation it was sent in.
pub struct OpenAttachment {
    accounts: Arc<dyn Accounts>,
    attachments: Arc<dyn Attachments>,
    messages: Arc<dyn Messages>,
    conversations: Arc<dyn Conversations>,
    tokens: Arc<dyn BlobTokens>,
}

impl OpenAttachment {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        attachments: Arc<dyn Attachments>,
        messages: Arc<dyn Messages>,
        conversations: Arc<dyn Conversations>,
        tokens: Arc<dyn BlobTokens>,
    ) -> Self {
        Self {
            accounts,
            attachments,
            messages,
            conversations,
            tokens,
        }
    }

    pub async fn execute(
        &self,
        caller: UserId,
        id: AttachmentId,
    ) -> Result<OpenedAttachment, AttachmentError> {
        let reader =
            self.accounts.find(caller).await?.ok_or_else(|| {
                AttachmentError::Unexpected(anyhow::anyhow!("the caller is gone"))
            })?;
        let attachment = self
            .attachments
            .find(id)
            .await?
            .ok_or(AttachmentError::NotFound)?;
        let members = match attachment.message {
            Some(message) if attachment.uploader != reader.actor_uri => {
                let message = self
                    .messages
                    .find(message)
                    .await?
                    .ok_or(AttachmentError::MessageMissing)?;
                self.conversations.members(message.conversation).await?
            }
            _ => Vec::new(),
        };
        if !attachment.readable_by(&reader.actor_uri, &members) {
            return Err(AttachmentError::Forbidden);
        }
        let (token, expires_at) = self.tokens.mint(caller, id);
        Ok(OpenedAttachment {
            attachment,
            token,
            expires_at,
        })
    }
}
