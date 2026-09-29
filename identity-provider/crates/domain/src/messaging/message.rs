use time::OffsetDateTime;

use crate::identity::ActorUri;
use crate::{AttachmentId, ConversationId, MessageId, ValidationError};

use super::{AttachmentView, MlsCiphertext};

/// Where a message sent to another instance stands. Local deliveries stay `Pending`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Failed,
}

impl DeliveryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Delivered => "delivered",
            Self::Failed => "failed",
        }
    }
}

impl std::str::FromStr for DeliveryStatus {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "delivered" => Ok(Self::Delivered),
            "failed" => Ok(Self::Failed),
            other => Err(ValidationError::new(
                "delivery status",
                format!("unknown value {other:?}"),
            )),
        }
    }
}

// Both instances of a federated conversation see the same activity URI, so deriving the row id
// from it gives them one id to reference from inside encrypted bodies (reactions, edits, replies).
impl MessageId {
    /// The activity a message is published as: `{sender}/activities/{id}`.
    pub fn activity_uri(&self, sender: &ActorUri) -> String {
        format!("{sender}/activities/{self}")
    }

    /// The id of the message an activity carries: the activity URI's trailing UUID, or a fresh
    /// one when it has none.
    pub fn of_activity(uri: &str) -> Self {
        trailing_uuid(uri).map_or_else(Self::generate, Self::from)
    }
}

pub(super) fn trailing_uuid(uri: &str) -> Option<uuid::Uuid> {
    uri.rsplit('/').next()?.parse().ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: MessageId,
    pub conversation: ConversationId,
    pub sender: ActorUri,
    pub ciphertext: MlsCiphertext,
    pub activity_uri: String,
    pub delivery: DeliveryStatus,
    pub created_at: OffsetDateTime,
    pub edited_at: Option<OffsetDateTime>,
    pub reply_to: Option<MessageId>,
    pub attachments: Vec<AttachmentView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMessage {
    pub id: MessageId,
    pub conversation: ConversationId,
    pub sender: ActorUri,
    pub ciphertext: MlsCiphertext,
    pub activity_uri: String,
    pub reply_to: Option<MessageId>,
    /// Uploads of the sender's, each unlinked or linked to one of its undelivered messages.
    pub attachments: Vec<AttachmentId>,
}

impl Message {
    /// A reply names a message of its own conversation: one from another would thread a message
    /// under a parent its readers may never see, and link rows across conversations.
    pub fn can_be_answered_in(&self, conversation: ConversationId) -> bool {
        self.conversation == conversation
    }
}

/// The oldest message of the page already read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryCursor {
    pub created_at: OffsetDateTime,
    pub id: MessageId,
}

#[cfg(test)]
mod tests;
