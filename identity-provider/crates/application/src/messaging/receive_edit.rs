use std::sync::Arc;

use domain::UserId;
use domain::identity::ActorUri;
use domain::messaging::{MessageNotifier, Messages, MessagingError, MlsCiphertext};

/// An edit another instance delivered: the new ciphertext of a message its sender sent.
pub struct IncomingEdit {
    pub recipient: UserId,
    pub sender: ActorUri,
    /// The activity that published the message being edited.
    pub activity_uri: String,
    pub ciphertext: MlsCiphertext,
}

/// The inbox's `Update{Note}`.
pub struct ReceiveEdit {
    messages: Arc<dyn Messages>,
    notifier: Arc<dyn MessageNotifier>,
}

impl ReceiveEdit {
    pub fn new(messages: Arc<dyn Messages>, notifier: Arc<dyn MessageNotifier>) -> Self {
        Self { messages, notifier }
    }

    pub async fn execute(&self, edit: IncomingEdit) -> Result<(), MessagingError> {
        let edited = self
            .messages
            .edit_by_activity(&edit.activity_uri, &edit.sender, &edit.ciphertext)
            .await?;
        match edited {
            Some(message) => self.notifier.edited(edit.recipient, &message),
            None => {
                tracing::warn!(activity = %edit.activity_uri, "edit of an unknown message, or not by its sender")
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
