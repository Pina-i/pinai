use std::sync::Arc;

use domain::UserId;
use domain::identity::ActorUri;
use domain::messaging::{
    ConversationKind, Conversations, MessageNotifier, Messages, MessagingError, MlsCiphertext,
};
use domain::social::Reachability;

/// An edit another instance delivered: the new ciphertext of a message its sender sent.
pub struct IncomingEdit {
    pub recipient: UserId,
    pub sender: ActorUri,
    /// The activity that published the message being edited.
    pub activity_uri: String,
    pub ciphertext: MlsCiphertext,
}

/// The inbox's `Update{Note}`. In a 1:1, an edit is a message: it reaches only whom the sender
/// could write to.
pub struct ReceiveEdit {
    conversations: Arc<dyn Conversations>,
    messages: Arc<dyn Messages>,
    reach: Arc<dyn Reachability>,
    notifier: Arc<dyn MessageNotifier>,
}

impl ReceiveEdit {
    pub fn new(
        conversations: Arc<dyn Conversations>,
        messages: Arc<dyn Messages>,
        reach: Arc<dyn Reachability>,
        notifier: Arc<dyn MessageNotifier>,
    ) -> Self {
        Self {
            conversations,
            messages,
            reach,
            notifier,
        }
    }

    pub async fn execute(&self, edit: IncomingEdit) -> Result<(), MessagingError> {
        let original = self
            .messages
            .find_by_activity(&edit.activity_uri)
            .await?
            .filter(|m| m.sender == edit.sender);
        if let Some(original) = original {
            let is_dm = self
                .conversations
                .find(original.conversation)
                .await?
                .is_some_and(|c| c.kind == ConversationKind::Dm);
            if is_dm {
                self.reach
                    .relation(edit.recipient, &edit.sender)
                    .await?
                    .admits()?;
            }
        }
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
