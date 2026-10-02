use std::sync::Arc;

use domain::identity::Accounts;
use domain::messaging::{
    ConversationKind, Conversations, MessageFederation, MessageNotifier, Messages, MessagingError,
    MlsCiphertext,
};
use domain::social::Reachability;
use domain::{MessageId, UserId};

use super::Posted;
use super::shared::{self, audience, display_name_of};

/// `PATCH /api/dm/{id}/edit`: the sender replaces a message's ciphertext; the server stays
/// opaque to what changed. In a 1:1, an edit is a message: it reaches only whom one could write
/// to.
pub struct EditMessage {
    accounts: Arc<dyn Accounts>,
    conversations: Arc<dyn Conversations>,
    messages: Arc<dyn Messages>,
    reach: Arc<dyn Reachability>,
    notifier: Arc<dyn MessageNotifier>,
    federation: Arc<dyn MessageFederation>,
}

impl EditMessage {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        conversations: Arc<dyn Conversations>,
        messages: Arc<dyn Messages>,
        reach: Arc<dyn Reachability>,
        notifier: Arc<dyn MessageNotifier>,
        federation: Arc<dyn MessageFederation>,
    ) -> Self {
        Self {
            accounts,
            conversations,
            messages,
            reach,
            notifier,
            federation,
        }
    }

    pub async fn execute(
        &self,
        caller: UserId,
        message: MessageId,
        ciphertext: MlsCiphertext,
    ) -> Result<Posted, MessagingError> {
        let editor = shared::caller(&*self.accounts, caller).await?;
        let original = self
            .messages
            .find(message)
            .await?
            .filter(|m| m.sender == editor.actor_uri)
            .ok_or(MessagingError::MessageNotFound)?;
        let members = self.conversations.members(original.conversation).await?;
        let is_dm = self
            .conversations
            .find(original.conversation)
            .await?
            .is_some_and(|c| c.kind == ConversationKind::Dm);
        if is_dm {
            for other in members.iter().filter(|m| m.actor_uri != editor.actor_uri) {
                self.reach
                    .relation(editor.id, &other.actor_uri)
                    .await?
                    .may_write()?;
                if let Some(local) = self.accounts.find_by_uri(&other.actor_uri).await? {
                    self.reach
                        .relation(local.id, &editor.actor_uri)
                        .await?
                        .admits()?;
                }
            }
        }
        let edited = self
            .messages
            .edit(message, &editor.actor_uri, &ciphertext)
            .await?
            .ok_or(MessagingError::MessageNotFound)?;
        let (local, remote) = audience(&*self.accounts, &members, &editor.actor_uri).await?;
        for member in &local {
            self.notifier.edited(member.id, &edited);
        }
        for actor in &remote {
            self.federation.send_edit(&editor, actor, &edited);
        }
        self.notifier.edit_echoed(editor.id, &edited);
        Ok(Posted {
            message: edited,
            sender_display_name: display_name_of(&editor),
        })
    }
}

#[cfg(test)]
mod tests;
