use std::sync::Arc;

use domain::identity::{Accounts, RemoteActors};
use domain::messaging::{
    Conversations, MessageFederation, MessageNotifier, Messages, MessagingError, MlsCiphertext,
};
use domain::{MessageId, UserId};

use super::Posted;
use super::shared::{self, audience, display_name_of};

/// `PATCH /api/dm/{id}/edit`: the sender replaces a message's ciphertext; the server stays
/// opaque to what changed.
pub struct EditMessage {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
    messages: Arc<dyn Messages>,
    notifier: Arc<dyn MessageNotifier>,
    federation: Arc<dyn MessageFederation>,
}

impl EditMessage {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        conversations: Arc<dyn Conversations>,
        messages: Arc<dyn Messages>,
        notifier: Arc<dyn MessageNotifier>,
        federation: Arc<dyn MessageFederation>,
    ) -> Self {
        Self {
            accounts,
            remote_actors,
            conversations,
            messages,
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
        let edited = self
            .messages
            .edit(message, &editor.actor_uri, &ciphertext)
            .await?
            .ok_or(MessagingError::MessageNotFound)?;
        let members = self.conversations.members(edited.conversation).await?;
        let (local, remote) = audience(
            &*self.accounts,
            &*self.remote_actors,
            &members,
            &editor.actor_uri,
        )
        .await?;
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
