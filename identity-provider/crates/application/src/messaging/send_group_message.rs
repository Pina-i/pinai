use std::sync::Arc;

use domain::identity::Accounts;
use domain::messaging::{
    ConversationKind, Conversations, GroupSnapshot, Member, Message, MessageEvent,
    MessageFederation, MessageNotifier, Messages, MessagingError, MlsCiphertext, NewMessage,
};
use domain::{AttachmentId, ConversationId, MessageId, UserId};

use super::shared::{address_of, audience, caller, display_name_of};

pub struct GroupMessageCommand {
    pub conversation: ConversationId,
    pub ciphertext: MlsCiphertext,
    pub reply_to: Option<MessageId>,
    pub attachments: Vec<AttachmentId>,
}

/// A message stored and announced, with the name it is shown under.
pub struct Posted {
    pub message: Message,
    pub sender_display_name: String,
}

/// `POST /api/groups/{id}/messages`: one ciphertext decrypts for the whole group, so the same
/// blob goes to every member.
pub struct SendGroupMessage {
    max_attachments: usize,
    accounts: Arc<dyn Accounts>,
    conversations: Arc<dyn Conversations>,
    messages: Arc<dyn Messages>,
    notifier: Arc<dyn MessageNotifier>,
    federation: Arc<dyn MessageFederation>,
}

impl SendGroupMessage {
    pub fn new(
        max_attachments: usize,
        accounts: Arc<dyn Accounts>,
        conversations: Arc<dyn Conversations>,
        messages: Arc<dyn Messages>,
        notifier: Arc<dyn MessageNotifier>,
        federation: Arc<dyn MessageFederation>,
    ) -> Self {
        Self {
            max_attachments,
            accounts,
            conversations,
            messages,
            notifier,
            federation,
        }
    }

    pub async fn execute(
        &self,
        sender: UserId,
        command: GroupMessageCommand,
    ) -> Result<Posted, MessagingError> {
        if command.attachments.len() > self.max_attachments {
            return Err(MessagingError::TooManyAttachments(self.max_attachments));
        }
        let sender = caller(&*self.accounts, sender).await?;
        let held = self.conversations.memberships(command.conversation).await?;
        let members: Vec<Member> = held
            .iter()
            .filter(|m| m.is_active())
            .map(|m| m.member.clone())
            .collect();
        if !members.iter().any(|m| m.actor_uri == sender.actor_uri) {
            return Err(MessagingError::ConversationNotFound);
        }
        let group = self
            .conversations
            .find(command.conversation)
            .await?
            .ok_or(MessagingError::ConversationNotFound)?;
        let parent = match command.reply_to {
            Some(id) => Some(
                self.messages
                    .find(id)
                    .await?
                    .filter(|p| p.can_be_answered_in(command.conversation))
                    .ok_or(MessagingError::ParentNotFound)?,
            ),
            None => None,
        };
        let id = MessageId::generate();
        let message = self
            .messages
            .record(&NewMessage {
                id,
                conversation: command.conversation,
                sender: sender.actor_uri.clone(),
                ciphertext: command.ciphertext,
                activity_uri: id.activity_uri(&sender.actor_uri),
                reply_to: command.reply_to,
                attachments: command.attachments,
            })
            .await?;

        let event = MessageEvent {
            message: message.clone(),
            kind: ConversationKind::Group,
            sender_address: address_of(&sender),
            sender_display_name: Some(display_name_of(&sender)),
            client_id: None,
        };
        let (local, remote) = audience(&*self.accounts, &members, &sender.actor_uri).await?;
        for member in &local {
            self.notifier.message(member.id, &event);
        }
        self.notifier.echo(sender.id, &event);
        // The roster rides along, so a member whose Welcome never landed still gets the group.
        self.federation.send_to_group(
            &sender,
            &remote,
            &message,
            parent.as_ref().map(|p| p.activity_uri.as_str()),
            &GroupSnapshot::of(&group, &held),
        );
        Ok(Posted {
            message,
            sender_display_name: display_name_of(&sender),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests;
