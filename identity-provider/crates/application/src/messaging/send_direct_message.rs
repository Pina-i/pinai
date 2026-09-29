use std::sync::Arc;

use domain::identity::{
    Account, Accounts, ActorUri, InstanceOrigin, Recipient, RemoteActor, RemoteActors,
};
use domain::messaging::{
    ConversationKind, Conversations, DirectDelivery, Message, MessageEvent, MessageNotifier,
    Messages, MessagingError, MlsCiphertext, NewMessage,
};
use domain::{AttachmentId, ConversationId, MessageId, UserId};

use super::shared::{address_of, caller, display_name_of};

pub struct DirectMessageCommand {
    pub recipient: Recipient,
    pub ciphertext: MlsCiphertext,
    pub reply_to: Option<MessageId>,
    pub attachments: Vec<AttachmentId>,
    /// The id the sender's client chose for a new DM: the MLS group it already bootstrapped.
    pub pinned: Option<ConversationId>,
    /// Echoed on the sender's own copy, so its client reconciles the optimistic message.
    pub client_id: Option<String>,
}

/// A message stored and announced — and, when it went to another instance, still to deliver:
/// the caller hands `delivery` to `DeliverDirectMessage` once it has answered.
#[must_use = "a message to another instance is only delivered by DeliverDirectMessage"]
pub struct Sent {
    pub message: Message,
    pub sender_display_name: String,
    pub delivery: Option<DirectDelivery>,
}

/// `POST /api/dm` and the WebSocket `send_dm`.
pub struct SendDirectMessage {
    origin: InstanceOrigin,
    max_attachments: usize,
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
    messages: Arc<dyn Messages>,
    notifier: Arc<dyn MessageNotifier>,
}

impl SendDirectMessage {
    pub fn new(
        origin: InstanceOrigin,
        max_attachments: usize,
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        conversations: Arc<dyn Conversations>,
        messages: Arc<dyn Messages>,
        notifier: Arc<dyn MessageNotifier>,
    ) -> Self {
        Self {
            origin,
            max_attachments,
            accounts,
            remote_actors,
            conversations,
            messages,
            notifier,
        }
    }

    pub async fn execute(
        &self,
        sender: UserId,
        command: DirectMessageCommand,
    ) -> Result<Sent, MessagingError> {
        if command.attachments.len() > self.max_attachments {
            return Err(MessagingError::TooManyAttachments(self.max_attachments));
        }
        let sender = caller(&*self.accounts, sender).await?;
        let parent = match command.reply_to {
            Some(id) => Some(
                self.messages
                    .find(id)
                    .await?
                    .ok_or(MessagingError::ParentNotFound)?,
            ),
            None => None,
        };
        let recipient = self.recipient(&sender, &command.recipient).await?;
        let conversation = self
            .conversations
            .open_dm(&sender.actor_uri, recipient.actor_uri(), command.pinned)
            .await?;
        if parent
            .as_ref()
            .is_some_and(|p| !p.can_be_answered_in(conversation))
        {
            return Err(MessagingError::ParentNotFound);
        }
        let id = MessageId::generate();
        let message = self
            .messages
            .record(&NewMessage {
                id,
                conversation,
                sender: sender.actor_uri.clone(),
                ciphertext: command.ciphertext,
                activity_uri: id.activity_uri(&sender.actor_uri),
                reply_to: command.reply_to,
                attachments: command.attachments,
            })
            .await?;

        let event = MessageEvent {
            message: message.clone(),
            kind: ConversationKind::Dm,
            sender_address: address_of(&sender),
            sender_display_name: Some(display_name_of(&sender)),
            client_id: None,
        };
        let own_copy = MessageEvent {
            client_id: command.client_id,
            ..event.clone()
        };
        let delivery = match recipient {
            To::Local(account) => {
                self.notifier.message(account.id, &event);
                self.notifier.message(sender.id, &own_copy);
                None
            }
            To::Remote(actor) => {
                // The recipient's own instance announces it to them once delivered.
                self.notifier.echo(sender.id, &own_copy);
                Some(DirectDelivery {
                    from: sender.clone(),
                    to: actor,
                    message: message.clone(),
                    reply_to: parent.map(|p| p.activity_uri),
                })
            }
        };
        Ok(Sent {
            message,
            sender_display_name: display_name_of(&sender),
            delivery,
        })
    }

    async fn recipient(
        &self,
        sender: &Account,
        recipient: &Recipient,
    ) -> Result<To, MessagingError> {
        match recipient {
            Recipient::Local(handle) => {
                let account = self
                    .accounts
                    .find_by_handle(handle)
                    .await?
                    .ok_or(MessagingError::RecipientNotFound)?;
                if account.id == sender.id {
                    return Err(MessagingError::SelfMessage);
                }
                Ok(To::Local(account))
            }
            Recipient::Remote(address) => {
                // The cache first: a WebFinger round trip per message would be too slow.
                let cached = match self.origin.conventional_uri(address) {
                    Some(uri) => self.remote_actors.find(&uri).await?,
                    None => None,
                };
                let actor = match cached {
                    Some(actor) => actor,
                    None => self.remote_actors.resolve(address).await?,
                };
                Ok(To::Remote(actor))
            }
        }
    }
}

enum To {
    Local(Account),
    Remote(RemoteActor),
}

impl To {
    fn actor_uri(&self) -> &ActorUri {
        match self {
            Self::Local(account) => &account.actor_uri,
            Self::Remote(actor) => &actor.actor_uri,
        }
    }
}

#[cfg(test)]
mod tests;
