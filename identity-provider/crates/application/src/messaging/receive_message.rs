use std::sync::Arc;

use domain::identity::{Accounts, ActorUri, RemoteActors};
use domain::messaging::{
    AttachmentLimits, ConversationKind, Conversations, GroupNotifier, GroupSnapshot, MessageEvent,
    MessageNotifier, Messages, MessagingError, MlsCiphertext, NewMessage, OfferedAttachment,
};
use domain::social::Reachability;
use domain::{ConversationId, MessageId, UserId};

use super::shared::{address_of_actor, caller, mirror};

/// A message another instance delivered to one of our accounts.
pub struct IncomingMessage {
    pub recipient: UserId,
    pub sender: ActorUri,
    /// The id the sending instance files the conversation under.
    pub conversation: ConversationId,
    pub activity_uri: String,
    pub ciphertext: MlsCiphertext,
    /// The activity URI of the message it answers.
    pub in_reply_to: Option<String>,
    /// The roster a group message carries.
    pub group: Option<GroupSnapshot>,
    pub attachments: Vec<OfferedAttachment>,
}

/// The inbox's `Create{Note}` carrying an MLS application message.
pub struct ReceiveMessage {
    limits: AttachmentLimits,
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
    messages: Arc<dyn Messages>,
    reach: Arc<dyn Reachability>,
    notifier: Arc<dyn MessageNotifier>,
    groups: Arc<dyn GroupNotifier>,
}

impl ReceiveMessage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        limits: AttachmentLimits,
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        conversations: Arc<dyn Conversations>,
        messages: Arc<dyn Messages>,
        reach: Arc<dyn Reachability>,
        notifier: Arc<dyn MessageNotifier>,
        groups: Arc<dyn GroupNotifier>,
    ) -> Self {
        Self {
            limits,
            accounts,
            remote_actors,
            conversations,
            messages,
            reach,
            notifier,
            groups,
        }
    }

    pub async fn execute(&self, incoming: IncomingMessage) -> Result<(), MessagingError> {
        let recipient = caller(&*self.accounts, incoming.recipient).await?;
        if let Some(group) = &incoming.group {
            let joins = !self
                .conversations
                .members(incoming.conversation)
                .await?
                .iter()
                .any(|m| m.actor_uri == recipient.actor_uri);
            if joins {
                let roster: Vec<ActorUri> = group
                    .members
                    .iter()
                    .map(|m| m.member.actor_uri.clone())
                    .collect();
                let roster_holds_someone_blocked =
                    self.reach.blocks_any(recipient.id, &roster).await?;
                let admitted = self
                    .reach
                    .relation(recipient.id, &incoming.sender)
                    .await?
                    .admits_group_from(roster_holds_someone_blocked);
                // Dropped, not refused, and before the DM path could file it as a 1:1.
                if admitted.is_err() {
                    tracing::debug!(sender = %incoming.sender, "group message dropped");
                    return Ok(());
                }
            }
            mirror(
                &*self.conversations,
                &*self.groups,
                &recipient,
                &incoming.sender,
                incoming.conversation,
                group,
            )
            .await?;
        }
        // A group is filed by its id; a DM goes through the pair, which also heals one whose
        // members were only half recorded.
        let (conversation, kind) = match self.conversations.find(incoming.conversation).await? {
            Some(c) if c.kind == ConversationKind::Group => {
                let members = self.conversations.members(c.id).await?;
                if !members.iter().any(|m| m.actor_uri == incoming.sender) {
                    return Err(MessagingError::ConversationNotFound);
                }
                // Fanned out from a copy of the group that still lists them.
                if !members.iter().any(|m| m.actor_uri == recipient.actor_uri) {
                    tracing::debug!(sender = %incoming.sender, "group message to a non-member dropped");
                    return Ok(());
                }
                (c.id, ConversationKind::Group)
            }
            _ => {
                // Before the DM is opened, as for a local sender.
                self.reach
                    .relation(recipient.id, &incoming.sender)
                    .await?
                    .admits()?;
                let dm = self
                    .conversations
                    .open_dm(
                        &incoming.sender,
                        &recipient.actor_uri,
                        Some(incoming.conversation),
                    )
                    .await?;
                (dm, ConversationKind::Dm)
            }
        };
        // A parent from another conversation is not linked: the message stands on its own.
        let reply_to = match &incoming.in_reply_to {
            Some(parent) => self
                .messages
                .find_by_activity(parent)
                .await?
                .filter(|p| p.can_be_answered_in(conversation))
                .map(|p| p.id),
            None => None,
        };

        let mut attachments = Vec::new();
        for (i, offer) in self
            .limits
            .admit(&incoming.attachments, &incoming.sender)
            .into_iter()
            .enumerate()
        {
            match offer {
                Ok(attachment) => attachments.push(attachment),
                Err(reason) => tracing::warn!(idx = i, reason, "inbound attachment skipped"),
            }
        }
        let Some(message) = self
            .messages
            .record_received(
                &NewMessage {
                    id: MessageId::of_activity(&incoming.activity_uri),
                    conversation,
                    sender: incoming.sender.clone(),
                    ciphertext: incoming.ciphertext,
                    activity_uri: incoming.activity_uri,
                    reply_to,
                    attachments: Vec::new(),
                },
                &attachments,
            )
            .await?
        else {
            // Delivery is at least once: the copy already stored was announced then.
            tracing::debug!(sender = %incoming.sender, "redelivered message ignored");
            return Ok(());
        };

        let sender_display_name = self
            .remote_actors
            .find(&incoming.sender)
            .await?
            .and_then(|actor| actor.display_name);
        self.notifier.message(
            recipient.id,
            &MessageEvent {
                message,
                kind,
                sender_address: address_of_actor(&incoming.sender),
                sender_display_name,
                client_id: None,
            },
        );
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
