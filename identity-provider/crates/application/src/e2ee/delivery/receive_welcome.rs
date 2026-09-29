use std::sync::Arc;

use domain::e2ee::{DeliveryError, MlsNotifier, NewWelcome, WelcomeBlob, Welcomes, check_welcome};
use domain::identity::{Accounts, ActorUri};
use domain::messaging::{Conversations, GroupNotifier, GroupSnapshot};
use domain::{ConversationId, DeviceId, UserId};

/// A Welcome another instance delivered for a device of one of our accounts.
pub struct IncomingWelcome {
    pub recipient: UserId,
    pub sender: ActorUri,
    pub conversation: ConversationId,
    pub device: DeviceId,
    pub blob: WelcomeBlob,
    /// A group's roster: the Welcome is this instance's one chance to hold the group.
    pub roster: Option<GroupSnapshot>,
}

/// The inbox's `Create{Note}` carrying an MLS Welcome.
pub struct ReceiveWelcome {
    accounts: Arc<dyn Accounts>,
    conversations: Arc<dyn Conversations>,
    welcomes: Arc<dyn Welcomes>,
    notifier: Arc<dyn MlsNotifier>,
    groups: Arc<dyn GroupNotifier>,
}

impl ReceiveWelcome {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        conversations: Arc<dyn Conversations>,
        welcomes: Arc<dyn Welcomes>,
        notifier: Arc<dyn MlsNotifier>,
        groups: Arc<dyn GroupNotifier>,
    ) -> Self {
        Self {
            accounts,
            conversations,
            welcomes,
            notifier,
            groups,
        }
    }

    pub async fn execute(&self, incoming: IncomingWelcome) -> Result<(), DeliveryError> {
        let recipient = self
            .accounts
            .find(incoming.recipient)
            .await?
            .ok_or_else(|| {
                DeliveryError::Unexpected(anyhow::anyhow!("the recipient's account is gone"))
            })?;
        if let Some(roster) = &incoming.roster {
            crate::messaging::shared::mirror(
                &*self.conversations,
                &*self.groups,
                &recipient,
                &incoming.sender,
                incoming.conversation,
                roster,
            )
            .await?;
        }
        let members = match self.conversations.find(incoming.conversation).await? {
            Some(_) => self.conversations.members(incoming.conversation).await?,
            // A DM's Welcome can outrun the friendship's Accept: it opens the pair's DM, as the
            // first message would — under its id, or not at all.
            None if incoming.roster.is_none() => {
                let dm = self
                    .conversations
                    .open_dm(
                        &incoming.sender,
                        &recipient.actor_uri,
                        Some(incoming.conversation),
                    )
                    .await?;
                if dm != incoming.conversation {
                    return Err(DeliveryError::NotAMember);
                }
                self.conversations.members(dm).await?
            }
            None => Vec::new(),
        };
        check_welcome(&members, &incoming.sender, &recipient.actor_uri)?;
        let welcome = self
            .welcomes
            .deposit(&NewWelcome {
                recipient: recipient.id,
                device: incoming.device,
                conversation: incoming.conversation,
                blob: incoming.blob,
            })
            .await?;
        self.notifier.welcome_ready(recipient.id, &welcome);
        Ok(())
    }
}
