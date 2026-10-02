use std::sync::Arc;

use domain::e2ee::{DeliveryError, MlsNotifier, NewWelcome, WelcomeBlob, Welcomes, check_welcome};
use domain::identity::{Accounts, ActorUri, RemoteActors};
use domain::messaging::{
    ConversationKind, Conversations, GroupEvents, GroupNotifier, GroupSnapshot,
};
use domain::social::Reachability;
use domain::{ConversationId, DeviceId, UserId};

use super::group_roster::Mirror;

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
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
    welcomes: Arc<dyn Welcomes>,
    reach: Arc<dyn Reachability>,
    notifier: Arc<dyn MlsNotifier>,
    groups: Arc<dyn GroupNotifier>,
    events: Arc<dyn GroupEvents>,
}

impl ReceiveWelcome {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        conversations: Arc<dyn Conversations>,
        welcomes: Arc<dyn Welcomes>,
        reach: Arc<dyn Reachability>,
        notifier: Arc<dyn MlsNotifier>,
        groups: Arc<dyn GroupNotifier>,
        events: Arc<dyn GroupEvents>,
    ) -> Self {
        Self {
            accounts,
            remote_actors,
            conversations,
            welcomes,
            reach,
            notifier,
            groups,
            events,
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
        let is_group = incoming.roster.is_some()
            || self
                .conversations
                .find(incoming.conversation)
                .await?
                .is_some_and(|c| c.kind == ConversationKind::Group);
        let joins = !self
            .conversations
            .members(incoming.conversation)
            .await?
            .iter()
            .any(|m| m.actor_uri == recipient.actor_uri);
        // The sender of a group's Welcome is who adds the recipient; a 1:1's is always checked.
        if !is_group || joins {
            self.reach
                .relation(recipient.id, &incoming.sender)
                .await?
                .admits()?;
        }
        if let Some(roster) = &incoming.roster {
            Mirror {
                accounts: &*self.accounts,
                remote_actors: &*self.remote_actors,
                conversations: &*self.conversations,
                groups: &*self.groups,
                events: &*self.events,
            }
            .apply(&recipient, &incoming.sender, incoming.conversation, roster)
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
