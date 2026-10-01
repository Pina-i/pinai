use std::sync::Arc;

use domain::e2ee::{
    DeliveryError, MlsFederation, MlsNotifier, NewWelcome, OutgoingWelcome, Welcome, WelcomeBlob,
    Welcomes, check_welcome,
};
use domain::identity::{Accounts, ActorUri, InstanceOrigin, RemoteActors};
use domain::messaging::{ConversationKind, Conversations, GroupSnapshot};
use domain::social::Reachability;
use domain::{ConversationId, DeviceId, UserId};

/// `POST /api/mls/welcomes`: a Welcome for one device of `recipient` — waiting here for a local
/// account, sent to its instance for a remote one. The client never tells the two apart.
pub struct SendWelcome {
    origin: InstanceOrigin,
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
    welcomes: Arc<dyn Welcomes>,
    reach: Arc<dyn Reachability>,
    notifier: Arc<dyn MlsNotifier>,
    federation: Arc<dyn MlsFederation>,
}

impl SendWelcome {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        origin: InstanceOrigin,
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        conversations: Arc<dyn Conversations>,
        welcomes: Arc<dyn Welcomes>,
        reach: Arc<dyn Reachability>,
        notifier: Arc<dyn MlsNotifier>,
        federation: Arc<dyn MlsFederation>,
    ) -> Self {
        Self {
            origin,
            accounts,
            remote_actors,
            conversations,
            welcomes,
            reach,
            notifier,
            federation,
        }
    }

    /// The Welcome stored for a local recipient; `None` once sent to another instance.
    pub async fn execute(
        &self,
        sender: UserId,
        recipient: &ActorUri,
        device: DeviceId,
        conversation: ConversationId,
        blob: WelcomeBlob,
    ) -> Result<Option<Welcome>, DeliveryError> {
        let sender = self.accounts.find(sender).await?.ok_or_else(|| {
            DeliveryError::Unexpected(anyhow::anyhow!("the sender's account is gone"))
        })?;
        let local = if self.origin.owns(recipient) {
            Some(
                self.accounts
                    .find_by_uri(recipient)
                    .await?
                    .ok_or(DeliveryError::RecipientNotFound)?,
            )
        } else {
            None
        };
        let members = self.conversations.members(conversation).await?;
        if members.is_empty() {
            return Err(DeliveryError::ConversationNotFound);
        }
        check_welcome(&members, &sender.actor_uri, recipient)?;
        if let Some(account) = local {
            // Joining a group went through its own checks; a 1:1 has none but this one.
            let is_dm = self
                .conversations
                .find(conversation)
                .await?
                .is_some_and(|c| c.kind == ConversationKind::Dm);
            if is_dm && account.id != sender.id {
                self.reach
                    .relation(account.id, &sender.actor_uri)
                    .await?
                    .admits()?;
            }
            let welcome = self
                .welcomes
                .deposit(&NewWelcome {
                    recipient: account.id,
                    device,
                    conversation,
                    blob,
                })
                .await?;
            self.notifier.welcome_ready(account.id, &welcome);
            return Ok(Some(welcome));
        }
        let roster = match self.conversations.find(conversation).await? {
            Some(group) if group.kind == ConversationKind::Group => Some(GroupSnapshot {
                name: group.name,
                members,
            }),
            _ => None,
        };
        let to = match self.remote_actors.find(recipient).await? {
            Some(actor) => actor,
            None => self.remote_actors.discover(recipient).await?,
        };
        self.federation.send_welcome(
            &sender.actor_uri,
            &to,
            &OutgoingWelcome {
                device,
                conversation,
                blob,
                roster,
            },
        );
        Ok(None)
    }
}
