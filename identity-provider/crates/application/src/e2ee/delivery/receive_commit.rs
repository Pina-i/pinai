use std::sync::Arc;

use domain::e2ee::{
    Append, CommitBlob, CommitLog, DeliveryError, Epoch, GroupInfo, GroupInfoBlob, GroupInfos,
    MlsNotifier, NewCommit, may_commit,
};
use domain::identity::{Accounts, ActorUri, RemoteActors};
use domain::messaging::{Conversations, GroupEvents, GroupNotifier, GroupSnapshot};
use domain::social::Reachability;
use domain::{ConversationId, UserId};

use super::group_roster::Mirror;
use crate::messaging::shared::admits_group_note;

/// A commit another instance delivered, by the activity's actor.
pub struct IncomingCommit {
    /// The account whose inbox it came through.
    pub recipient: UserId,
    pub proposer: ActorUri,
    pub conversation: ConversationId,
    pub epoch: Epoch,
    pub blob: CommitBlob,
    /// The GroupInfo of the epoch the commit opens.
    pub group_info: GroupInfoBlob,
    /// A group's roster: the commit adding someone can outrun the Welcome that would bring the
    /// group here.
    pub roster: Option<GroupSnapshot>,
}

/// The inbox's `Create{Note}` carrying an MLS commit and its GroupInfo, kept when newer than the
/// one held — only a commit a client makes, as the proposer's instance took it. A commit already
/// at its epoch is a redelivery, or a race another member won: either way there is nothing more
/// to do.
pub struct ReceiveCommit {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
    commits: Arc<dyn CommitLog>,
    group_infos: Arc<dyn GroupInfos>,
    reach: Arc<dyn Reachability>,
    notifier: Arc<dyn MlsNotifier>,
    groups: Arc<dyn GroupNotifier>,
    events: Arc<dyn GroupEvents>,
}

impl ReceiveCommit {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        conversations: Arc<dyn Conversations>,
        commits: Arc<dyn CommitLog>,
        group_infos: Arc<dyn GroupInfos>,
        reach: Arc<dyn Reachability>,
        notifier: Arc<dyn MlsNotifier>,
        groups: Arc<dyn GroupNotifier>,
        events: Arc<dyn GroupEvents>,
    ) -> Self {
        Self {
            accounts,
            remote_actors,
            conversations,
            commits,
            group_infos,
            reach,
            notifier,
            groups,
            events,
        }
    }

    pub async fn execute(&self, incoming: IncomingCommit) -> Result<(), DeliveryError> {
        if incoming.blob.kind().is_none() {
            return Err(DeliveryError::NotACommit);
        }
        if let Some(roster) = &incoming.roster {
            let recipient = self
                .accounts
                .find(incoming.recipient)
                .await?
                .ok_or_else(|| {
                    DeliveryError::Unexpected(anyhow::anyhow!("the recipient's account is gone"))
                })?;
            let admitted = admits_group_note(
                &*self.conversations,
                &*self.reach,
                &recipient,
                &incoming.proposer,
                incoming.conversation,
                roster,
            )
            .await?;
            // Dropped, as a group message is: the members already here get their own copy.
            if !admitted {
                tracing::debug!(proposer = %incoming.proposer, "group commit dropped");
                return Ok(());
            }
            Mirror {
                accounts: &*self.accounts,
                remote_actors: &*self.remote_actors,
                conversations: &*self.conversations,
                reach: &*self.reach,
                groups: &*self.groups,
                events: &*self.events,
            }
            .apply(
                &recipient,
                &incoming.proposer,
                incoming.conversation,
                roster,
            )
            .await?;
        }
        // A commit from outside would take an epoch the members need: their own commits there
        // would lose to it, and the group could not advance.
        let members = self.conversations.members(incoming.conversation).await?;
        if members.is_empty() {
            return Err(DeliveryError::ConversationNotFound);
        }
        if !may_commit(&members, &incoming.proposer) {
            return Err(DeliveryError::NotAMember);
        }
        // Mirrored at its epoch, whatever the latest here: the proposer's instance placed it,
        // and its deliveries can arrive out of order.
        let commit = match self
            .commits
            .append(&NewCommit {
                conversation: incoming.conversation,
                epoch: incoming.epoch,
                blob: incoming.blob,
                proposer: incoming.proposer,
            })
            .await?
        {
            Append::Stored(commit) => commit,
            Append::Taken(_) => {
                tracing::debug!(conversation = %incoming.conversation, "inbound commit already at its epoch");
                return Ok(());
            }
        };
        self.group_infos
            .keep(
                commit.conversation,
                &GroupInfo {
                    epoch: commit.epoch,
                    blob: incoming.group_info,
                },
            )
            .await?;
        for member in members {
            if let Some(local) = self.accounts.find_by_uri(&member.actor_uri).await? {
                self.notifier.committed(local.id, &commit);
            }
        }
        Ok(())
    }
}
