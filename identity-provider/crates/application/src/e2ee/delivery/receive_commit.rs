use std::sync::Arc;

use domain::ConversationId;
use domain::e2ee::{
    Append, CommitBlob, CommitLog, DeliveryError, Epoch, MlsNotifier, NewCommit, may_commit,
};
use domain::identity::{Accounts, ActorUri};
use domain::messaging::Conversations;

/// A commit another instance delivered, by the activity's actor.
pub struct IncomingCommit {
    pub proposer: ActorUri,
    pub conversation: ConversationId,
    pub epoch: Epoch,
    pub blob: CommitBlob,
}

/// The inbox's `Create{Note}` carrying an MLS commit. A commit already at its epoch is a
/// redelivery, or a race another member won: either way there is nothing more to do.
pub struct ReceiveCommit {
    accounts: Arc<dyn Accounts>,
    conversations: Arc<dyn Conversations>,
    commits: Arc<dyn CommitLog>,
    notifier: Arc<dyn MlsNotifier>,
}

impl ReceiveCommit {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        conversations: Arc<dyn Conversations>,
        commits: Arc<dyn CommitLog>,
        notifier: Arc<dyn MlsNotifier>,
    ) -> Self {
        Self {
            accounts,
            conversations,
            commits,
            notifier,
        }
    }

    pub async fn execute(&self, incoming: IncomingCommit) -> Result<(), DeliveryError> {
        // A commit from outside would take an epoch the members need: their own commits there
        // would lose to it, and the group could not advance.
        let members = self.conversations.members(incoming.conversation).await?;
        if members.is_empty() {
            return Err(DeliveryError::ConversationNotFound);
        }
        if !may_commit(&members, &incoming.proposer) {
            return Err(DeliveryError::NotAMember);
        }
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
        for member in members {
            if let Some(local) = self.accounts.find_by_uri(&member.actor_uri).await? {
                self.notifier.committed(local.id, &commit);
            }
        }
        Ok(())
    }
}
