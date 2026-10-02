use std::sync::Arc;

use domain::e2ee::{
    Append, Commit, CommitBlob, CommitLog, DeliveryError, Epoch, MlsFederation, MlsNotifier,
    NewCommit, may_commit,
};
use domain::identity::Accounts;
use domain::messaging::Conversations;
use domain::{ConversationId, UserId};

use super::group_roster::roster_of;

/// `POST /api/mls/groups/{id}/commits`: a member's commit at the next epoch, then to every
/// member — the proposer's own sessions too, so its other tabs keep up. A group's travels to
/// other instances with its roster.
pub struct AppendCommit {
    accounts: Arc<dyn Accounts>,
    conversations: Arc<dyn Conversations>,
    commits: Arc<dyn CommitLog>,
    notifier: Arc<dyn MlsNotifier>,
    federation: Arc<dyn MlsFederation>,
}

impl AppendCommit {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        conversations: Arc<dyn Conversations>,
        commits: Arc<dyn CommitLog>,
        notifier: Arc<dyn MlsNotifier>,
        federation: Arc<dyn MlsFederation>,
    ) -> Self {
        Self {
            accounts,
            conversations,
            commits,
            notifier,
            federation,
        }
    }

    pub async fn execute(
        &self,
        proposer: UserId,
        conversation: ConversationId,
        epoch: Epoch,
        blob: CommitBlob,
    ) -> Result<Commit, DeliveryError> {
        let account = self.accounts.find(proposer).await?.ok_or_else(|| {
            DeliveryError::Unexpected(anyhow::anyhow!("the proposer's account is gone"))
        })?;
        // A conversation exists before its MLS group: a DM from the friendship, a group from
        // its creation.
        let members = self.conversations.members(conversation).await?;
        if members.is_empty() {
            return Err(DeliveryError::ConversationNotFound);
        }
        if !may_commit(&members, &account.actor_uri) {
            return Err(DeliveryError::NotAMember);
        }
        let commit = match self
            .commits
            .append(&NewCommit {
                conversation,
                epoch,
                blob,
                proposer: account.actor_uri.clone(),
            })
            .await?
        {
            Append::Stored(commit) => commit,
            Append::Taken(winner) => return Err(DeliveryError::EpochTaken(Box::new(winner))),
        };
        let mut remote = Vec::new();
        for member in &members {
            if let Some(local) = self.accounts.find_by_uri(&member.actor_uri).await? {
                self.notifier.committed(local.id, &commit);
            } else {
                remote.push(member.actor_uri.clone());
            }
        }
        if !remote.is_empty() {
            let roster = roster_of(&*self.conversations, conversation).await?;
            self.federation
                .send_commit(&account.actor_uri, &remote, &commit, roster.as_ref());
        }
        Ok(commit)
    }
}
