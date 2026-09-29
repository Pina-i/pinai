use std::sync::Arc;

use domain::e2ee::{CATCH_UP_LIMIT, Commit, CommitLog, DeliveryError, Epoch};
use domain::identity::Accounts;
use domain::messaging::Conversations;
use domain::{ConversationId, UserId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitPage {
    pub commits: Vec<Commit>,
    /// The page is full: another may follow, after its last epoch.
    pub has_more: bool,
}

/// `GET /api/mls/groups/{id}/commits?since=`: a member's catch-up, by epoch.
pub struct CatchUpCommits {
    accounts: Arc<dyn Accounts>,
    conversations: Arc<dyn Conversations>,
    commits: Arc<dyn CommitLog>,
}

impl CatchUpCommits {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        conversations: Arc<dyn Conversations>,
        commits: Arc<dyn CommitLog>,
    ) -> Self {
        Self {
            accounts,
            conversations,
            commits,
        }
    }

    pub async fn execute(
        &self,
        caller: UserId,
        conversation: ConversationId,
        since: Epoch,
    ) -> Result<CommitPage, DeliveryError> {
        let account = self.accounts.find(caller).await?.ok_or_else(|| {
            DeliveryError::Unexpected(anyhow::anyhow!("the caller's account is gone"))
        })?;
        let members = self.conversations.members(conversation).await?;
        if members.is_empty() {
            return Err(DeliveryError::ConversationNotFound);
        }
        if !members.iter().any(|m| m.actor_uri == account.actor_uri) {
            return Err(DeliveryError::NotAMember);
        }
        let commits = self
            .commits
            .since(conversation, since, CATCH_UP_LIMIT)
            .await?;
        Ok(CommitPage {
            has_more: commits.len() == CATCH_UP_LIMIT,
            commits,
        })
    }
}
