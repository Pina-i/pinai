use std::sync::Arc;

use domain::UserId;
use domain::identity::Accounts;
use domain::messaging::{ConversationSummary, Conversations, MessagingError};

use super::shared;

/// `GET /api/dm`: the caller's conversations, the most recently active first.
pub struct ListConversations {
    accounts: Arc<dyn Accounts>,
    conversations: Arc<dyn Conversations>,
}

impl ListConversations {
    pub fn new(accounts: Arc<dyn Accounts>, conversations: Arc<dyn Conversations>) -> Self {
        Self {
            accounts,
            conversations,
        }
    }

    pub async fn execute(
        &self,
        caller: UserId,
    ) -> Result<Vec<ConversationSummary>, MessagingError> {
        let account = shared::caller(&*self.accounts, caller).await?;
        Ok(self
            .conversations
            .list_for(account.id, &account.actor_uri)
            .await?)
    }
}

#[cfg(test)]
mod tests;
