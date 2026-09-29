use std::sync::Arc;

use domain::identity::Accounts;
use domain::messaging::{Conversations, MessagingError};
use domain::{ConversationId, UserId};

use super::shared::member_account;

/// `POST /api/dm/{id}/read`: the caller has seen everything in the conversation so far.
pub struct MarkRead {
    accounts: Arc<dyn Accounts>,
    conversations: Arc<dyn Conversations>,
}

impl MarkRead {
    pub fn new(accounts: Arc<dyn Accounts>, conversations: Arc<dyn Conversations>) -> Self {
        Self {
            accounts,
            conversations,
        }
    }

    pub async fn execute(
        &self,
        caller: UserId,
        conversation: ConversationId,
    ) -> Result<(), MessagingError> {
        let reader =
            member_account(&*self.accounts, &*self.conversations, caller, conversation).await?;
        Ok(self
            .conversations
            .mark_read(reader.id, conversation)
            .await?)
    }
}

#[cfg(test)]
mod tests;
