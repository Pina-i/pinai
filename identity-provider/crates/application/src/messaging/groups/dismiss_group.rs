use std::sync::Arc;

use domain::identity::Accounts;
use domain::messaging::{Conversations, MessagingError};
use domain::{ConversationId, UserId};

use super::group_members;
use crate::messaging::shared::caller as caller_account;

/// `DELETE /api/groups/{id}`: someone removed from a group clears it from their list. Its
/// history goes with it, for them; being added again brings the group back.
pub struct DismissGroup {
    accounts: Arc<dyn Accounts>,
    conversations: Arc<dyn Conversations>,
}

impl DismissGroup {
    pub fn new(accounts: Arc<dyn Accounts>, conversations: Arc<dyn Conversations>) -> Self {
        Self {
            accounts,
            conversations,
        }
    }

    pub async fn execute(
        &self,
        caller: UserId,
        group: ConversationId,
    ) -> Result<(), MessagingError> {
        let account = caller_account(&*self.accounts, caller).await?;
        let members = group_members(&*self.conversations, group).await?;
        if members.iter().any(|m| m.actor_uri == account.actor_uri) {
            return Err(MessagingError::StillAMember);
        }
        if !self
            .conversations
            .dismiss(group, &account.actor_uri)
            .await?
        {
            return Err(MessagingError::ConversationNotFound);
        }
        Ok(())
    }
}
