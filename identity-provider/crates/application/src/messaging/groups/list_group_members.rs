use std::sync::Arc;

use domain::identity::{Accounts, RemoteActors};
use domain::messaging::{Conversations, MessagingError};
use domain::{ConversationId, UserId};

use super::{MemberProfile, group_members, profiles};
use crate::messaging::shared::caller as caller_account;

/// `GET /api/groups/{id}/members`, for members only.
pub struct ListGroupMembers {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
}

impl ListGroupMembers {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        conversations: Arc<dyn Conversations>,
    ) -> Self {
        Self {
            accounts,
            remote_actors,
            conversations,
        }
    }

    pub async fn execute(
        &self,
        caller: UserId,
        group: ConversationId,
    ) -> Result<Vec<MemberProfile>, MessagingError> {
        let reader = caller_account(&*self.accounts, caller).await?;
        let members = group_members(&*self.conversations, group).await?;
        if !members.iter().any(|m| m.actor_uri == reader.actor_uri) {
            return Err(MessagingError::ConversationNotFound);
        }
        profiles(&*self.accounts, &*self.remote_actors, &members).await
    }
}
