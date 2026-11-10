use std::sync::Arc;

use domain::e2ee::{DeliveryError, GroupInfo, GroupInfos};
use domain::identity::Accounts;
use domain::messaging::Conversations;
use domain::{ConversationId, UserId};

/// `GET /api/mls/groups/{id}/group-info`: the group's newest GroupInfo, which a member's device
/// not in the group joins it by.
pub struct LoadGroupInfo {
    accounts: Arc<dyn Accounts>,
    conversations: Arc<dyn Conversations>,
    group_infos: Arc<dyn GroupInfos>,
}

impl LoadGroupInfo {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        conversations: Arc<dyn Conversations>,
        group_infos: Arc<dyn GroupInfos>,
    ) -> Self {
        Self {
            accounts,
            conversations,
            group_infos,
        }
    }

    pub async fn execute(
        &self,
        caller: UserId,
        conversation: ConversationId,
    ) -> Result<GroupInfo, DeliveryError> {
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
        self.group_infos
            .newest(conversation)
            .await?
            .ok_or(DeliveryError::NoGroupInfo)
    }
}
