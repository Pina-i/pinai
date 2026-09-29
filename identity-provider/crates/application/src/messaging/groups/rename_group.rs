use std::sync::Arc;

use domain::identity::{Accounts, RemoteActors};
use domain::messaging::{Conversations, GroupName, GroupNotifier, MessagingError, authorize_admin};
use domain::{ConversationId, UserId};

use super::{GroupView, group_members, local_accounts, profiles};
use crate::messaging::shared::caller as caller_account;

/// `PATCH /api/groups/{id}`, by an admin.
pub struct RenameGroup {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
    notifier: Arc<dyn GroupNotifier>,
}

impl RenameGroup {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        conversations: Arc<dyn Conversations>,
        notifier: Arc<dyn GroupNotifier>,
    ) -> Self {
        Self {
            accounts,
            remote_actors,
            conversations,
            notifier,
        }
    }

    pub async fn execute(
        &self,
        caller: UserId,
        group: ConversationId,
        name: GroupName,
    ) -> Result<GroupView, MessagingError> {
        let admin = caller_account(&*self.accounts, caller).await?;
        authorize_admin(
            &group_members(&*self.conversations, group).await?,
            &admin.actor_uri,
        )?;
        let renamed = self
            .conversations
            .rename_group(group, &name)
            .await?
            .ok_or(MessagingError::GroupNotFound)?;
        let members = self.conversations.members(group).await?;
        for local in local_accounts(&*self.accounts, &members).await? {
            self.notifier.renamed(local.id, &renamed, &admin.actor_uri);
        }
        Ok(GroupView {
            members: profiles(&*self.accounts, &*self.remote_actors, &members).await?,
            group: renamed,
        })
    }
}
