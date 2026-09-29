use std::sync::Arc;

use domain::identity::{Accounts, ActorUri, RemoteActors};
use domain::messaging::{
    Conversations, GroupNotifier, MessagingError, Role, authorize_admin, may_stop_being_admin,
};
use domain::{ConversationId, UserId};

use super::{MemberProfile, group_members, local_accounts, profile_of};
use crate::messaging::shared::caller as caller_account;

/// `POST /api/groups/{id}/members/{actor}/role`, by an admin.
pub struct SetMemberRole {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
    notifier: Arc<dyn GroupNotifier>,
}

impl SetMemberRole {
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
        actor: ActorUri,
        role: Role,
    ) -> Result<MemberProfile, MessagingError> {
        let admin = caller_account(&*self.accounts, caller).await?;
        let members = group_members(&*self.conversations, group).await?;
        authorize_admin(&members, &admin.actor_uri)?;
        if role == Role::Member && !may_stop_being_admin(&members, &actor) {
            return Err(MessagingError::LastAdmin);
        }
        let changed = self
            .conversations
            .set_role(group, &actor, role)
            .await?
            .ok_or(MessagingError::MemberNotFound)?;
        let members = self.conversations.members(group).await?;
        for local in local_accounts(&*self.accounts, &members).await? {
            self.notifier
                .role_changed(local.id, group, &changed, &admin.actor_uri);
        }
        profile_of(&*self.accounts, &*self.remote_actors, &changed).await
    }
}
