use std::sync::Arc;

use domain::identity::{Accounts, ActorUri};
use domain::messaging::{
    Conversations, GroupNotifier, MessagingError, authorize_admin, may_stop_being_admin,
};
use domain::{ConversationId, UserId};

use super::{group_members, local_accounts};
use crate::messaging::shared::caller as caller_account;

/// `DELETE /api/groups/{id}/members/{actor}`: an admin removes a member, or a member leaves.
pub struct RemoveGroupMember {
    accounts: Arc<dyn Accounts>,
    conversations: Arc<dyn Conversations>,
    notifier: Arc<dyn GroupNotifier>,
}

impl RemoveGroupMember {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        conversations: Arc<dyn Conversations>,
        notifier: Arc<dyn GroupNotifier>,
    ) -> Self {
        Self {
            accounts,
            conversations,
            notifier,
        }
    }

    pub async fn execute(
        &self,
        caller: UserId,
        group: ConversationId,
        actor: ActorUri,
    ) -> Result<(), MessagingError> {
        let remover = caller_account(&*self.accounts, caller).await?;
        let leaving = actor == remover.actor_uri;
        // Taken before the removal, so the removed member's own sessions are told too.
        let members = group_members(&*self.conversations, group).await?;
        if !leaving {
            authorize_admin(&members, &remover.actor_uri)?;
        }
        if !may_stop_being_admin(&members, &actor) {
            return Err(MessagingError::LastAdmin);
        }
        if !self.conversations.remove_member(group, &actor).await? {
            return Err(MessagingError::MemberNotFound);
        }
        let by = (!leaving).then_some(&remover.actor_uri);
        for local in local_accounts(&*self.accounts, &members).await? {
            self.notifier.member_removed(local.id, group, &actor, by);
        }
        Ok(())
    }
}
