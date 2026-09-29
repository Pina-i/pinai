use std::sync::Arc;

use domain::identity::{Accounts, ActorUri, RemoteActors};
use domain::messaging::{
    Conversations, GroupNotifier, Member, MessagingError, Role, authorize_admin,
};
use domain::{ConversationId, UserId};

use super::{MemberProfile, group_members, local_accounts, profile_of};
use crate::messaging::shared::caller as caller_account;

/// `POST /api/groups/{id}/members`, by an admin. The MLS Welcome the client posts delivers the
/// keys; this only records the membership.
pub struct AddGroupMember {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
    notifier: Arc<dyn GroupNotifier>,
}

impl AddGroupMember {
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
    ) -> Result<MemberProfile, MessagingError> {
        let admin = caller_account(&*self.accounts, caller).await?;
        let members = group_members(&*self.conversations, group).await?;
        authorize_admin(&members, &admin.actor_uri)?;
        // Adding an active member again would silently reset their role.
        if members.iter().any(|m| m.actor_uri == actor) {
            return Err(MessagingError::AlreadyAMember);
        }
        let added = Member {
            actor_uri: actor,
            role: Role::Member,
        };
        self.conversations.add_member(group, &added).await?;
        let members = self.conversations.members(group).await?;
        for local in local_accounts(&*self.accounts, &members).await? {
            self.notifier
                .member_added(local.id, group, &added, &admin.actor_uri);
        }
        profile_of(&*self.accounts, &*self.remote_actors, &added).await
    }
}
