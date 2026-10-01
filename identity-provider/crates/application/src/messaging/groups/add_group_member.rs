use std::sync::Arc;

use domain::identity::{Accounts, ActorUri, InstanceOrigin, RemoteActors};
use domain::messaging::{
    Conversations, GroupNotifier, Member, MessagingError, Role, authorize_admin,
};
use domain::social::Reachability;
use domain::{ConversationId, UserId};

use super::{Invitees, MemberProfile, group_members, local_accounts, may_add, profile_of};
use crate::messaging::shared::caller as caller_account;

/// `POST /api/groups/{id}/members`, by an admin. The MLS Welcome the client posts delivers the
/// keys; this only records the membership.
pub struct AddGroupMember {
    origin: InstanceOrigin,
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
    reach: Arc<dyn Reachability>,
    notifier: Arc<dyn GroupNotifier>,
}

impl AddGroupMember {
    pub fn new(
        origin: InstanceOrigin,
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        conversations: Arc<dyn Conversations>,
        reach: Arc<dyn Reachability>,
        notifier: Arc<dyn GroupNotifier>,
    ) -> Self {
        Self {
            origin,
            accounts,
            remote_actors,
            conversations,
            reach,
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
        may_add(&self.invitees(), &admin, &actor).await?;
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

impl AddGroupMember {
    fn invitees(&self) -> Invitees<'_> {
        Invitees {
            origin: &self.origin,
            accounts: &*self.accounts,
            remote_actors: &*self.remote_actors,
            reach: &*self.reach,
        }
    }
}
