use std::sync::Arc;

use domain::identity::{Accounts, ActorUri, RemoteActors};
use domain::messaging::{
    Conversations, GroupChange, GroupChangeKind, GroupEvent, GroupEvents, GroupFederation,
    GroupNotifier, MessagingError, Role, authorize_admin, may_stop_being_admin,
};
use domain::{ConversationId, UserId};

use super::{MemberProfile, announce, group_members, local_accounts, profile_of};
use crate::messaging::shared::{Timeline, caller as caller_account};

/// `POST /api/groups/{id}/members/{actor}/role`, by an admin.
pub struct SetMemberRole {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
    notifier: Arc<dyn GroupNotifier>,
    federation: Arc<dyn GroupFederation>,
    events: Arc<dyn GroupEvents>,
}

impl SetMemberRole {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        conversations: Arc<dyn Conversations>,
        notifier: Arc<dyn GroupNotifier>,
        federation: Arc<dyn GroupFederation>,
        events: Arc<dyn GroupEvents>,
    ) -> Self {
        Self {
            accounts,
            remote_actors,
            conversations,
            notifier,
            federation,
            events,
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
        let held = self.conversations.memberships(group).await?;
        let role_at = held
            .iter()
            .find(|m| m.is_active() && m.member.actor_uri == changed.actor_uri)
            .map(|m| m.role_at)
            .ok_or_else(|| anyhow::anyhow!("the member is no longer in the group"))?;
        let members: Vec<_> = held
            .into_iter()
            .filter(|m| m.is_active())
            .map(|m| m.member)
            .collect();
        for local in local_accounts(&*self.accounts, &members).await? {
            self.notifier
                .role_changed(local.id, group, &changed, &admin.actor_uri);
        }
        let change = GroupChange {
            group,
            by: admin.actor_uri.clone(),
            at: role_at,
            kind: GroupChangeKind::RoleChanged(changed.actor_uri.clone(), changed.role),
        };
        self.timeline()
            .record(&members, GroupEvent::of(&change))
            .await?;
        announce(&*self.accounts, &*self.federation, &admin, &members, change).await?;
        profile_of(&*self.accounts, &*self.remote_actors, &changed).await
    }
}

impl SetMemberRole {
    fn timeline(&self) -> Timeline<'_> {
        Timeline {
            accounts: &*self.accounts,
            remote_actors: &*self.remote_actors,
            events: &*self.events,
            notifier: &*self.notifier,
        }
    }
}
