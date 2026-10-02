use std::sync::Arc;

use domain::identity::{Accounts, ActorUri, InstanceOrigin, RemoteActors};
use domain::messaging::{
    Conversations, GroupChange, GroupChangeKind, GroupEvent, GroupEvents, GroupFederation,
    GroupNotifier, MAX_MEMBERS, Member, MessagingError, Role, authorize_admin, has_room,
};
use domain::social::Reachability;
use domain::{ConversationId, UserId};

use super::{
    Invitees, MemberProfile, announce, group_members, local_accounts, may_add, profile_of,
};
use crate::messaging::shared::{Timeline, caller as caller_account};

/// `POST /api/groups/{id}/members`, by an admin. The MLS Welcome the client posts delivers the
/// keys; this only records the membership.
pub struct AddGroupMember {
    origin: InstanceOrigin,
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
    reach: Arc<dyn Reachability>,
    notifier: Arc<dyn GroupNotifier>,
    federation: Arc<dyn GroupFederation>,
    events: Arc<dyn GroupEvents>,
}

impl AddGroupMember {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        origin: InstanceOrigin,
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        conversations: Arc<dyn Conversations>,
        reach: Arc<dyn Reachability>,
        notifier: Arc<dyn GroupNotifier>,
        federation: Arc<dyn GroupFederation>,
        events: Arc<dyn GroupEvents>,
    ) -> Self {
        Self {
            origin,
            accounts,
            remote_actors,
            conversations,
            reach,
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
    ) -> Result<MemberProfile, MessagingError> {
        let admin = caller_account(&*self.accounts, caller).await?;
        let members = group_members(&*self.conversations, group).await?;
        authorize_admin(&members, &admin.actor_uri)?;
        // Adding an active member again would silently reset their role.
        if members.iter().any(|m| m.actor_uri == actor) {
            return Err(MessagingError::AlreadyAMember);
        }
        if !has_room(&members) {
            return Err(MessagingError::GroupFull(MAX_MEMBERS));
        }
        may_add(&self.invitees(), &admin, &actor).await?;
        let added = Member {
            actor_uri: actor,
            role: Role::Member,
        };
        self.conversations.add_member(group, &added).await?;
        let held = self.conversations.memberships(group).await?;
        let joined_at = held
            .iter()
            .find(|m| m.is_active() && m.member.actor_uri == added.actor_uri)
            .map(|m| m.joined_at)
            .ok_or_else(|| anyhow::anyhow!("the added member is not in the group"))?;
        let members: Vec<Member> = held
            .into_iter()
            .filter(|m| m.is_active())
            .map(|m| m.member)
            .collect();
        for local in local_accounts(&*self.accounts, &members).await? {
            self.notifier
                .member_added(local.id, group, &added, &admin.actor_uri);
        }
        let change = GroupChange {
            group,
            by: admin.actor_uri.clone(),
            at: joined_at,
            kind: GroupChangeKind::Added(added.actor_uri.clone()),
        };
        self.timeline()
            .record(&members, GroupEvent::of(&change))
            .await?;
        announce(&*self.accounts, &*self.federation, &admin, &members, change).await?;
        profile_of(&*self.accounts, &*self.remote_actors, &added).await
    }
}

impl AddGroupMember {
    fn timeline(&self) -> Timeline<'_> {
        Timeline {
            accounts: &*self.accounts,
            remote_actors: &*self.remote_actors,
            events: &*self.events,
            notifier: &*self.notifier,
        }
    }

    fn invitees(&self) -> Invitees<'_> {
        Invitees {
            origin: &self.origin,
            accounts: &*self.accounts,
            remote_actors: &*self.remote_actors,
            reach: &*self.reach,
        }
    }
}
