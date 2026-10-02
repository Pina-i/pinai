use std::sync::Arc;

use domain::identity::{Accounts, ActorUri, RemoteActors};
use domain::messaging::{
    Conversations, GroupChange, GroupChangeKind, GroupEvent, GroupEvents, GroupFederation,
    GroupNotifier, MessagingError, authorize_admin, may_stop_being_admin,
};
use domain::{ConversationId, UserId};

use super::{announce, group_members, local_accounts};
use crate::messaging::shared::{Timeline, caller as caller_account};

/// `DELETE /api/groups/{id}/members/{actor}`: an admin removes a member, or a member leaves.
pub struct RemoveGroupMember {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
    notifier: Arc<dyn GroupNotifier>,
    federation: Arc<dyn GroupFederation>,
    events: Arc<dyn GroupEvents>,
}

impl RemoveGroupMember {
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

    fn timeline(&self) -> Timeline<'_> {
        Timeline {
            accounts: &*self.accounts,
            remote_actors: &*self.remote_actors,
            events: &*self.events,
            notifier: &*self.notifier,
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
        let by = (!leaving).then_some(&remover.actor_uri);
        if !self
            .conversations
            .remove_member(group, &actor, by, None)
            .await?
        {
            return Err(MessagingError::MemberNotFound);
        }
        for local in local_accounts(&*self.accounts, &members).await? {
            self.notifier.member_removed(local.id, group, &actor, by);
        }
        let left_at = self
            .conversations
            .departure(group, &actor)
            .await?
            .ok_or_else(|| anyhow::anyhow!("the member removed is still in the group"))?
            .left_at;
        let kind = if leaving {
            GroupChangeKind::Left
        } else {
            GroupChangeKind::Removed(actor)
        };
        let change = GroupChange {
            group,
            by: remover.actor_uri.clone(),
            at: left_at,
            kind,
        };
        self.timeline()
            .record(&members, GroupEvent::of(&change))
            .await?;
        // To everyone who was in it, the member removed too.
        announce(
            &*self.accounts,
            &*self.federation,
            &remover,
            &members,
            change,
        )
        .await
    }
}
