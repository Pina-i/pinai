use std::sync::Arc;

use domain::UserId;
use domain::identity::{Accounts, ActorUri, InstanceOrigin, RemoteActors};
use domain::messaging::{
    Conversations, GroupEvent, GroupEvents, GroupName, GroupNotifier, MessagingError,
    initial_roster,
};
use domain::social::Reachability;

use super::{GroupView, Invitees, local_accounts, may_add, profiles};
use crate::messaging::shared::{Timeline, caller as caller_account};

/// `POST /api/groups`: the caller becomes its first admin; each invited actor joins as a member.
/// The client then bootstraps the MLS group against the returned id.
pub struct CreateGroup {
    origin: InstanceOrigin,
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
    reach: Arc<dyn Reachability>,
    notifier: Arc<dyn GroupNotifier>,
    events: Arc<dyn GroupEvents>,
}

impl CreateGroup {
    pub fn new(
        origin: InstanceOrigin,
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        conversations: Arc<dyn Conversations>,
        reach: Arc<dyn Reachability>,
        notifier: Arc<dyn GroupNotifier>,
        events: Arc<dyn GroupEvents>,
    ) -> Self {
        Self {
            origin,
            accounts,
            remote_actors,
            conversations,
            reach,
            notifier,
            events,
        }
    }

    pub async fn execute(
        &self,
        caller: UserId,
        name: Option<GroupName>,
        invited: Vec<ActorUri>,
    ) -> Result<GroupView, MessagingError> {
        if invited.is_empty() {
            return Err(MessagingError::GroupNeedsMembers);
        }
        let creator = caller_account(&*self.accounts, caller).await?;
        // Sized before any invitee is looked up on their instance.
        let roster = initial_roster(&creator.actor_uri, &invited)?;
        for invitee in roster.iter().skip(1) {
            may_add(&self.invitees(), &creator, &invitee.actor_uri).await?;
        }
        let group = self
            .conversations
            .create_group(name.as_ref(), &roster)
            .await?;
        let members = self.conversations.members(group.id).await?;
        for local in local_accounts(&*self.accounts, &members).await? {
            self.notifier.joined(local.id, &group, &creator.actor_uri);
        }
        let created = GroupEvent::created(group.id, creator.actor_uri.clone(), group.created_at);
        self.timeline().record(&members, created).await?;
        Ok(GroupView {
            members: profiles(&*self.accounts, &*self.remote_actors, &members).await?,
            group,
        })
    }
}

impl CreateGroup {
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
