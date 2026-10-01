use std::sync::Arc;

use domain::UserId;
use domain::identity::{Accounts, ActorUri, InstanceOrigin, RemoteActors};
use domain::messaging::{Conversations, GroupName, GroupNotifier, MessagingError, initial_roster};
use domain::social::Reachability;

use super::{GroupView, Invitees, local_accounts, may_add, profiles};
use crate::messaging::shared::caller as caller_account;

/// `POST /api/groups`: the caller becomes its first admin; each invited actor joins as a member.
/// The client then bootstraps the MLS group against the returned id.
pub struct CreateGroup {
    origin: InstanceOrigin,
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
    reach: Arc<dyn Reachability>,
    notifier: Arc<dyn GroupNotifier>,
}

impl CreateGroup {
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
        name: Option<GroupName>,
        invited: Vec<ActorUri>,
    ) -> Result<GroupView, MessagingError> {
        if invited.is_empty() {
            return Err(MessagingError::GroupNeedsMembers);
        }
        let creator = caller_account(&*self.accounts, caller).await?;
        for invitee in invited.iter().filter(|i| **i != creator.actor_uri) {
            may_add(&self.invitees(), &creator, invitee).await?;
        }
        let roster = initial_roster(&creator.actor_uri, &invited);
        let group = self
            .conversations
            .create_group(name.as_ref(), &roster)
            .await?;
        let members = self.conversations.members(group.id).await?;
        for local in local_accounts(&*self.accounts, &members).await? {
            self.notifier.joined(local.id, &group, &creator.actor_uri);
        }
        Ok(GroupView {
            members: profiles(&*self.accounts, &*self.remote_actors, &members).await?,
            group,
        })
    }
}

impl CreateGroup {
    fn invitees(&self) -> Invitees<'_> {
        Invitees {
            origin: &self.origin,
            accounts: &*self.accounts,
            remote_actors: &*self.remote_actors,
            reach: &*self.reach,
        }
    }
}
