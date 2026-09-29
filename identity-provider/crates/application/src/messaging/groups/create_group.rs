use std::sync::Arc;

use domain::UserId;
use domain::identity::{Accounts, ActorUri, RemoteActors};
use domain::messaging::{Conversations, GroupName, GroupNotifier, MessagingError, initial_roster};

use super::{GroupView, local_accounts, profiles};
use crate::messaging::shared::caller as caller_account;

/// `POST /api/groups`: the caller becomes its first admin; each invited actor joins as a member.
/// The client then bootstraps the MLS group against the returned id.
pub struct CreateGroup {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
    notifier: Arc<dyn GroupNotifier>,
}

impl CreateGroup {
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
        name: Option<GroupName>,
        invited: Vec<ActorUri>,
    ) -> Result<GroupView, MessagingError> {
        if invited.is_empty() {
            return Err(MessagingError::GroupNeedsMembers);
        }
        let creator = caller_account(&*self.accounts, caller).await?;
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
