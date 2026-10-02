use domain::ConversationId;
use domain::e2ee::DeliveryError;
use domain::identity::{Account, Accounts, ActorUri, RemoteActors};
use domain::messaging::{
    ConversationKind, Conversations, GroupChangeKind, GroupEvent, GroupEventKind, GroupEvents,
    GroupNotifier, GroupSnapshot,
};

use crate::messaging::shared::{Timeline, mirror};

/// The roster an MLS Note bound for another instance carries, so that instance can hold the
/// group; `None` for a DM, which both hold from the friendship.
pub(super) async fn roster_of(
    conversations: &dyn Conversations,
    id: ConversationId,
) -> Result<Option<GroupSnapshot>, DeliveryError> {
    Ok(match conversations.find(id).await? {
        Some(group) if group.kind == ConversationKind::Group => {
            let held = conversations.memberships(id).await?;
            Some(GroupSnapshot::of(&group, &held))
        }
        _ => None,
    })
}

/// What mirroring a roster another instance sent takes.
pub(super) struct Mirror<'a> {
    pub(super) accounts: &'a dyn Accounts,
    pub(super) remote_actors: &'a dyn RemoteActors,
    pub(super) conversations: &'a dyn Conversations,
    pub(super) groups: &'a dyn GroupNotifier,
    pub(super) events: &'a dyn GroupEvents,
}

impl Mirror<'_> {
    /// Take from `roster` what is newer here. When it brings the recipient in, its sender is who
    /// added them: the line their conversation starts with.
    pub(super) async fn apply(
        &self,
        recipient: &Account,
        sender: &ActorUri,
        id: ConversationId,
        roster: &GroupSnapshot,
    ) -> Result<(), DeliveryError> {
        let Some(at) = mirror(
            self.conversations,
            self.groups,
            recipient,
            sender,
            id,
            roster,
        )
        .await?
        else {
            return Ok(());
        };
        let added = GroupEvent {
            at,
            kind: GroupEventKind::Changed(GroupChangeKind::Added(recipient.actor_uri.clone())),
            ..GroupEvent::created(id, sender.clone(), at)
        };
        let members = self.conversations.members(id).await?;
        Timeline {
            accounts: self.accounts,
            remote_actors: self.remote_actors,
            events: self.events,
            notifier: self.groups,
        }
        .record(&members, added)
        .await?;
        Ok(())
    }
}
