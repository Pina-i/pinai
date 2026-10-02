use domain::ConversationId;
use domain::e2ee::DeliveryError;
use domain::identity::{Account, Accounts, ActorUri, RemoteActors};
use domain::messaging::{
    ConversationKind, Conversations, GroupChangeKind, GroupEvent, GroupEventKind, GroupEvents,
    GroupNotifier, GroupSnapshot,
};
use domain::social::Reachability;

use crate::messaging::shared::{Roster, Timeline};

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
    pub(super) reach: &'a dyn Reachability,
    pub(super) groups: &'a dyn GroupNotifier,
    pub(super) events: &'a dyn GroupEvents,
}

impl Mirror<'_> {
    /// Take from `roster` what is newer here. Its sender is who added each account here it
    /// brings in: the line that one's conversation starts with.
    pub(super) async fn apply(
        &self,
        recipient: &Account,
        sender: &ActorUri,
        id: ConversationId,
        roster: &GroupSnapshot,
    ) -> Result<(), DeliveryError> {
        let newcomers = Roster {
            conversations: self.conversations,
            accounts: self.accounts,
            reach: self.reach,
            notifier: self.groups,
        }
        .mirror(recipient, sender, id, roster)
        .await?;
        if newcomers.is_empty() {
            return Ok(());
        }
        let members = self.conversations.members(id).await?;
        let timeline = Timeline {
            accounts: self.accounts,
            remote_actors: self.remote_actors,
            events: self.events,
            notifier: self.groups,
        };
        for newcomer in newcomers {
            let at = newcomer.joined_at;
            let added = GroupEvent {
                at,
                kind: GroupEventKind::Changed(GroupChangeKind::Added(newcomer.account.actor_uri)),
                ..GroupEvent::created(id, sender.clone(), at)
            };
            timeline.record(&members, added).await?;
        }
        Ok(())
    }
}
