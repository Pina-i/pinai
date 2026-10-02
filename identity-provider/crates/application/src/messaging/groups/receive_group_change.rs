use std::sync::Arc;

use domain::UserId;
use domain::identity::{Accounts, ActorUri, RemoteActors};
use domain::messaging::{
    ConversationKind, Conversations, GroupChange, GroupChangeKind, GroupEffect, GroupEvent,
    GroupEvents, GroupNotifier, Member, MessagingError, Role,
};
use domain::social::Reachability;

use super::local_accounts;
use crate::messaging::shared::{Timeline, caller};

/// A group change another instance made, delivered to one of this instance's accounts: taken
/// when its maker may make it and it is newer than what this copy holds, ignored otherwise —
/// a peer learns nothing of who is in a group here.
pub struct ReceiveGroupChange {
    accounts: Arc<dyn Accounts>,
    remote_actors: Arc<dyn RemoteActors>,
    conversations: Arc<dyn Conversations>,
    reach: Arc<dyn Reachability>,
    notifier: Arc<dyn GroupNotifier>,
    events: Arc<dyn GroupEvents>,
}

impl ReceiveGroupChange {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        remote_actors: Arc<dyn RemoteActors>,
        conversations: Arc<dyn Conversations>,
        reach: Arc<dyn Reachability>,
        notifier: Arc<dyn GroupNotifier>,
        events: Arc<dyn GroupEvents>,
    ) -> Self {
        Self {
            accounts,
            remote_actors,
            conversations,
            reach,
            notifier,
            events,
        }
    }

    /// As for an add made here: an account of this instance comes in only by someone it admits.
    /// Another instance's account is that instance's to refuse.
    async fn admits(&self, added: &ActorUri, by: &ActorUri) -> Result<bool, MessagingError> {
        Ok(match self.accounts.find_by_uri(added).await? {
            Some(local) => self.reach.relation(local.id, by).await?.admits().is_ok(),
            None => true,
        })
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
        recipient: UserId,
        change: GroupChange,
    ) -> Result<(), MessagingError> {
        let owner = caller(&*self.accounts, recipient).await?;
        let Some(group) = self
            .conversations
            .find(change.group)
            .await?
            .filter(|c| c.kind == ConversationKind::Group)
        else {
            tracing::debug!(group = %change.group, "change to a group unknown here ignored");
            return Ok(());
        };
        let held = self.conversations.memberships(group.id).await?;
        let before: Vec<Member> = held
            .iter()
            .filter(|m| m.is_active())
            .map(|m| m.member.clone())
            .collect();
        if !change.may_arrive_through(&owner.actor_uri, &before) || !change.is_entitled(&before) {
            tracing::debug!(by = %change.by, "group change its maker may not make ignored");
            return Ok(());
        }
        let Some(effect) = change.effect(&group, &held) else {
            return Ok(());
        };
        match effect {
            GroupEffect::Depart {
                member,
                at,
                removed_by,
            } => {
                self.conversations
                    .remove_member(group.id, &member, removed_by.as_ref(), Some(at))
                    .await?;
                for local in local_accounts(&*self.accounts, &before).await? {
                    self.notifier
                        .member_removed(local.id, group.id, &member, removed_by.as_ref());
                }
                self.timeline()
                    .record(&before, GroupEvent::of(&change))
                    .await?;
            }
            GroupEffect::Take(changes) => {
                if let GroupChangeKind::Added(added) = &change.kind {
                    let new_here = !before.iter().any(|m| &m.actor_uri == added);
                    if new_here && !self.admits(added, &change.by).await? {
                        tracing::debug!(by = %change.by, "add of an account here who doesn't admit its maker ignored");
                        return Ok(());
                    }
                }
                let mirrored = self.conversations.mirror_group(group.id, &changes).await?;
                let group = mirrored.group;
                let after = self.conversations.members(group.id).await?;
                let locals = local_accounts(&*self.accounts, &after).await?;
                match &change.kind {
                    GroupChangeKind::Added(added) => {
                        // An add that only moves a stamp forward tells nobody anything, nor does
                        // one another member's copy of it brought in at the same moment.
                        if !mirrored.brought_in.contains(added) {
                            return Ok(());
                        }
                        let member = Member {
                            actor_uri: added.clone(),
                            role: Role::Member,
                        };
                        for local in locals {
                            if &local.actor_uri == added {
                                self.notifier.joined(local.id, &group, &change.by);
                            } else {
                                self.notifier
                                    .member_added(local.id, group.id, &member, &change.by);
                            }
                        }
                    }
                    GroupChangeKind::Renamed(_) => {
                        for local in locals {
                            self.notifier.renamed(local.id, &group, &change.by);
                        }
                    }
                    GroupChangeKind::RoleChanged(member, role) => {
                        let member = Member {
                            actor_uri: member.clone(),
                            role: *role,
                        };
                        for local in locals {
                            self.notifier
                                .role_changed(local.id, group.id, &member, &change.by);
                        }
                    }
                    GroupChangeKind::Removed(_) | GroupChangeKind::Left => {}
                }
                self.timeline()
                    .record(&after, GroupEvent::of(&change))
                    .await?;
            }
        }
        Ok(())
    }
}
