//! Group management: creating a group, and its members, roles and name. Admins manage; members
//! of this instance are told; members elsewhere learn it from MLS commits and message rosters.

mod add_group_member;
mod create_group;
mod list_group_members;
mod remove_group_member;
mod rename_group;
mod set_member_role;
#[cfg(test)]
mod tests;

pub use add_group_member::AddGroupMember;
pub use create_group::CreateGroup;
pub use list_group_members::ListGroupMembers;
pub use remove_group_member::RemoveGroupMember;
pub use rename_group::RenameGroup;
pub use set_member_role::SetMemberRole;

use domain::ConversationId;
use domain::identity::{
    Account, Accounts, ActorUri, InstanceOrigin, RemoteActors, RemoteActorsError,
};
use domain::messaging::{Conversation, ConversationKind, Conversations, Member, MessagingError};
use domain::social::Reachability;

use super::shared::display_name_of;

/// Whether `adder` may add `invitee`: an account that exists — asked of its own instance, since
/// this one's cache would tell who here has met whom —, not someone they blocked, nor a local
/// account that doesn't admit them. Another instance's account is that instance's to refuse.
async fn may_add(
    ports: &Invitees<'_>,
    adder: &Account,
    invitee: &ActorUri,
) -> Result<(), MessagingError> {
    let not_found = || MessagingError::InviteeNotFound(invitee.clone());
    let local = if ports.origin.owns(invitee) {
        Some(
            ports
                .accounts
                .find_by_uri(invitee)
                .await?
                .ok_or_else(not_found)?,
        )
    } else {
        let address = invitee.federated_address().ok_or_else(not_found)?;
        match ports.remote_actors.resolve(&address).await {
            // A WebFinger answer naming another actor is no proof this URI is anyone's.
            Ok(actor) if actor.actor_uri == *invitee => None,
            Ok(_) | Err(RemoteActorsError::NotFound) => return Err(not_found()),
            Err(RemoteActorsError::Unavailable(_)) => {
                return Err(MessagingError::InviteeUnavailable(invitee.clone()));
            }
            Err(e) => return Err(e.into()),
        }
    };
    ports
        .reach
        .relation(adder.id, invitee)
        .await?
        .may_write()
        .map_err(|_| MessagingError::YouBlockedInvitee(invitee.clone()))?;
    if let Some(local) = local {
        ports
            .reach
            .relation(local.id, &adder.actor_uri)
            .await?
            .admits()
            .map_err(|_| MessagingError::CannotAdd(invitee.clone()))?;
    }
    Ok(())
}

/// What `may_add` asks.
struct Invitees<'a> {
    origin: &'a InstanceOrigin,
    accounts: &'a dyn Accounts,
    remote_actors: &'a dyn RemoteActors,
    reach: &'a dyn Reachability,
}

/// A member as the group's views show them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberProfile {
    pub member: Member,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupView {
    pub group: Conversation,
    pub members: Vec<MemberProfile>,
}

/// A local member by their display name (else handle), a remote one as this instance cached them.
async fn profile_of(
    accounts: &dyn Accounts,
    remote_actors: &dyn RemoteActors,
    member: &Member,
) -> Result<MemberProfile, MessagingError> {
    let (display_name, avatar_url) = match accounts.find_by_uri(&member.actor_uri).await? {
        Some(account) => (Some(display_name_of(&account)), account.avatar_url),
        None => match remote_actors.find(&member.actor_uri).await? {
            Some(actor) => (actor.display_name, actor.avatar_url),
            None => (None, None),
        },
    };
    Ok(MemberProfile {
        member: member.clone(),
        display_name,
        avatar_url,
    })
}

async fn profiles(
    accounts: &dyn Accounts,
    remote_actors: &dyn RemoteActors,
    members: &[Member],
) -> Result<Vec<MemberProfile>, MessagingError> {
    let mut out = Vec::with_capacity(members.len());
    for member in members {
        out.push(profile_of(accounts, remote_actors, member).await?);
    }
    Ok(out)
}

/// The active members of a group. A DM, or no conversation at all, is no group: both are
/// "not found", as for an outsider.
async fn group_members(
    conversations: &dyn Conversations,
    group: ConversationId,
) -> Result<Vec<Member>, MessagingError> {
    match conversations.find(group).await? {
        Some(c) if c.kind == ConversationKind::Group => Ok(conversations.members(group).await?),
        _ => Err(MessagingError::ConversationNotFound),
    }
}

/// The members with an account here: the ones this instance tells.
async fn local_accounts(
    accounts: &dyn Accounts,
    members: &[Member],
) -> Result<Vec<Account>, MessagingError> {
    let mut local = Vec::new();
    for member in members {
        if let Some(account) = accounts.find_by_uri(&member.actor_uri).await? {
            local.push(account);
        }
    }
    Ok(local)
}
