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
use domain::identity::{Account, Accounts, RemoteActors};
use domain::messaging::{Conversation, ConversationKind, Conversations, Member, MessagingError};

use super::shared::display_name_of;

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
