use domain::identity::{Account, Accounts, ActorUri, RemoteActor, RemoteActors};
use domain::messaging::{Conversations, GroupNotifier, GroupSnapshot, Member, MessagingError};
use domain::{ConversationId, UserId};

/// How a local account signs its messages: `user@domain`.
pub(crate) fn address_of(account: &Account) -> String {
    account
        .actor_uri
        .federated_address()
        .map_or_else(|| account.username.clone(), |address| address.to_string())
}

/// How a remote account signs its messages: `user@domain`, else its actor URI.
pub(crate) fn address_of_actor(actor: &ActorUri) -> String {
    actor
        .federated_address()
        .map_or_else(|| actor.to_string(), |address| address.to_string())
}

/// The name a local account's messages show: its display name, else its handle.
pub(crate) fn display_name_of(account: &Account) -> String {
    account
        .display_name
        .clone()
        .unwrap_or_else(|| account.username.clone())
}

pub(crate) async fn caller(accounts: &dyn Accounts, id: UserId) -> Result<Account, MessagingError> {
    accounts
        .find(id)
        .await?
        .ok_or_else(|| MessagingError::Unexpected(anyhow::anyhow!("the caller's account is gone")))
}

/// Who a conversation's other members are: accounts of this instance, and remote actors it
/// knows. A member it knows nothing of can't be reached and is left out.
pub(crate) async fn audience(
    accounts: &dyn Accounts,
    remote_actors: &dyn RemoteActors,
    members: &[Member],
    except: &ActorUri,
) -> Result<(Vec<Account>, Vec<RemoteActor>), MessagingError> {
    let (mut local, mut remote) = (Vec::new(), Vec::new());
    for member in members.iter().filter(|m| &m.actor_uri != except) {
        if let Some(account) = accounts.find_by_uri(&member.actor_uri).await? {
            local.push(account);
        } else if let Some(actor) = remote_actors.find(&member.actor_uri).await? {
            remote.push(actor);
        }
    }
    Ok((local, remote))
}

/// A member of this instance must be one of the conversation's active members.
pub(crate) async fn member_account(
    accounts: &dyn Accounts,
    conversations: &dyn Conversations,
    caller: UserId,
    conversation: ConversationId,
) -> Result<Account, MessagingError> {
    let account = self::caller(accounts, caller).await?;
    let members = conversations.members(conversation).await?;
    if !members.iter().any(|m| m.actor_uri == account.actor_uri) {
        return Err(MessagingError::ConversationNotFound);
    }
    Ok(account)
}

/// How a message's sender is named here: a local account by its display name (else handle), a
/// remote one by the name this instance cached, if any.
pub(crate) async fn sender_name(
    accounts: &dyn Accounts,
    remote_actors: &dyn RemoteActors,
    sender: &ActorUri,
) -> Result<Option<String>, MessagingError> {
    if let Some(account) = accounts.find_by_uri(sender).await? {
        return Ok(Some(display_name_of(&account)));
    }
    Ok(remote_actors
        .find(sender)
        .await?
        .and_then(|actor| actor.display_name))
}

/// Mirror the roster a group message or Welcome carries. Every one re-asserts it, so an add or
/// a role change converges on the next one a member receives.
pub(crate) async fn mirror(
    conversations: &dyn Conversations,
    notifier: &dyn GroupNotifier,
    recipient: &Account,
    sender: &ActorUri,
    id: ConversationId,
    snapshot: &GroupSnapshot,
) -> Result<(), MessagingError> {
    if snapshot.members.is_empty() {
        return Ok(());
    }
    let local = conversations.find(id).await?;
    let members = conversations.members(id).await?;
    // A roster only a member may assert: anyone else could add themselves to the group here.
    if !snapshot.may_be_asserted_by(sender, local.as_ref(), &members) {
        return Err(MessagingError::ConversationNotFound);
    }
    if snapshot.is_mirrored_by(local.as_ref(), &members) {
        return Ok(());
    }
    let joins = !members.iter().any(|m| m.actor_uri == recipient.actor_uri);
    let group = conversations.mirror_group(id, snapshot).await?;
    // Gated on the recipient's own membership: a second member's first message lands in a group
    // already mirrored here, and still has to reach them.
    if joins {
        notifier.joined(recipient.id, &group, snapshot.creator(sender));
    }
    Ok(())
}
