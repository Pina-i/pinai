use domain::identity::{Account, Accounts, ActorUri, RemoteActors};
use domain::messaging::{
    Conversations, GroupEvent, GroupEvents, GroupNotifier, GroupSnapshot, MAX_MEMBERS, Member,
    MessagingError, NamedEvent,
};
use domain::{ConversationId, UserId};
use time::OffsetDateTime;

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

/// Who a conversation's other members are: accounts of this instance, and the others, whom the
/// federation reaches at their inboxes.
pub(crate) async fn audience(
    accounts: &dyn Accounts,
    members: &[Member],
    except: &ActorUri,
) -> Result<(Vec<Account>, Vec<ActorUri>), MessagingError> {
    let (mut local, mut remote) = (Vec::new(), Vec::new());
    for member in members.iter().filter(|m| &m.actor_uri != except) {
        match accounts.find_by_uri(&member.actor_uri).await? {
            Some(account) => local.push(account),
            None => remote.push(member.actor_uri.clone()),
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

/// An event with the names this instance shows its maker and its subject by.
pub(crate) async fn name_event(
    accounts: &dyn Accounts,
    remote_actors: &dyn RemoteActors,
    event: GroupEvent,
) -> Result<NamedEvent, MessagingError> {
    let by_name = sender_name(accounts, remote_actors, &event.by).await?;
    let subject_name = match event.subject() {
        Some(subject) => sender_name(accounts, remote_actors, subject).await?,
        None => None,
    };
    Ok(NamedEvent {
        event,
        by_name,
        subject_name,
    })
}

/// A group's changes as lines of its conversation: each recorded, then pushed to the members of
/// this instance who see it.
pub(crate) struct Timeline<'a> {
    pub(crate) accounts: &'a dyn Accounts,
    pub(crate) remote_actors: &'a dyn RemoteActors,
    pub(crate) events: &'a dyn GroupEvents,
    pub(crate) notifier: &'a dyn GroupNotifier,
}

impl Timeline<'_> {
    /// `members` see it: those in the group after the change, or before a departure.
    pub(crate) async fn record(
        &self,
        members: &[Member],
        event: GroupEvent,
    ) -> Result<(), MessagingError> {
        self.events.record(&event).await?;
        let named = name_event(self.accounts, self.remote_actors, event).await?;
        for member in members {
            if let Some(local) = self.accounts.find_by_uri(&member.actor_uri).await? {
                self.notifier.event(local.id, &named);
            }
        }
        Ok(())
    }
}

/// Mirror the roster a group message or Welcome carries, taking from it only what is newer than
/// this copy holds (`GroupSnapshot::changes`): an add or a role change converges on the next one
/// a member receives, and a stale one undoes nothing. Answers the recipient's join stamp when it
/// brings them in.
pub(crate) async fn mirror(
    conversations: &dyn Conversations,
    notifier: &dyn GroupNotifier,
    recipient: &Account,
    sender: &ActorUri,
    id: ConversationId,
    snapshot: &GroupSnapshot,
) -> Result<Option<OffsetDateTime>, MessagingError> {
    if snapshot.members.is_empty() {
        return Ok(None);
    }
    // No copy of a group holds more: this one is not a group's.
    if snapshot.members.len() > MAX_MEMBERS {
        return Err(MessagingError::TooManyMembers(MAX_MEMBERS));
    }
    let local = conversations.find(id).await?;
    let held = conversations.memberships(id).await?;
    let members: Vec<Member> = held
        .iter()
        .filter(|m| m.is_active())
        .map(|m| m.member.clone())
        .collect();
    // A roster only a member may assert: anyone else could add themselves to the group here.
    if !snapshot.may_be_asserted_by(sender, local.as_ref(), &members) {
        return Err(MessagingError::ConversationNotFound);
    }
    let changes = snapshot.changes(local.as_ref(), &held, OffsetDateTime::now_utc());
    if changes.is_empty() {
        return Ok(None);
    }
    let joined_at = changes
        .members
        .iter()
        .find(|m| m.member.actor_uri == recipient.actor_uri)
        .map(|m| m.joined_at)
        .filter(|_| !members.iter().any(|m| m.actor_uri == recipient.actor_uri));
    let group = conversations.mirror_group(id, &changes).await?;
    // Gated on the recipient's own membership: a second member's first message lands in a group
    // already mirrored here, and still has to reach them.
    if joined_at.is_some() {
        notifier.joined(recipient.id, &group, snapshot.creator(sender));
    }
    Ok(joined_at)
}
