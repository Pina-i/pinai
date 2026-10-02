use domain::identity::{Account, Accounts, ActorUri, RemoteActors};
use domain::messaging::{
    Conversations, GroupEvent, GroupEvents, GroupNotifier, GroupSnapshot, MAX_MEMBERS, Member,
    MessagingError, NamedEvent,
};
use domain::social::Reachability;
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

/// An account of this instance a roster brought into a group, and when it joined.
pub(crate) struct Newcomer {
    pub(crate) account: Account,
    pub(crate) joined_at: OffsetDateTime,
}

/// What mirroring the roster another instance sent reads and tells.
pub(crate) struct Roster<'a> {
    pub(crate) conversations: &'a dyn Conversations,
    pub(crate) accounts: &'a dyn Accounts,
    pub(crate) reach: &'a dyn Reachability,
    pub(crate) notifier: &'a dyn GroupNotifier,
}

impl Roster<'_> {
    /// Mirror the roster a group message, commit or Welcome carries, taking from it only what is
    /// newer than this copy holds (`GroupSnapshot::changes`): an add or a role change converges
    /// on the next one a member receives, and a stale one undoes nothing.
    ///
    /// Each member's inbox gets its own copy, and whichever comes first brings in every account
    /// here the roster lists: each is told it joined, and the others the recipient's caller didn't
    /// ask are left out when they don't admit the sender. Answers the accounts brought in.
    pub(crate) async fn mirror(
        &self,
        recipient: &Account,
        sender: &ActorUri,
        id: ConversationId,
        snapshot: &GroupSnapshot,
    ) -> Result<Vec<Newcomer>, MessagingError> {
        if snapshot.members.is_empty() {
            return Ok(Vec::new());
        }
        // No copy of a group holds more: this one is not a group's.
        if snapshot.members.len() > MAX_MEMBERS {
            return Err(MessagingError::TooManyMembers(MAX_MEMBERS));
        }
        let local = self.conversations.find(id).await?;
        let held = self.conversations.memberships(id).await?;
        let members: Vec<Member> = held
            .iter()
            .filter(|m| m.is_active())
            .map(|m| m.member.clone())
            .collect();
        // A roster only a member may assert: anyone else could add themselves to the group here.
        if !snapshot.may_be_asserted_by(sender, local.as_ref(), &members) {
            return Err(MessagingError::ConversationNotFound);
        }
        let mut changes = snapshot.changes(local.as_ref(), &held, OffsetDateTime::now_utc());
        let listed = listed(snapshot);
        let mut newcomers = Vec::new();
        let mut kept = Vec::with_capacity(changes.members.len());
        for change in std::mem::take(&mut changes.members) {
            let new_here = !members
                .iter()
                .any(|m| m.actor_uri == change.member.actor_uri);
            let account = match new_here {
                true => self.accounts.find_by_uri(&change.member.actor_uri).await?,
                false => None,
            };
            if let Some(account) = account {
                let asked = account.actor_uri == recipient.actor_uri;
                if !asked && !admits_into_group(self.reach, &account, sender, &listed).await? {
                    continue;
                }
                newcomers.push(Newcomer {
                    account,
                    joined_at: change.joined_at,
                });
            }
            kept.push(change);
        }
        changes.members = kept;
        if changes.is_empty() {
            return Ok(Vec::new());
        }
        let mirrored = self.conversations.mirror_group(id, &changes).await?;
        // Another member's Note may be mirroring the same group at this moment: whoever this
        // write didn't bring in, that one did, and tells them.
        newcomers.retain(|n| mirrored.brought_in.contains(&n.account.actor_uri));
        for newcomer in &newcomers {
            self.notifier.joined(
                newcomer.account.id,
                &mirrored.group,
                snapshot.creator(sender),
            );
        }
        Ok(newcomers)
    }
}

fn listed(snapshot: &GroupSnapshot) -> Vec<ActorUri> {
    snapshot
        .members
        .iter()
        .map(|m| m.member.actor_uri.clone())
        .collect()
}

/// Whether `sender` may bring `account` into a group listing `listed`: someone it admits, with
/// nobody it blocked among them, since a roster doesn't say who added whom.
async fn admits_into_group(
    reach: &dyn Reachability,
    account: &Account,
    sender: &ActorUri,
    listed: &[ActorUri],
) -> Result<bool, MessagingError> {
    let roster_holds_someone_blocked = reach.blocks_any(account.id, listed).await?;
    Ok(reach
        .relation(account.id, sender)
        .await?
        .admits_group_from(roster_holds_someone_blocked)
        .is_ok())
}

/// Whether a group Note may bring `recipient` into the group it names: only from someone they
/// admit, and with nobody they blocked on its roster. Someone already in it is not asked again.
pub(crate) async fn admits_group_note(
    conversations: &dyn Conversations,
    reach: &dyn Reachability,
    recipient: &Account,
    sender: &ActorUri,
    id: ConversationId,
    roster: &GroupSnapshot,
) -> Result<bool, MessagingError> {
    let joins = !conversations
        .members(id)
        .await?
        .iter()
        .any(|m| m.actor_uri == recipient.actor_uri);
    if !joins {
        return Ok(true);
    }
    admits_into_group(reach, recipient, sender, &listed(roster)).await
}
