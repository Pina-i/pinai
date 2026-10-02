//! In-memory fakes of the messaging ports and the contract every store must satisfy.

use std::collections::HashMap;
use std::sync::Mutex;

use time::OffsetDateTime;

use crate::identity::{Account, ActorUri, InstanceOrigin};
use crate::{AttachmentId, ConversationId, MessageId, UserId};

use bytes::Bytes;

use super::{
    Attachment, Attachments, BlobTokenError, BlobTokens, ByteStream, Conversation,
    ConversationKind, ConversationSummary, Conversations, DeliveryFailed, DeliveryStatus,
    Departure, DirectDelivery, EventWindow, GroupChange, GroupChanges, GroupEvent, GroupEvents,
    GroupFederation, GroupName, GroupNotifier, GroupSnapshot, HistoryCursor, Member, MemberView,
    Membership, Message, MessageEvent, MessageFederation, MessageNotifier, MessageStoreError,
    Messages, Mirrored, MlsCiphertext, NamedEvent, NewMessage, ObjectStore, ObjectStoreError,
    RemoteAttachment, RemoteFiles, Role, SnapshotMember, may_hold_dm,
};

/// A snapshot as an instance that predates stamps sends it.
pub fn unstamped(name: Option<&str>, members: &[Member]) -> GroupSnapshot {
    GroupSnapshot {
        name: name.map(str::to_owned),
        name_at: None,
        members: members.iter().map(listed).collect(),
    }
}

/// `member` as an unstamped snapshot lists them.
pub fn listed(member: &Member) -> SnapshotMember {
    SnapshotMember {
        member: member.clone(),
        joined_at: None,
        role_at: None,
    }
}

/// What a group new here takes from `snapshot`: how a test seeds a store with a group.
pub fn as_new(snapshot: &GroupSnapshot) -> GroupChanges {
    snapshot.changes(None, &[], OffsetDateTime::now_utc())
}

/// Seeds what the stores read but do not write: uploads come from the attachments context.
#[async_trait::async_trait]
pub trait Uploads: Send + Sync {
    /// An attachment `owner` uploaded and has not attached to anything yet.
    async fn upload(&self, owner: &ActorUri) -> AttachmentId;
}

/// Both stores over one state, as they share their tables.
#[derive(Default)]
pub struct InMemoryMessaging {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    conversations: Vec<Conversation>,
    /// Every membership ever held.
    members: Vec<Held>,
    messages: Vec<Message>,
    uploads: Vec<Upload>,
    reads: HashMap<(UserId, ConversationId), OffsetDateTime>,
    events: Vec<GroupEvent>,
}

struct Held {
    conversation: ConversationId,
    membership: Membership,
    /// Set once the member is out: how, and the group as it stood then.
    departed: Option<Departed>,
}

struct Departed {
    removed_by: Option<ActorUri>,
    name: Option<String>,
    others: Vec<ActorUri>,
    dismissed: bool,
}

struct Upload {
    attachment: Attachment,
    recorded_at: OffsetDateTime,
}

impl State {
    fn active_members(&self, id: ConversationId) -> Vec<Member> {
        self.members
            .iter()
            .filter(|m| m.conversation == id && m.membership.is_active())
            .map(|m| m.membership.member.clone())
            .collect()
    }

    fn row_mut(&mut self, id: ConversationId, actor: &ActorUri) -> Option<&mut Held> {
        self.members
            .iter_mut()
            .find(|m| m.conversation == id && &m.membership.member.actor_uri == actor)
    }

    fn held_mut(&mut self, id: ConversationId, actor: &ActorUri) -> Option<&mut Membership> {
        self.row_mut(id, actor).map(|m| &mut m.membership)
    }

    /// Hold `membership` exactly as given.
    fn hold(&mut self, id: ConversationId, membership: &Membership) {
        match self.row_mut(id, &membership.member.actor_uri) {
            Some(row) => {
                row.membership = membership.clone();
                row.departed = None;
            }
            None => self.members.push(Held {
                conversation: id,
                membership: membership.clone(),
                departed: None,
            }),
        }
    }

    fn is_active(&self, id: ConversationId, actor: &ActorUri) -> bool {
        self.active_members(id)
            .iter()
            .any(|m| &m.actor_uri == actor)
    }

    fn dm_between(&self, a: &ActorUri, b: &ActorUri) -> Option<ConversationId> {
        self.conversations
            .iter()
            .filter(|c| c.kind == ConversationKind::Dm)
            .map(|c| c.id)
            .find(|id| self.is_active(*id, a) && self.is_active(*id, b))
    }

    fn create(
        &mut self,
        id: ConversationId,
        kind: ConversationKind,
        name: Option<String>,
        name_at: OffsetDateTime,
    ) {
        self.conversations.push(Conversation {
            id,
            kind,
            name,
            name_at,
            created_at: OffsetDateTime::now_utc(),
        });
    }

    /// Joins, or re-joins in the role it already had.
    fn add(&mut self, id: ConversationId, actor: &ActorUri) {
        let now = OffsetDateTime::now_utc();
        match self.row_mut(id, actor) {
            Some(row) => {
                if !row.membership.is_active() {
                    row.membership.left_at = None;
                    row.membership.joined_at = now;
                    row.departed = None;
                }
            }
            None => self.members.push(Held {
                conversation: id,
                membership: Membership {
                    member: Member {
                        actor_uri: actor.clone(),
                        role: Role::Member,
                    },
                    joined_at: now,
                    role_at: now,
                    left_at: None,
                },
                departed: None,
            }),
        }
    }

    fn add_in_role(&mut self, id: ConversationId, member: &Member) {
        self.add(id, &member.actor_uri);
        let held = self.held_mut(id, &member.actor_uri).expect("just added");
        held.member.role = member.role;
        held.role_at = OffsetDateTime::now_utc();
    }

    fn with_attachments(&self, message: &Message) -> Message {
        Message {
            attachments: self
                .uploads
                .iter()
                .filter(|u| u.attachment.message == Some(message.id))
                .map(|u| u.attachment.view())
                .collect(),
            ..message.clone()
        }
    }

    fn linkable(&self, id: AttachmentId, sender: &ActorUri) -> bool {
        self.uploads.iter().any(|u| {
            u.attachment.id == id
                && &u.attachment.uploader == sender
                && u.attachment.message.is_none_or(|linked| {
                    self.messages.iter().any(|m| {
                        m.id == linked
                            && &m.sender == sender
                            && m.delivery == DeliveryStatus::Failed
                    })
                })
        })
    }

    fn insert(&mut self, message: &NewMessage) -> Result<(), MessageStoreError> {
        if self
            .messages
            .iter()
            .any(|m| m.id == message.id || m.activity_uri == message.activity_uri)
        {
            return Err(anyhow::anyhow!("duplicate message {}", message.id).into());
        }
        self.messages.push(Message {
            id: message.id,
            conversation: message.conversation,
            sender: message.sender.clone(),
            ciphertext: message.ciphertext.clone(),
            activity_uri: message.activity_uri.clone(),
            delivery: DeliveryStatus::Pending,
            created_at: OffsetDateTime::now_utc(),
            edited_at: None,
            reply_to: message.reply_to,
            attachments: Vec::new(),
        });
        Ok(())
    }

    fn edit_where(
        &mut self,
        found: impl Fn(&Message) -> bool,
        sender: &ActorUri,
        ciphertext: &MlsCiphertext,
    ) -> Option<Message> {
        let message = self
            .messages
            .iter_mut()
            .find(|m| found(m) && &m.sender == sender)?;
        message.ciphertext = ciphertext.clone();
        message.edited_at = Some(OffsetDateTime::now_utc());
        let edited = message.clone();
        Some(self.with_attachments(&edited))
    }
}

#[async_trait::async_trait]
impl GroupEvents for InMemoryMessaging {
    async fn record(&self, event: &GroupEvent) -> Result<(), MessageStoreError> {
        self.state.lock().unwrap().events.push(event.clone());
        Ok(())
    }

    async fn page(
        &self,
        conversation: ConversationId,
        before: Option<HistoryCursor>,
        window: EventWindow,
        limit: i64,
    ) -> Result<Vec<GroupEvent>, MessageStoreError> {
        let state = self.state.lock().unwrap();
        let mut page: Vec<GroupEvent> = state
            .events
            .iter()
            .filter(|e| e.group == conversation && window.contains(e.at))
            .filter(|e| before.is_none_or(|c| (e.at, e.id.as_uuid()) < (c.created_at, c.id)))
            .cloned()
            .collect();
        page.sort_by_key(|e| std::cmp::Reverse((e.at, e.id)));
        page.truncate(usize::try_from(limit).unwrap_or(0));
        Ok(page)
    }
}

#[async_trait::async_trait]
impl Uploads for InMemoryMessaging {
    async fn upload(&self, owner: &ActorUri) -> AttachmentId {
        let id = AttachmentId::generate();
        self.state.lock().unwrap().uploads.push(Upload {
            attachment: Attachment {
                id,
                uploader: owner.clone(),
                message: None,
                mime_type: "image/png".to_owned(),
                byte_size: 512,
                original_filename: "cat.png".to_owned(),
                remote_url: None,
            },
            recorded_at: OffsetDateTime::now_utc(),
        });
        id
    }
}

#[async_trait::async_trait]
impl Conversations for InMemoryMessaging {
    async fn open_dm(
        &self,
        a: &ActorUri,
        b: &ActorUri,
        pinned: Option<ConversationId>,
    ) -> Result<ConversationId, MessageStoreError> {
        let mut state = self.state.lock().unwrap();
        let id = match (state.dm_between(a, b), pinned) {
            (Some(existing), Some(_)) => return Ok(existing),
            (Some(existing), None) => existing,
            (None, Some(pinned)) => match state.conversations.iter().find(|c| c.id == pinned) {
                None => {
                    state.create(
                        pinned,
                        ConversationKind::Dm,
                        None,
                        OffsetDateTime::now_utc(),
                    );
                    pinned
                }
                Some(existing) => {
                    let ever: Vec<ActorUri> = state
                        .members
                        .iter()
                        .filter(|m| m.conversation == pinned)
                        .map(|m| m.membership.member.actor_uri.clone())
                        .collect();
                    if may_hold_dm(existing.kind, &ever, a, b) {
                        pinned
                    } else {
                        let id = ConversationId::generate();
                        state.create(id, ConversationKind::Dm, None, OffsetDateTime::now_utc());
                        id
                    }
                }
            },
            (None, None) => {
                let id = ConversationId::generate();
                state.create(id, ConversationKind::Dm, None, OffsetDateTime::now_utc());
                id
            }
        };
        state.add(id, a);
        state.add(id, b);
        Ok(id)
    }

    async fn find(&self, id: ConversationId) -> Result<Option<Conversation>, MessageStoreError> {
        let state = self.state.lock().unwrap();
        Ok(state.conversations.iter().find(|c| c.id == id).cloned())
    }

    async fn members(&self, id: ConversationId) -> Result<Vec<Member>, MessageStoreError> {
        Ok(self.state.lock().unwrap().active_members(id))
    }

    async fn memberships(&self, id: ConversationId) -> Result<Vec<Membership>, MessageStoreError> {
        let state = self.state.lock().unwrap();
        Ok(state
            .members
            .iter()
            .filter(|m| m.conversation == id)
            .map(|m| m.membership.clone())
            .collect())
    }

    async fn ever_held(
        &self,
        actor: &ActorUri,
        ids: &[ConversationId],
    ) -> Result<Vec<ConversationId>, MessageStoreError> {
        let state = self.state.lock().unwrap();
        let mut held: Vec<ConversationId> = state
            .members
            .iter()
            .filter(|m| &m.membership.member.actor_uri == actor && ids.contains(&m.conversation))
            .map(|m| m.conversation)
            .collect();
        held.sort();
        held.dedup();
        Ok(held)
    }

    async fn mirror_group(
        &self,
        id: ConversationId,
        changes: &GroupChanges,
    ) -> Result<Mirrored, MessageStoreError> {
        let mut state = self.state.lock().unwrap();
        match state.conversations.iter_mut().find(|c| c.id == id) {
            Some(existing) => {
                if let Some(named) = &changes.name
                    && existing.kind == ConversationKind::Group
                {
                    existing.name = named.name.clone();
                    existing.name_at = named.at;
                }
            }
            None => {
                let (name, at) = changes.name.as_ref().map_or_else(
                    || (None, OffsetDateTime::now_utc()),
                    |named| (named.name.clone(), named.at),
                );
                state.create(id, ConversationKind::Group, name, at);
            }
        }
        let mut brought_in = Vec::new();
        for membership in &changes.members {
            let actor = &membership.member.actor_uri;
            if !state.is_active(id, actor) {
                brought_in.push(actor.clone());
            }
            state.hold(id, membership);
        }
        let group = state.conversations.iter().find(|c| c.id == id).cloned();
        Ok(Mirrored {
            group: group.expect("just mirrored"),
            brought_in,
        })
    }

    async fn list_for(
        &self,
        user: UserId,
        actor: &ActorUri,
    ) -> Result<Vec<ConversationSummary>, MessageStoreError> {
        let state = self.state.lock().unwrap();
        let mut listed: Vec<_> = state
            .conversations
            .iter()
            .filter(|c| state.is_active(c.id, actor))
            .map(|c| {
                let messages: Vec<_> = state
                    .messages
                    .iter()
                    .filter(|m| m.conversation == c.id)
                    .collect();
                let last = messages.iter().max_by_key(|m| (m.created_at, m.id));
                let read = state.reads.get(&(user, c.id));
                ConversationSummary {
                    id: c.id,
                    kind: c.kind,
                    name: c.name.clone(),
                    members: state
                        .active_members(c.id)
                        .into_iter()
                        .filter(|m| &m.actor_uri != actor)
                        .map(|m| MemberView {
                            actor_uri: m.actor_uri,
                            display_name: None,
                            avatar_url: None,
                        })
                        .collect(),
                    last_message_sender: last.map(|m| m.sender.clone()),
                    unread_count: messages
                        .iter()
                        .filter(|m| &m.sender != actor && read.is_none_or(|r| m.created_at > *r))
                        .count() as i64,
                    last_message_at: last.map(|m| m.created_at),
                    removed_at: None,
                }
            })
            .collect();
        let removed_from = state.members.iter().filter_map(|row| {
            let departed = row.departed.as_ref()?;
            let left_at = row.membership.left_at?;
            (&row.membership.member.actor_uri == actor
                && departed.removed_by.is_some()
                && !departed.dismissed)
                .then_some((row.conversation, departed, left_at))
        });
        for (id, departed, left_at) in removed_from {
            let last = state
                .messages
                .iter()
                .filter(|m| m.conversation == id && m.created_at <= left_at)
                .max_by_key(|m| (m.created_at, m.id));
            listed.push(ConversationSummary {
                id,
                kind: ConversationKind::Group,
                name: departed.name.clone(),
                members: departed
                    .others
                    .iter()
                    .map(|actor_uri| MemberView {
                        actor_uri: actor_uri.clone(),
                        display_name: None,
                        avatar_url: None,
                    })
                    .collect(),
                last_message_sender: last.map(|m| m.sender.clone()),
                unread_count: 0,
                last_message_at: last.map(|m| m.created_at),
                removed_at: Some(left_at),
            });
        }
        // Most recent first; never-active conversations last.
        listed.sort_by_key(|s| std::cmp::Reverse(s.last_message_at));
        Ok(listed)
    }

    async fn mark_read(&self, user: UserId, id: ConversationId) -> Result<(), MessageStoreError> {
        let mut state = self.state.lock().unwrap();
        state.reads.insert((user, id), OffsetDateTime::now_utc());
        Ok(())
    }

    async fn create_group(
        &self,
        name: Option<&GroupName>,
        roster: &[Member],
    ) -> Result<Conversation, MessageStoreError> {
        let mut state = self.state.lock().unwrap();
        let id = ConversationId::generate();
        state.create(
            id,
            ConversationKind::Group,
            name.map(|n| n.as_str().to_owned()),
            OffsetDateTime::now_utc(),
        );
        let group = state.conversations.last().cloned().expect("just created");
        // All in one step, as a store's transaction stamps it.
        for member in roster {
            state.hold(
                id,
                &Membership {
                    member: member.clone(),
                    joined_at: group.created_at,
                    role_at: group.created_at,
                    left_at: None,
                },
            );
        }
        Ok(group)
    }

    async fn add_member(
        &self,
        id: ConversationId,
        member: &Member,
    ) -> Result<(), MessageStoreError> {
        self.state.lock().unwrap().add_in_role(id, member);
        Ok(())
    }

    async fn remove_member(
        &self,
        id: ConversationId,
        actor: &ActorUri,
        removed_by: Option<&ActorUri>,
        at: Option<OffsetDateTime>,
    ) -> Result<bool, MessageStoreError> {
        let mut state = self.state.lock().unwrap();
        let name = state
            .conversations
            .iter()
            .find(|c| c.id == id)
            .and_then(|c| c.name.clone());
        let others: Vec<ActorUri> = state
            .active_members(id)
            .into_iter()
            .map(|m| m.actor_uri)
            .filter(|a| a != actor)
            .collect();
        let Some(row) = state
            .row_mut(id, actor)
            .filter(|r| r.membership.is_active())
        else {
            return Ok(false);
        };
        row.membership.left_at = Some(at.unwrap_or_else(OffsetDateTime::now_utc));
        row.departed = Some(Departed {
            removed_by: removed_by.cloned(),
            name,
            others,
            dismissed: false,
        });
        Ok(true)
    }

    async fn departure(
        &self,
        id: ConversationId,
        actor: &ActorUri,
    ) -> Result<Option<Departure>, MessageStoreError> {
        let mut state = self.state.lock().unwrap();
        Ok(state.row_mut(id, actor).and_then(|row| {
            Some(Departure {
                left_at: row.membership.left_at?,
                removed_by: row.departed.as_ref().and_then(|d| d.removed_by.clone()),
                dismissed: row.departed.as_ref().is_some_and(|d| d.dismissed),
            })
        }))
    }

    async fn dismiss(
        &self,
        id: ConversationId,
        actor: &ActorUri,
    ) -> Result<bool, MessageStoreError> {
        let mut state = self.state.lock().unwrap();
        let removed = state
            .row_mut(id, actor)
            .and_then(|row| row.departed.as_mut())
            .filter(|d| d.removed_by.is_some() && !d.dismissed);
        Ok(removed.map(|d| d.dismissed = true).is_some())
    }

    async fn set_role(
        &self,
        id: ConversationId,
        actor: &ActorUri,
        role: Role,
    ) -> Result<Option<Member>, MessageStoreError> {
        let mut state = self.state.lock().unwrap();
        let held = state.held_mut(id, actor).filter(|m| m.is_active());
        Ok(held.map(|m| {
            m.member.role = role;
            m.role_at = OffsetDateTime::now_utc();
            m.member.clone()
        }))
    }

    async fn rename_group(
        &self,
        id: ConversationId,
        name: &GroupName,
    ) -> Result<Option<Conversation>, MessageStoreError> {
        let mut state = self.state.lock().unwrap();
        let group = state
            .conversations
            .iter_mut()
            .find(|c| c.id == id && c.kind == ConversationKind::Group);
        Ok(group.map(|g| {
            g.name = Some(name.as_str().to_owned());
            g.name_at = OffsetDateTime::now_utc();
            g.clone()
        }))
    }
}

#[async_trait::async_trait]
impl Messages for InMemoryMessaging {
    async fn record(&self, message: &NewMessage) -> Result<Message, MessageStoreError> {
        let mut state = self.state.lock().unwrap();
        let mut wanted = message.attachments.clone();
        wanted.sort();
        wanted.dedup();
        if wanted.len() != message.attachments.len()
            || !wanted.iter().all(|id| state.linkable(*id, &message.sender))
        {
            return Err(MessageStoreError::AttachmentsUnavailable);
        }
        state.insert(message)?;
        for upload in state
            .uploads
            .iter_mut()
            .filter(|u| wanted.contains(&u.attachment.id))
        {
            upload.attachment.message = Some(message.id);
        }
        let recorded = state.messages.last().cloned().expect("just recorded");
        Ok(state.with_attachments(&recorded))
    }

    async fn record_received(
        &self,
        message: &NewMessage,
        attachments: &[RemoteAttachment],
    ) -> Result<Option<Message>, MessageStoreError> {
        let mut state = self.state.lock().unwrap();
        if state.insert(message).is_err() {
            return Ok(None);
        }
        for file in attachments {
            if state.uploads.iter().any(|u| u.attachment.id == file.id) {
                continue;
            }
            state.uploads.push(Upload {
                attachment: Attachment {
                    id: file.id,
                    uploader: message.sender.clone(),
                    message: Some(message.id),
                    mime_type: file.mime_type.clone(),
                    byte_size: file.byte_size,
                    original_filename: file.original_filename.clone(),
                    remote_url: Some(file.url.clone()),
                },
                recorded_at: OffsetDateTime::now_utc(),
            });
        }
        let recorded = state.messages.last().cloned().expect("just recorded");
        Ok(Some(state.with_attachments(&recorded)))
    }

    async fn find(&self, id: MessageId) -> Result<Option<Message>, MessageStoreError> {
        let state = self.state.lock().unwrap();
        let found = state.messages.iter().find(|m| m.id == id);
        Ok(found.map(|m| state.with_attachments(m)))
    }

    async fn find_by_activity(&self, uri: &str) -> Result<Option<Message>, MessageStoreError> {
        let state = self.state.lock().unwrap();
        let found = state.messages.iter().find(|m| m.activity_uri == uri);
        Ok(found.map(|m| state.with_attachments(m)))
    }

    async fn edit(
        &self,
        id: MessageId,
        sender: &ActorUri,
        ciphertext: &MlsCiphertext,
    ) -> Result<Option<Message>, MessageStoreError> {
        let mut state = self.state.lock().unwrap();
        Ok(state.edit_where(|m| m.id == id, sender, ciphertext))
    }

    async fn edit_by_activity(
        &self,
        uri: &str,
        sender: &ActorUri,
        ciphertext: &MlsCiphertext,
    ) -> Result<Option<Message>, MessageStoreError> {
        let mut state = self.state.lock().unwrap();
        Ok(state.edit_where(|m| m.activity_uri == uri, sender, ciphertext))
    }

    async fn history(
        &self,
        conversation: ConversationId,
        before: Option<HistoryCursor>,
        until: Option<OffsetDateTime>,
        limit: i64,
    ) -> Result<Vec<Message>, MessageStoreError> {
        let state = self.state.lock().unwrap();
        let mut page: Vec<_> = state
            .messages
            .iter()
            .filter(|m| m.conversation == conversation)
            .filter(|m| {
                before.is_none_or(|c| (m.created_at, m.id.as_uuid()) < (c.created_at, c.id))
            })
            .filter(|m| until.is_none_or(|until| m.created_at <= until))
            .map(|m| state.with_attachments(m))
            .collect();
        page.sort_by_key(|m| std::cmp::Reverse((m.created_at, m.id)));
        page.truncate(usize::try_from(limit).unwrap_or(0));
        Ok(page)
    }

    async fn set_delivery(
        &self,
        id: MessageId,
        status: DeliveryStatus,
    ) -> Result<(), MessageStoreError> {
        let mut state = self.state.lock().unwrap();
        if let Some(message) = state.messages.iter_mut().find(|m| m.id == id) {
            message.delivery = status;
        }
        Ok(())
    }

    async fn fail_stale_deliveries(
        &self,
        sent_before: OffsetDateTime,
    ) -> Result<Vec<Message>, MessageStoreError> {
        // The fake's accounts are those of `identity::testing::account`'s instance.
        let here = InstanceOrigin::parse("http://localhost:8080").expect("a valid origin");
        let mut state = self.state.lock().unwrap();
        let stale: Vec<MessageId> = state
            .messages
            .iter()
            .filter(|m| {
                m.delivery == DeliveryStatus::Pending
                    && m.created_at < sent_before
                    && here.owns(&m.sender)
                    && state
                        .conversations
                        .iter()
                        .any(|c| c.id == m.conversation && c.kind == ConversationKind::Dm)
                    && state.members.iter().any(|held| {
                        held.conversation == m.conversation
                            && held.membership.member.actor_uri != m.sender
                            && !here.owns(&held.membership.member.actor_uri)
                    })
            })
            .map(|m| m.id)
            .collect();
        let mut failed = Vec::new();
        for message in state.messages.iter_mut().filter(|m| stale.contains(&m.id)) {
            message.delivery = DeliveryStatus::Failed;
            failed.push(message.clone());
        }
        Ok(failed.iter().map(|m| state.with_attachments(m)).collect())
    }
}

#[async_trait::async_trait]
impl Attachments for InMemoryMessaging {
    async fn find(&self, id: AttachmentId) -> Result<Option<Attachment>, MessageStoreError> {
        let state = self.state.lock().unwrap();
        let found = state.uploads.iter().find(|u| u.attachment.id == id);
        Ok(found.map(|u| u.attachment.clone()))
    }

    async fn record_upload(&self, upload: &Attachment) -> Result<bool, MessageStoreError> {
        let mut state = self.state.lock().unwrap();
        if state.uploads.iter().any(|u| u.attachment.id == upload.id) {
            return Ok(false);
        }
        state.uploads.push(Upload {
            attachment: upload.clone(),
            recorded_at: OffsetDateTime::now_utc(),
        });
        Ok(true)
    }

    async fn delete(&self, id: AttachmentId) -> Result<(), MessageStoreError> {
        let mut state = self.state.lock().unwrap();
        state.uploads.retain(|u| u.attachment.id != id);
        Ok(())
    }

    async fn orphans_older_than(
        &self,
        cutoff: OffsetDateTime,
    ) -> Result<Vec<Attachment>, MessageStoreError> {
        let state = self.state.lock().unwrap();
        Ok(state
            .uploads
            .iter()
            .filter(|u| u.attachment.message.is_none() && u.recorded_at < cutoff)
            .map(|u| u.attachment.clone())
            .collect())
    }
}

/// A stream yielding `bytes` in one chunk.
pub fn byte_stream(bytes: Vec<u8>) -> ByteStream {
    struct Once(Option<Bytes>);
    impl futures_core::Stream for Once {
        type Item = std::io::Result<Bytes>;
        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Ready(self.0.take().map(Ok))
        }
    }
    ByteStream {
        length: Some(bytes.len() as u64),
        chunks: Box::pin(Once(Some(Bytes::from(bytes)))),
    }
}

/// A stream yielding each of `chunks` in turn.
pub fn byte_chunks(chunks: Vec<Vec<u8>>) -> ByteStream {
    struct Chunks(std::collections::VecDeque<Bytes>);
    impl futures_core::Stream for Chunks {
        type Item = std::io::Result<Bytes>;
        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Ready(self.0.pop_front().map(Ok))
        }
    }
    ByteStream {
        length: None,
        chunks: Box::pin(Chunks(chunks.into_iter().map(Bytes::from).collect())),
    }
}

/// Every byte a stream yields, or the first error.
pub async fn collect(mut stream: ByteStream) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = std::future::poll_fn(|cx| stream.chunks.as_mut().poll_next(cx)).await {
        out.extend_from_slice(&chunk?);
    }
    Ok(out)
}

/// An object store in memory; `unavailable()` fails every call.
#[derive(Default)]
pub struct InMemoryObjects {
    objects: Mutex<HashMap<AttachmentId, (Vec<u8>, String)>>,
    unavailable: bool,
}

impl InMemoryObjects {
    pub fn unavailable() -> Self {
        Self {
            unavailable: true,
            ..Self::default()
        }
    }

    pub fn holds(&self, id: AttachmentId) -> Option<Vec<u8>> {
        self.objects
            .lock()
            .unwrap()
            .get(&id)
            .map(|(b, _)| b.clone())
    }

    pub fn insert(&self, id: AttachmentId, bytes: Vec<u8>) {
        self.objects
            .lock()
            .unwrap()
            .insert(id, (bytes, "application/octet-stream".to_owned()));
    }

    fn check(&self) -> Result<(), ObjectStoreError> {
        if self.unavailable {
            return Err(anyhow::anyhow!("object store unavailable").into());
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl ObjectStore for InMemoryObjects {
    async fn put(
        &self,
        id: AttachmentId,
        bytes: Vec<u8>,
        mime_type: &str,
    ) -> Result<(), ObjectStoreError> {
        self.check()?;
        self.objects
            .lock()
            .unwrap()
            .insert(id, (bytes, mime_type.to_owned()));
        Ok(())
    }

    async fn get(&self, id: AttachmentId) -> Result<ByteStream, ObjectStoreError> {
        self.check()?;
        let bytes = self
            .holds(id)
            .ok_or_else(|| anyhow::anyhow!("no object {id}"))?;
        Ok(byte_stream(bytes))
    }

    async fn delete(&self, id: AttachmentId) -> Result<(), ObjectStoreError> {
        self.check()?;
        self.objects.lock().unwrap().remove(&id);
        Ok(())
    }
}

/// Other instances' attachments, by URL; records what was fetched.
#[derive(Default)]
pub struct InMemoryRemoteFiles {
    files: Mutex<HashMap<String, Vec<u8>>>,
    fetched: Mutex<Vec<String>>,
}

impl InMemoryRemoteFiles {
    pub fn with(files: impl IntoIterator<Item = (String, Vec<u8>)>) -> Self {
        Self {
            files: Mutex::new(files.into_iter().collect()),
            ..Self::default()
        }
    }

    pub fn fetched(&self) -> Vec<String> {
        self.fetched.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl RemoteFiles for InMemoryRemoteFiles {
    async fn fetch(&self, url: &str) -> Result<ByteStream, ObjectStoreError> {
        self.fetched.lock().unwrap().push(url.to_owned());
        let bytes = self.files.lock().unwrap().get(url).cloned();
        Ok(byte_stream(bytes.ok_or_else(|| {
            anyhow::anyhow!("peer answered 404 for {url}")
        })?))
    }
}

/// Tokens as plain text: `{user}.{attachment}`, or `expired.{user}.{attachment}`.
#[derive(Default)]
pub struct PlainBlobTokens;

impl PlainBlobTokens {
    pub fn expired(user: UserId, attachment: AttachmentId) -> String {
        format!("expired.{user}.{attachment}")
    }
}

impl BlobTokens for PlainBlobTokens {
    fn mint(&self, user: UserId, attachment: AttachmentId) -> (String, OffsetDateTime) {
        (
            format!("{user}.{attachment}"),
            OffsetDateTime::now_utc() + time::Duration::minutes(5),
        )
    }

    fn verify(&self, token: &str) -> Result<(UserId, AttachmentId), BlobTokenError> {
        if token.starts_with("expired.") {
            return Err(BlobTokenError::Expired);
        }
        let (user, attachment) = token.split_once('.').ok_or(BlobTokenError::Invalid)?;
        let user = user
            .parse::<uuid::Uuid>()
            .map_err(|_| BlobTokenError::Invalid)?;
        let attachment = attachment
            .parse::<uuid::Uuid>()
            .map_err(|_| BlobTokenError::Invalid)?;
        Ok((user.into(), attachment.into()))
    }
}

/// What a notifier was asked to tell, and to whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageNotice {
    Message(UserId, MessageEvent),
    Echo(UserId, MessageEvent),
    Edited(UserId, Message),
    EditEchoed(UserId, Message),
    DeliveryFailed(UserId, MessageId),
}

#[derive(Default)]
pub struct RecordingMessageNotifier {
    sent: Mutex<Vec<MessageNotice>>,
}

impl RecordingMessageNotifier {
    pub fn sent(&self) -> Vec<MessageNotice> {
        self.sent.lock().unwrap().clone()
    }

    fn push(&self, notice: MessageNotice) {
        self.sent.lock().unwrap().push(notice);
    }
}

impl MessageNotifier for RecordingMessageNotifier {
    fn message(&self, to: UserId, event: &MessageEvent) {
        self.push(MessageNotice::Message(to, event.clone()));
    }

    fn echo(&self, to: UserId, event: &MessageEvent) {
        self.push(MessageNotice::Echo(to, event.clone()));
    }

    fn edited(&self, to: UserId, message: &Message) {
        self.push(MessageNotice::Edited(to, message.clone()));
    }

    fn edit_echoed(&self, to: UserId, message: &Message) {
        self.push(MessageNotice::EditEchoed(to, message.clone()));
    }

    fn delivery_failed(&self, to: UserId, message: &Message) {
        self.push(MessageNotice::DeliveryFailed(to, message.id));
    }
}

/// What a group notifier was asked to tell, and to whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupNotice {
    Joined(UserId, ConversationId, ActorUri),
    MemberAdded(UserId, ConversationId, Member, ActorUri),
    MemberRemoved(UserId, ConversationId, ActorUri, Option<ActorUri>),
    Renamed(UserId, ConversationId, Option<String>, ActorUri),
    RoleChanged(UserId, ConversationId, Member, ActorUri),
}

#[derive(Default)]
pub struct RecordingGroupNotifier {
    sent: Mutex<Vec<GroupNotice>>,
    events: Mutex<Vec<(UserId, NamedEvent)>>,
}

impl RecordingGroupNotifier {
    /// The conversation lines pushed, apart from the other notices.
    pub fn events(&self) -> Vec<(UserId, NamedEvent)> {
        self.events.lock().unwrap().clone()
    }

    pub fn sent(&self) -> Vec<GroupNotice> {
        self.sent.lock().unwrap().clone()
    }

    fn push(&self, notice: GroupNotice) {
        self.sent.lock().unwrap().push(notice);
    }
}

impl GroupNotifier for RecordingGroupNotifier {
    fn joined(&self, to: UserId, group: &Conversation, creator: &ActorUri) {
        self.push(GroupNotice::Joined(to, group.id, creator.clone()));
    }

    fn member_added(&self, to: UserId, group: ConversationId, member: &Member, by: &ActorUri) {
        self.push(GroupNotice::MemberAdded(
            to,
            group,
            member.clone(),
            by.clone(),
        ));
    }

    fn member_removed(
        &self,
        to: UserId,
        group: ConversationId,
        member: &ActorUri,
        by: Option<&ActorUri>,
    ) {
        self.push(GroupNotice::MemberRemoved(
            to,
            group,
            member.clone(),
            by.cloned(),
        ));
    }

    fn renamed(&self, to: UserId, group: &Conversation, by: &ActorUri) {
        self.push(GroupNotice::Renamed(
            to,
            group.id,
            group.name.clone(),
            by.clone(),
        ));
    }

    fn role_changed(&self, to: UserId, group: ConversationId, member: &Member, by: &ActorUri) {
        self.push(GroupNotice::RoleChanged(
            to,
            group,
            member.clone(),
            by.clone(),
        ));
    }

    fn event(&self, to: UserId, event: &NamedEvent) {
        self.events.lock().unwrap().push((to, event.clone()));
    }
}

/// What was sent to other instances.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    Direct(Box<DirectDelivery>),
    Group {
        from: ActorUri,
        to: Vec<ActorUri>,
        message: MessageId,
        reply_to: Option<String>,
        group: GroupSnapshot,
    },
    Edit {
        from: ActorUri,
        to: ActorUri,
        message: MessageId,
    },
}

/// A group change told to other instances.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announced {
    pub from: ActorUri,
    pub to: Vec<ActorUri>,
    pub change: GroupChange,
}

#[derive(Default)]
pub struct RecordingGroupFederation {
    sent: Mutex<Vec<Announced>>,
}

impl RecordingGroupFederation {
    pub fn sent(&self) -> Vec<Announced> {
        self.sent.lock().unwrap().clone()
    }
}

impl GroupFederation for RecordingGroupFederation {
    fn announce(&self, from: &Account, to: &[ActorUri], change: &GroupChange) {
        self.sent.lock().unwrap().push(Announced {
            from: from.actor_uri.clone(),
            to: to.to_vec(),
            change: change.clone(),
        });
    }
}

/// Records every send; direct deliveries succeed unless built `unreachable`.
#[derive(Default)]
pub struct RecordingMessageFederation {
    sent: Mutex<Vec<Outbound>>,
    unreachable: bool,
}

impl RecordingMessageFederation {
    pub fn unreachable() -> Self {
        Self {
            unreachable: true,
            ..Self::default()
        }
    }

    pub fn sent(&self) -> Vec<Outbound> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl MessageFederation for RecordingMessageFederation {
    async fn deliver_direct(&self, delivery: &DirectDelivery) -> Result<(), DeliveryFailed> {
        self.sent
            .lock()
            .unwrap()
            .push(Outbound::Direct(Box::new(delivery.clone())));
        if self.unreachable {
            return Err(DeliveryFailed("connection refused".to_owned()));
        }
        Ok(())
    }

    fn send_to_group(
        &self,
        from: &Account,
        to: &[ActorUri],
        message: &Message,
        reply_to: Option<&str>,
        group: &GroupSnapshot,
    ) {
        self.sent.lock().unwrap().push(Outbound::Group {
            from: from.actor_uri.clone(),
            to: to.to_vec(),
            message: message.id,
            reply_to: reply_to.map(str::to_owned),
            group: group.clone(),
        });
    }

    fn send_edit(&self, from: &Account, to: &ActorUri, message: &Message) {
        self.sent.lock().unwrap().push(Outbound::Edit {
            from: from.actor_uri.clone(),
            to: to.clone(),
            message: message.id,
        });
    }
}

pub mod contract {
    use crate::identity::{Account, ActorUri};
    use time::OffsetDateTime;

    use crate::messaging::{
        Attachment, Attachments, ConversationKind, Conversations, DeliveryStatus, GroupChanges,
        GroupName, HistoryCursor, Member, Membership, MessageStoreError, Messages, MlsCiphertext,
        NewMessage, RemoteAttachment, Role, StampedName,
    };
    use crate::{AttachmentId, ConversationId, MessageId};

    use super::Uploads;

    /// An upload of `uploader`'s, not recorded yet.
    pub fn an_upload(uploader: &ActorUri) -> Attachment {
        Attachment {
            id: AttachmentId::generate(),
            uploader: uploader.clone(),
            message: None,
            mime_type: "image/png".to_owned(),
            byte_size: 512,
            original_filename: "cat.png".to_owned(),
            remote_url: None,
        }
    }

    pub async fn an_upload_is_recorded_unlinked_and_found(
        attachments: &dyn Attachments,
        alice: &Account,
    ) {
        let upload = an_upload(&alice.actor_uri);

        assert!(attachments.record_upload(&upload).await.unwrap());

        assert_eq!(attachments.find(upload.id).await.unwrap(), Some(upload));
        assert_eq!(
            attachments.find(AttachmentId::generate()).await.unwrap(),
            None
        );
    }

    pub async fn an_upload_under_a_taken_id_is_refused(
        attachments: &dyn Attachments,
        alice: &Account,
        bob: &Account,
    ) {
        let alices = an_upload(&alice.actor_uri);
        attachments.record_upload(&alices).await.unwrap();

        let bobs = Attachment {
            original_filename: "mine-now.png".to_owned(),
            ..an_upload(&bob.actor_uri)
        };
        let taken = attachments
            .record_upload(&Attachment {
                id: alices.id,
                ..bobs
            })
            .await
            .unwrap();

        assert!(!taken);
        assert_eq!(attachments.find(alices.id).await.unwrap(), Some(alices));
    }

    pub async fn a_deleted_attachment_is_gone(attachments: &dyn Attachments, alice: &Account) {
        let upload = an_upload(&alice.actor_uri);
        attachments.record_upload(&upload).await.unwrap();

        attachments.delete(upload.id).await.unwrap();

        assert_eq!(attachments.find(upload.id).await.unwrap(), None);
        attachments.delete(upload.id).await.unwrap();
    }

    pub async fn orphans_are_the_unlinked_uploads_recorded_before_the_cutoff(
        attachments: &dyn Attachments,
        conversations: &dyn Conversations,
        messages: &dyn Messages,
        alice: &Account,
    ) {
        let (orphan, sent) = (an_upload(&alice.actor_uri), an_upload(&alice.actor_uri));
        attachments.record_upload(&orphan).await.unwrap();
        attachments.record_upload(&sent).await.unwrap();
        let dm = conversations
            .open_dm(&alice.actor_uri, &remote("bob"), None)
            .await
            .unwrap();
        messages
            .record(&NewMessage {
                attachments: vec![sent.id],
                ..new_message(dm, &alice.actor_uri)
            })
            .await
            .unwrap();
        let now = time::OffsetDateTime::now_utc();

        let old = attachments
            .orphans_older_than(now + time::Duration::minutes(1))
            .await
            .unwrap();
        let none_yet = attachments
            .orphans_older_than(now - time::Duration::minutes(1))
            .await
            .unwrap();

        assert_eq!(old, vec![orphan]);
        assert!(none_yet.is_empty());
    }

    pub fn remote(name: &str) -> ActorUri {
        ActorUri::parse(&format!("https://idp.remote.test/users/{name}")).unwrap()
    }

    pub fn ciphertext(byte: u8) -> MlsCiphertext {
        MlsCiphertext::parse(vec![byte; 8]).unwrap()
    }

    /// A message `sender` sends in `conversation`, published under its own activity URI.
    pub fn new_message(conversation: ConversationId, sender: &ActorUri) -> NewMessage {
        let id = MessageId::generate();
        NewMessage {
            id,
            conversation,
            sender: sender.clone(),
            ciphertext: ciphertext(1),
            activity_uri: id.activity_uri(sender),
            reply_to: None,
            attachments: Vec::new(),
        }
    }

    fn member(actor_uri: &ActorUri, role: Role) -> Member {
        Member {
            actor_uri: actor_uri.clone(),
            role,
        }
    }

    fn sorted(mut members: Vec<Member>) -> Vec<Member> {
        members.sort_by(|a, b| a.actor_uri.as_str().cmp(b.actor_uri.as_str()));
        members
    }

    /// `n` minutes into a mirrored group's life, as another instance stamped it.
    fn stamp(n: i64) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(n)
    }

    fn holding(actor_uri: &ActorUri, role: Role, joined: i64, role_set: i64) -> Membership {
        Membership {
            member: member(actor_uri, role),
            joined_at: stamp(joined),
            role_at: stamp(role_set),
            left_at: None,
        }
    }

    fn named(name: &str, at: i64) -> Option<StampedName> {
        Some(StampedName {
            name: Some(name.to_owned()),
            at: stamp(at),
        })
    }

    fn by_actor(mut held: Vec<Membership>) -> Vec<Membership> {
        held.sort_by(|a, b| a.member.actor_uri.as_str().cmp(b.member.actor_uri.as_str()));
        held
    }

    async fn membership_of(
        conversations: &dyn Conversations,
        id: ConversationId,
        actor: &ActorUri,
    ) -> Membership {
        conversations
            .memberships(id)
            .await
            .unwrap()
            .into_iter()
            .find(|m| &m.member.actor_uri == actor)
            .expect("a membership")
    }

    pub async fn a_dm_is_opened_once_for_a_pair_in_either_order(
        conversations: &dyn Conversations,
        alice: &Account,
        bob: &Account,
    ) {
        let (a, b) = (&alice.actor_uri, &bob.actor_uri);

        let dm = conversations.open_dm(a, b, None).await.unwrap();

        assert_eq!(conversations.open_dm(a, b, None).await.unwrap(), dm);
        assert_eq!(conversations.open_dm(b, a, None).await.unwrap(), dm);
        let found = conversations.find(dm).await.unwrap().unwrap();
        assert_eq!((found.kind, found.name), (ConversationKind::Dm, None));
        assert_eq!(
            sorted(conversations.members(dm).await.unwrap()),
            sorted(vec![member(a, Role::Member), member(b, Role::Member)])
        );
    }

    pub async fn a_dm_is_opened_under_the_pinned_id_when_the_pair_has_none(
        conversations: &dyn Conversations,
        alice: &Account,
    ) {
        let pinned = ConversationId::generate();

        let dm = conversations
            .open_dm(&alice.actor_uri, &remote("bob"), Some(pinned))
            .await
            .unwrap();

        assert_eq!(dm, pinned);
        assert_eq!(conversations.members(dm).await.unwrap().len(), 2);
    }

    pub async fn a_pair_that_shares_a_dm_keeps_it_whatever_id_is_pinned(
        conversations: &dyn Conversations,
        alice: &Account,
    ) {
        let dm = conversations
            .open_dm(&alice.actor_uri, &remote("bob"), None)
            .await
            .unwrap();

        let reopened = conversations
            .open_dm(
                &remote("bob"),
                &alice.actor_uri,
                Some(ConversationId::generate()),
            )
            .await
            .unwrap();

        assert_eq!(reopened, dm);
    }

    pub async fn a_pinned_id_naming_a_group_opens_a_separate_dm(
        conversations: &dyn Conversations,
        alice: &Account,
    ) {
        let group = ConversationId::generate();
        let roster = vec![member(&remote("ana"), Role::Admin)];
        conversations
            .mirror_group(
                group,
                &GroupChanges {
                    name: None,
                    members: vec![holding(&remote("ana"), Role::Admin, 0, 0)],
                },
            )
            .await
            .unwrap();

        let dm = conversations
            .open_dm(&alice.actor_uri, &remote("bob"), Some(group))
            .await
            .unwrap();

        assert_ne!(dm, group);
        assert_eq!(conversations.members(group).await.unwrap(), roster);
    }

    pub async fn a_pinned_id_naming_another_pairs_dm_opens_a_separate_dm(
        conversations: &dyn Conversations,
        alice: &Account,
    ) {
        let theirs = conversations
            .open_dm(&remote("bob"), &remote("cy"), None)
            .await
            .unwrap();

        let dm = conversations
            .open_dm(&alice.actor_uri, &remote("dave"), Some(theirs))
            .await
            .unwrap();

        assert_ne!(dm, theirs);
        assert_eq!(conversations.members(theirs).await.unwrap().len(), 2);
    }

    pub async fn a_mirrored_group_is_created_with_its_name_roster_and_stamps(
        conversations: &dyn Conversations,
        alice: &Account,
    ) {
        let id = ConversationId::generate();
        let changes = GroupChanges {
            name: named("crew", 10),
            members: vec![
                holding(&remote("ana"), Role::Admin, 0, 0),
                holding(&alice.actor_uri, Role::Member, 5, 7),
            ],
        };

        let mirrored = conversations.mirror_group(id, &changes).await.unwrap();

        let group = mirrored.group;
        assert_eq!(
            (group.id, group.kind, group.name.as_deref(), group.name_at),
            (id, ConversationKind::Group, Some("crew"), stamp(10))
        );
        assert_eq!(
            mirrored.brought_in,
            vec![remote("ana"), alice.actor_uri.clone()]
        );
        assert_eq!(conversations.find(id).await.unwrap(), Some(group));
        assert_eq!(
            by_actor(conversations.memberships(id).await.unwrap()),
            by_actor(changes.members)
        );
    }

    pub async fn mirroring_holds_each_member_as_given_and_leaves_the_others(
        conversations: &dyn Conversations,
        alice: &Account,
    ) {
        let id = ConversationId::generate();
        conversations
            .mirror_group(
                id,
                &GroupChanges {
                    name: named("crew", 10),
                    members: vec![
                        holding(&remote("ana"), Role::Admin, 0, 0),
                        holding(&alice.actor_uri, Role::Member, 5, 5),
                        holding(&remote("cy"), Role::Member, 5, 5),
                    ],
                },
            )
            .await
            .unwrap();
        conversations
            .remove_member(id, &remote("cy"), Some(&remote("ana")), None)
            .await
            .unwrap();

        let renamed = conversations
            .mirror_group(
                id,
                &GroupChanges {
                    name: named("new crew", 20),
                    members: vec![
                        holding(&alice.actor_uri, Role::Admin, 5, 15),
                        holding(&remote("cy"), Role::Member, 30, 30),
                    ],
                },
            )
            .await
            .unwrap();

        assert_eq!(renamed.brought_in, vec![remote("cy")], "back; alice was in");
        let renamed = renamed.group;
        assert_eq!(
            (renamed.name.as_deref(), renamed.name_at),
            (Some("new crew"), stamp(20))
        );
        assert_eq!(
            by_actor(conversations.memberships(id).await.unwrap()),
            by_actor(vec![
                holding(&remote("ana"), Role::Admin, 0, 0),
                holding(&alice.actor_uri, Role::Admin, 5, 15),
                holding(&remote("cy"), Role::Member, 30, 30),
            ])
        );
        assert_eq!(
            conversations.departure(id, &remote("cy")).await.unwrap(),
            None,
            "a rejoin forgets the removal"
        );
        let unnamed = conversations
            .mirror_group(id, &GroupChanges::default())
            .await
            .unwrap()
            .group;
        assert_eq!(
            (unnamed.name.as_deref(), unnamed.name_at),
            (Some("new crew"), stamp(20))
        );
    }

    pub async fn a_change_made_here_is_stamped_now(
        conversations: &dyn Conversations,
        alice: &Account,
        bob: &Account,
    ) {
        let before = OffsetDateTime::now_utc() - time::Duration::minutes(1);
        let group = conversations
            .create_group(
                None,
                &crew_of(&[
                    (&alice.actor_uri, Role::Admin),
                    (&bob.actor_uri, Role::Member),
                ]),
            )
            .await
            .unwrap();
        let joined = membership_of(conversations, group.id, &bob.actor_uri).await;
        assert!(group.name_at > before && joined.joined_at > before && joined.role_at > before);

        conversations
            .remove_member(group.id, &bob.actor_uri, None, None)
            .await
            .unwrap();
        let left = membership_of(conversations, group.id, &bob.actor_uri).await;
        let left_at = left.left_at.expect("left");
        assert!(left_at > joined.joined_at);

        conversations
            .add_member(group.id, &member(&bob.actor_uri, Role::Member))
            .await
            .unwrap();
        let back = membership_of(conversations, group.id, &bob.actor_uri).await;
        assert!(back.is_active() && back.joined_at > left_at && back.role_at > left_at);

        conversations
            .set_role(group.id, &bob.actor_uri, Role::Admin)
            .await
            .unwrap();
        let promoted = membership_of(conversations, group.id, &bob.actor_uri).await;
        assert!(promoted.role_at > back.role_at);
        assert_eq!(
            promoted.joined_at, back.joined_at,
            "a role change is no rejoin"
        );

        let renamed = conversations
            .rename_group(group.id, &GroupName::parse("crew").unwrap())
            .await
            .unwrap()
            .expect("a group");
        assert!(renamed.name_at > group.name_at);
    }

    fn crew_of(names: &[(&ActorUri, Role)]) -> Vec<Member> {
        names.iter().map(|(uri, role)| member(uri, *role)).collect()
    }

    pub async fn a_group_is_created_with_its_whole_roster(
        conversations: &dyn Conversations,
        alice: &Account,
        bob: &Account,
    ) {
        let roster = crew_of(&[
            (&alice.actor_uri, Role::Admin),
            (&bob.actor_uri, Role::Member),
            (&remote("cy"), Role::Member),
        ]);

        let group = conversations
            .create_group(Some(&GroupName::parse("crew").unwrap()), &roster)
            .await
            .unwrap();
        let unnamed = conversations.create_group(None, &roster).await.unwrap();

        assert_eq!(
            (group.kind, group.name.as_deref()),
            (ConversationKind::Group, Some("crew"))
        );
        assert_eq!(unnamed.name, None);
        assert_ne!(group.id, unnamed.id);
        assert_eq!(
            conversations.find(group.id).await.unwrap(),
            Some(group.clone())
        );
        assert_eq!(
            sorted(conversations.members(group.id).await.unwrap()),
            sorted(roster)
        );
    }

    pub async fn an_added_member_takes_the_given_role_and_one_who_left_rejoins(
        conversations: &dyn Conversations,
        alice: &Account,
        bob: &Account,
    ) {
        let group = conversations
            .create_group(None, &crew_of(&[(&alice.actor_uri, Role::Admin)]))
            .await
            .unwrap();
        let role_of = |members: Vec<Member>| {
            members
                .into_iter()
                .find(|m| m.actor_uri == bob.actor_uri)
                .map(|m| m.role)
        };

        conversations
            .add_member(group.id, &member(&bob.actor_uri, Role::Member))
            .await
            .unwrap();
        assert_eq!(
            role_of(conversations.members(group.id).await.unwrap()),
            Some(Role::Member)
        );
        conversations
            .add_member(group.id, &member(&bob.actor_uri, Role::Admin))
            .await
            .unwrap();
        assert_eq!(
            role_of(conversations.members(group.id).await.unwrap()),
            Some(Role::Admin)
        );
        conversations
            .remove_member(group.id, &bob.actor_uri, None, None)
            .await
            .unwrap();
        conversations
            .add_member(group.id, &member(&bob.actor_uri, Role::Member))
            .await
            .unwrap();

        assert_eq!(
            role_of(conversations.members(group.id).await.unwrap()),
            Some(Role::Member)
        );
    }

    pub async fn the_conversations_an_actor_ever_held_include_those_it_left(
        conversations: &dyn Conversations,
        alice: &Account,
        bob: &Account,
    ) {
        let pair = crew_of(&[
            (&alice.actor_uri, Role::Admin),
            (&bob.actor_uri, Role::Member),
        ]);
        let kept = conversations.create_group(None, &pair).await.unwrap().id;
        let left = conversations.create_group(None, &pair).await.unwrap().id;
        conversations
            .remove_member(left, &bob.actor_uri, None, None)
            .await
            .unwrap();
        let alone = conversations
            .create_group(None, &crew_of(&[(&alice.actor_uri, Role::Admin)]))
            .await
            .unwrap()
            .id;

        let mut held = conversations
            .ever_held(
                &bob.actor_uri,
                &[kept, left, alone, ConversationId::generate()],
            )
            .await
            .unwrap();
        held.sort();

        let mut expected = vec![kept, left];
        expected.sort();
        assert_eq!(held, expected);
        assert!(
            conversations
                .ever_held(&bob.actor_uri, &[])
                .await
                .unwrap()
                .is_empty()
        );
    }

    pub async fn a_member_leaves_a_group_once(
        conversations: &dyn Conversations,
        alice: &Account,
        bob: &Account,
    ) {
        let group = conversations
            .create_group(
                None,
                &crew_of(&[
                    (&alice.actor_uri, Role::Admin),
                    (&bob.actor_uri, Role::Member),
                ]),
            )
            .await
            .unwrap();

        assert!(
            conversations
                .remove_member(group.id, &bob.actor_uri, None, None)
                .await
                .unwrap()
        );
        assert!(
            !conversations
                .remove_member(group.id, &bob.actor_uri, None, None)
                .await
                .unwrap()
        );
        assert!(
            !conversations
                .remove_member(group.id, &remote("never"), None, None)
                .await
                .unwrap()
        );
        assert_eq!(
            conversations.members(group.id).await.unwrap(),
            crew_of(&[(&alice.actor_uri, Role::Admin)])
        );
    }

    pub async fn a_role_changes_only_for_an_active_member(
        conversations: &dyn Conversations,
        alice: &Account,
        bob: &Account,
    ) {
        let group = conversations
            .create_group(
                None,
                &crew_of(&[
                    (&alice.actor_uri, Role::Admin),
                    (&bob.actor_uri, Role::Member),
                ]),
            )
            .await
            .unwrap();

        let promoted = conversations
            .set_role(group.id, &bob.actor_uri, Role::Admin)
            .await
            .unwrap();
        conversations
            .remove_member(group.id, &bob.actor_uri, None, None)
            .await
            .unwrap();
        let gone = conversations
            .set_role(group.id, &bob.actor_uri, Role::Member)
            .await
            .unwrap();

        assert_eq!(promoted, Some(member(&bob.actor_uri, Role::Admin)));
        assert_eq!(gone, None);
        assert_eq!(
            conversations
                .set_role(group.id, &remote("never"), Role::Admin)
                .await
                .unwrap(),
            None
        );
    }

    pub async fn only_a_group_is_renamed(
        conversations: &dyn Conversations,
        alice: &Account,
        bob: &Account,
    ) {
        let group = conversations
            .create_group(None, &crew_of(&[(&alice.actor_uri, Role::Admin)]))
            .await
            .unwrap();
        let dm = conversations
            .open_dm(&alice.actor_uri, &bob.actor_uri, None)
            .await
            .unwrap();
        let name = GroupName::parse("new crew").unwrap();

        let renamed = conversations.rename_group(group.id, &name).await.unwrap();

        assert_eq!(
            renamed.as_ref().and_then(|g| g.name.as_deref()),
            Some("new crew")
        );
        assert_eq!(conversations.find(group.id).await.unwrap(), renamed);
        assert_eq!(conversations.rename_group(dm, &name).await.unwrap(), None);
        assert_eq!(
            conversations
                .rename_group(ConversationId::generate(), &name)
                .await
                .unwrap(),
            None
        );
    }

    fn uris_of(listed: &crate::messaging::ConversationSummary) -> Vec<String> {
        let mut uris: Vec<String> = listed
            .members
            .iter()
            .map(|m| m.actor_uri.to_string())
            .collect();
        uris.sort();
        uris
    }

    pub async fn a_removed_member_keeps_the_group_as_it_stood_until_they_clear_it(
        conversations: &dyn Conversations,
        messages: &dyn Messages,
        alice: &Account,
        bob: &Account,
    ) {
        let group = conversations
            .create_group(
                Some(&GroupName::parse("crew").unwrap()),
                &crew_of(&[
                    (&alice.actor_uri, Role::Admin),
                    (&bob.actor_uri, Role::Member),
                    (&remote("cy"), Role::Member),
                ]),
            )
            .await
            .unwrap();
        let before = messages
            .record(&new_message(group.id, &alice.actor_uri))
            .await
            .unwrap();
        conversations
            .remove_member(group.id, &bob.actor_uri, Some(&alice.actor_uri), None)
            .await
            .unwrap();
        conversations
            .rename_group(group.id, &GroupName::parse("new crew").unwrap())
            .await
            .unwrap();
        conversations
            .add_member(group.id, &member(&remote("dave"), Role::Member))
            .await
            .unwrap();
        messages
            .record(&new_message(group.id, &alice.actor_uri))
            .await
            .unwrap();

        let listed = conversations
            .list_for(bob.id, &bob.actor_uri)
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);
        let shown = &listed[0];
        assert_eq!(
            (shown.id, shown.name.as_deref(), shown.unread_count),
            (group.id, Some("crew"), 0)
        );
        assert!(shown.removed_at.is_some());
        let mut was_with = vec![alice.actor_uri.to_string(), remote("cy").to_string()];
        was_with.sort();
        assert_eq!(uris_of(shown), was_with, "the others then, not dave");
        assert_eq!(
            (shown.last_message_at, shown.last_message_sender.as_ref()),
            (Some(before.created_at), Some(&alice.actor_uri))
        );
        let departure = conversations
            .departure(group.id, &bob.actor_uri)
            .await
            .unwrap()
            .expect("a departure");
        assert_eq!(
            (departure.removed_by, departure.dismissed, shown.removed_at),
            (
                Some(alice.actor_uri.clone()),
                false,
                Some(departure.left_at)
            )
        );

        assert!(
            conversations
                .dismiss(group.id, &bob.actor_uri)
                .await
                .unwrap()
        );
        assert!(
            conversations
                .list_for(bob.id, &bob.actor_uri)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            !conversations
                .dismiss(group.id, &bob.actor_uri)
                .await
                .unwrap()
        );
        assert!(
            conversations
                .departure(group.id, &bob.actor_uri)
                .await
                .unwrap()
                .is_some_and(|d| d.dismissed)
        );
    }

    pub async fn one_who_left_keeps_nothing_and_a_rejoin_forgets_a_removal(
        conversations: &dyn Conversations,
        alice: &Account,
        bob: &Account,
    ) {
        let group = conversations
            .create_group(
                Some(&GroupName::parse("crew").unwrap()),
                &crew_of(&[
                    (&alice.actor_uri, Role::Admin),
                    (&bob.actor_uri, Role::Member),
                ]),
            )
            .await
            .unwrap();
        let listed = || async {
            conversations
                .list_for(bob.id, &bob.actor_uri)
                .await
                .unwrap()
        };

        conversations
            .remove_member(group.id, &bob.actor_uri, None, None)
            .await
            .unwrap();
        assert!(listed().await.is_empty(), "a left group is gone");
        let left = conversations
            .departure(group.id, &bob.actor_uri)
            .await
            .unwrap();
        assert_eq!(left.map(|d| d.removed_by), Some(None));
        assert!(
            !conversations
                .dismiss(group.id, &bob.actor_uri)
                .await
                .unwrap()
        );

        for cleared in [true, false] {
            conversations
                .add_member(group.id, &member(&bob.actor_uri, Role::Member))
                .await
                .unwrap();
            conversations
                .remove_member(group.id, &bob.actor_uri, Some(&alice.actor_uri), None)
                .await
                .unwrap();
            let shown = listed().await;
            assert!(
                shown.len() == 1 && shown[0].removed_at.is_some(),
                "each removal is shown, a cleared one before it or not"
            );
            if cleared {
                assert!(
                    conversations
                        .dismiss(group.id, &bob.actor_uri)
                        .await
                        .unwrap()
                );
            }
        }
        conversations
            .add_member(group.id, &member(&bob.actor_uri, Role::Member))
            .await
            .unwrap();

        assert_eq!(
            conversations
                .departure(group.id, &bob.actor_uri)
                .await
                .unwrap(),
            None
        );
        let back = listed().await;
        assert_eq!(back.len(), 1);
        assert_eq!(
            (back[0].removed_at, back[0].name.as_deref()),
            (None, Some("crew"))
        );
        assert_eq!(uris_of(&back[0]), vec![alice.actor_uri.to_string()]);
    }

    pub async fn a_departure_made_elsewhere_keeps_its_stamp(
        conversations: &dyn Conversations,
        alice: &Account,
        bob: &Account,
    ) {
        let group = conversations
            .create_group(
                None,
                &crew_of(&[
                    (&alice.actor_uri, Role::Admin),
                    (&bob.actor_uri, Role::Member),
                ]),
            )
            .await
            .unwrap();
        let elsewhere = OffsetDateTime::now_utc() + time::Duration::minutes(5);

        conversations
            .remove_member(
                group.id,
                &bob.actor_uri,
                Some(&alice.actor_uri),
                Some(elsewhere),
            )
            .await
            .unwrap();

        let departure = conversations
            .departure(group.id, &bob.actor_uri)
            .await
            .unwrap()
            .expect("a departure");
        assert_eq!(
            departure.left_at.unix_timestamp_nanos() / 1_000,
            elsewhere.unix_timestamp_nanos() / 1_000,
            "to the microsecond a store keeps"
        );
    }

    pub async fn a_groups_events_are_paged_newest_first_within_the_readers_window(
        conversations: &dyn Conversations,
        events: &dyn crate::messaging::GroupEvents,
        alice: &Account,
    ) {
        use crate::messaging::{EventWindow, GroupChangeKind, GroupEvent, GroupEventKind};
        let crew = crew_of(&[(&alice.actor_uri, Role::Admin)]);
        let group = conversations.create_group(None, &crew).await.unwrap().id;
        let other = conversations.create_group(None, &crew).await.unwrap().id;
        let at = |n: i64| OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(n);
        let event = |id: ConversationId, minute: i64| GroupEvent {
            at: at(minute),
            kind: GroupEventKind::Changed(GroupChangeKind::Added(remote(&format!("m{minute}")))),
            ..GroupEvent::created(id, alice.actor_uri.clone(), at(minute))
        };
        let recorded: Vec<GroupEvent> = [10, 20, 30].map(|m| event(group, m)).to_vec();
        for e in &recorded {
            events.record(e).await.unwrap();
        }
        events.record(&event(other, 25)).await.unwrap();
        let ids = |page: Vec<GroupEvent>| page.into_iter().map(|e| e.id).collect::<Vec<_>>();
        let window = |since, until: Option<i64>| EventWindow {
            since: at(since),
            until: until.map(at),
        };

        assert_eq!(
            ids(events.page(group, None, window(0, None), 10).await.unwrap()),
            vec![recorded[2].id, recorded[1].id, recorded[0].id]
        );
        assert_eq!(
            events.page(group, None, window(0, None), 10).await.unwrap()[0],
            recorded[2],
            "as recorded"
        );
        assert_eq!(
            ids(events
                .page(group, None, window(20, Some(20)), 10)
                .await
                .unwrap()),
            vec![recorded[1].id],
            "the window's ends included"
        );
        let cursor = HistoryCursor {
            created_at: recorded[2].at,
            id: recorded[2].id.as_uuid(),
        };
        assert_eq!(
            ids(events
                .page(group, Some(cursor), window(0, None), 1)
                .await
                .unwrap()),
            vec![recorded[1].id]
        );
    }

    pub async fn every_kind_of_event_comes_back_as_recorded(
        conversations: &dyn Conversations,
        events: &dyn crate::messaging::GroupEvents,
        alice: &Account,
    ) {
        use crate::messaging::{EventWindow, GroupChangeKind, GroupEvent, GroupEventKind};
        let crew = crew_of(&[(&alice.actor_uri, Role::Admin)]);
        let group = conversations.create_group(None, &crew).await.unwrap().id;
        let at = |n: i64| OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(n);
        let kinds = [
            GroupEventKind::Created,
            GroupEventKind::Changed(GroupChangeKind::Added(remote("bo"))),
            GroupEventKind::Changed(GroupChangeKind::Removed(remote("bo"))),
            GroupEventKind::Changed(GroupChangeKind::Left),
            GroupEventKind::Changed(GroupChangeKind::Renamed(GroupName::parse("crew").unwrap())),
            GroupEventKind::Changed(GroupChangeKind::RoleChanged(remote("cy"), Role::Admin)),
        ];
        let mut recorded = Vec::new();
        for (minute, kind) in (1..).zip(kinds) {
            let event = GroupEvent {
                kind,
                ..GroupEvent::created(group, alice.actor_uri.clone(), at(minute))
            };
            events.record(&event).await.unwrap();
            recorded.push(event);
        }

        let mut page = events
            .page(
                group,
                None,
                EventWindow {
                    since: at(0),
                    until: None,
                },
                10,
            )
            .await
            .unwrap();
        page.reverse();

        assert_eq!(page, recorded);
    }

    pub async fn history_until_a_moment_leaves_out_what_came_after(
        conversations: &dyn Conversations,
        messages: &dyn Messages,
        alice: &Account,
    ) {
        let dm = conversations
            .open_dm(&alice.actor_uri, &remote("bob"), None)
            .await
            .unwrap();
        let first = messages
            .record(&new_message(dm, &alice.actor_uri))
            .await
            .unwrap();
        messages
            .record(&new_message(dm, &alice.actor_uri))
            .await
            .unwrap();

        let until = messages
            .history(dm, None, Some(first.created_at), 10)
            .await
            .unwrap();

        assert_eq!(
            until.iter().map(|m| m.id).collect::<Vec<_>>(),
            vec![first.id]
        );
        assert_eq!(messages.history(dm, None, None, 10).await.unwrap().len(), 2);
    }

    pub async fn the_conversation_list_shows_the_others_the_last_message_and_unread_counts(
        conversations: &dyn Conversations,
        messages: &dyn Messages,
        alice: &Account,
        bob: &Account,
    ) {
        let dm = conversations
            .open_dm(&alice.actor_uri, &bob.actor_uri, None)
            .await
            .unwrap();
        messages
            .record(&new_message(dm, &bob.actor_uri))
            .await
            .unwrap();
        let last = messages
            .record(&new_message(dm, &bob.actor_uri))
            .await
            .unwrap();

        let listed = conversations
            .list_for(alice.id, &alice.actor_uri)
            .await
            .unwrap();

        assert_eq!(listed.len(), 1);
        let summary = &listed[0];
        assert_eq!((summary.id, summary.kind), (dm, ConversationKind::Dm));
        assert_eq!(
            summary
                .members
                .iter()
                .map(|m| &m.actor_uri)
                .collect::<Vec<_>>(),
            vec![&bob.actor_uri]
        );
        assert_eq!(summary.last_message_sender.as_ref(), Some(&bob.actor_uri));
        assert_eq!(summary.last_message_at, Some(last.created_at));
        assert_eq!(summary.unread_count, 2);
        let bobs = conversations
            .list_for(bob.id, &bob.actor_uri)
            .await
            .unwrap();
        assert_eq!(
            bobs[0].unread_count, 0,
            "one's own messages are never unread"
        );

        conversations.mark_read(alice.id, dm).await.unwrap();

        let read = conversations
            .list_for(alice.id, &alice.actor_uri)
            .await
            .unwrap();
        assert_eq!(read[0].unread_count, 0);
    }

    pub async fn the_most_recently_active_conversation_is_listed_first(
        conversations: &dyn Conversations,
        messages: &dyn Messages,
        alice: &Account,
    ) {
        let quiet = conversations
            .open_dm(&alice.actor_uri, &remote("quiet"), None)
            .await
            .unwrap();
        let older = conversations
            .open_dm(&alice.actor_uri, &remote("older"), None)
            .await
            .unwrap();
        let newer = conversations
            .open_dm(&alice.actor_uri, &remote("newer"), None)
            .await
            .unwrap();
        messages
            .record(&new_message(older, &remote("older")))
            .await
            .unwrap();
        messages
            .record(&new_message(newer, &remote("newer")))
            .await
            .unwrap();

        let listed = conversations
            .list_for(alice.id, &alice.actor_uri)
            .await
            .unwrap();

        assert_eq!(
            listed.iter().map(|s| s.id).collect::<Vec<_>>(),
            vec![newer, older, quiet]
        );
    }

    pub async fn a_recorded_message_is_found_by_id_and_activity_pending_delivery(
        conversations: &dyn Conversations,
        messages: &dyn Messages,
        alice: &Account,
    ) {
        let dm = conversations
            .open_dm(&alice.actor_uri, &remote("bob"), None)
            .await
            .unwrap();
        let sent = new_message(dm, &alice.actor_uri);

        let recorded = messages.record(&sent).await.unwrap();

        assert_eq!(
            (recorded.id, recorded.conversation, &recorded.sender),
            (sent.id, dm, &alice.actor_uri)
        );
        assert_eq!(
            (
                &recorded.ciphertext,
                &recorded.activity_uri,
                recorded.reply_to
            ),
            (&sent.ciphertext, &sent.activity_uri, None)
        );
        assert_eq!(
            (recorded.delivery, recorded.edited_at),
            (DeliveryStatus::Pending, None)
        );
        assert_eq!(
            messages.find(sent.id).await.unwrap().as_ref(),
            Some(&recorded)
        );
        assert_eq!(
            messages.find_by_activity(&sent.activity_uri).await.unwrap(),
            Some(recorded)
        );
        assert_eq!(messages.find(MessageId::generate()).await.unwrap(), None);
    }

    pub async fn a_message_takes_the_senders_uploads_along(
        conversations: &dyn Conversations,
        messages: &dyn Messages,
        uploads: &dyn Uploads,
        alice: &Account,
    ) {
        let dm = conversations
            .open_dm(&alice.actor_uri, &remote("bob"), None)
            .await
            .unwrap();
        let files = vec![
            uploads.upload(&alice.actor_uri).await,
            uploads.upload(&alice.actor_uri).await,
        ];

        let recorded = messages
            .record(&NewMessage {
                attachments: files.clone(),
                ..new_message(dm, &alice.actor_uri)
            })
            .await
            .unwrap();

        let mut attached: Vec<_> = recorded.attachments.iter().map(|a| a.id).collect();
        attached.sort();
        let mut expected = files;
        expected.sort();
        assert_eq!(attached, expected);
        assert_eq!(
            messages
                .find(recorded.id)
                .await
                .unwrap()
                .unwrap()
                .attachments,
            recorded.attachments
        );
    }

    pub async fn an_upload_the_sender_may_not_attach_stores_nothing(
        conversations: &dyn Conversations,
        messages: &dyn Messages,
        uploads: &dyn Uploads,
        alice: &Account,
        bob: &Account,
    ) {
        let dm = conversations
            .open_dm(&alice.actor_uri, &bob.actor_uri, None)
            .await
            .unwrap();
        let bobs = uploads.upload(&bob.actor_uri).await;
        let already_sent = uploads.upload(&alice.actor_uri).await;
        messages
            .record(&NewMessage {
                attachments: vec![already_sent],
                ..new_message(dm, &alice.actor_uri)
            })
            .await
            .unwrap();

        for refused in [
            vec![bobs],
            vec![already_sent],
            vec![AttachmentId::generate()],
        ] {
            let attempt = new_message(dm, &alice.actor_uri);

            let outcome = messages
                .record(&NewMessage {
                    attachments: refused.clone(),
                    ..attempt.clone()
                })
                .await;

            assert!(
                matches!(outcome, Err(MessageStoreError::AttachmentsUnavailable)),
                "{refused:?}: {outcome:?}"
            );
            assert_eq!(messages.find(attempt.id).await.unwrap(), None);
        }
    }

    pub async fn the_uploads_of_an_undelivered_message_move_to_its_resend(
        conversations: &dyn Conversations,
        messages: &dyn Messages,
        uploads: &dyn Uploads,
        alice: &Account,
    ) {
        let dm = conversations
            .open_dm(&alice.actor_uri, &remote("bob"), None)
            .await
            .unwrap();
        let file = uploads.upload(&alice.actor_uri).await;
        let failed = messages
            .record(&NewMessage {
                attachments: vec![file],
                ..new_message(dm, &alice.actor_uri)
            })
            .await
            .unwrap();
        messages
            .set_delivery(failed.id, DeliveryStatus::Failed)
            .await
            .unwrap();

        let resent = messages
            .record(&NewMessage {
                attachments: vec![file],
                ..new_message(dm, &alice.actor_uri)
            })
            .await
            .unwrap();

        assert_eq!(resent.attachments.len(), 1);
        let failed = messages.find(failed.id).await.unwrap().unwrap();
        assert_eq!(
            (failed.delivery, failed.attachments.len()),
            (DeliveryStatus::Failed, 0)
        );
    }

    pub async fn a_received_message_records_the_attachments_it_describes(
        conversations: &dyn Conversations,
        messages: &dyn Messages,
        alice: &Account,
    ) {
        let bob = remote("bob");
        let dm = conversations
            .open_dm(&bob, &alice.actor_uri, None)
            .await
            .unwrap();
        let id = AttachmentId::generate();
        let file = RemoteAttachment {
            id,
            url: format!("https://idp.remote.test/api/attachments/{id}/content"),
            mime_type: "image/png".to_owned(),
            byte_size: 512,
            original_filename: "cat.png".to_owned(),
        };

        let received = messages
            .record_received(&new_message(dm, &bob), std::slice::from_ref(&file))
            .await
            .unwrap()
            .expect("a first delivery");

        assert_eq!(received.attachments.len(), 1);
        let view = &received.attachments[0];
        assert_eq!(
            (
                view.id,
                view.mime_type.as_str(),
                view.byte_size,
                view.original_filename.as_str()
            ),
            (id, "image/png", 512, "cat.png")
        );
        assert_eq!(messages.find(received.id).await.unwrap(), Some(received));
    }

    pub async fn a_redelivered_message_is_recorded_once(
        conversations: &dyn Conversations,
        messages: &dyn Messages,
        alice: &Account,
    ) {
        let bob = remote("bob");
        let dm = conversations
            .open_dm(&bob, &alice.actor_uri, None)
            .await
            .unwrap();
        let delivered = new_message(dm, &bob);

        let first = messages.record_received(&delivered, &[]).await.unwrap();
        let again = messages.record_received(&delivered, &[]).await.unwrap();

        assert!(first.is_some());
        assert_eq!(again, None, "already stored");
        assert_eq!(messages.history(dm, None, None, 10).await.unwrap().len(), 1);
    }

    pub async fn a_delivery_left_pending_is_failed_once_stale(
        conversations: &dyn Conversations,
        messages: &dyn Messages,
        alice: &Account,
        carol: &Account,
    ) {
        let bob = remote("bob");
        let remote_dm = conversations
            .open_dm(&alice.actor_uri, &bob, None)
            .await
            .unwrap();
        let local_dm = conversations
            .open_dm(&alice.actor_uri, &carol.actor_uri, None)
            .await
            .unwrap();
        let sent = messages
            .record(&new_message(remote_dm, &alice.actor_uri))
            .await
            .unwrap();
        let local = messages
            .record(&new_message(local_dm, &alice.actor_uri))
            .await
            .unwrap();
        let received = messages
            .record_received(&new_message(remote_dm, &bob), &[])
            .await
            .unwrap()
            .unwrap();
        let later = time::OffsetDateTime::now_utc() + time::Duration::minutes(1);

        let too_early = messages
            .fail_stale_deliveries(sent.created_at)
            .await
            .unwrap();
        let swept = messages.fail_stale_deliveries(later).await.unwrap();
        let again = messages.fail_stale_deliveries(later).await.unwrap();

        assert!(too_early.is_empty(), "not stale yet");
        assert_eq!(
            swept.iter().map(|m| m.id).collect::<Vec<_>>(),
            vec![sent.id]
        );
        assert_eq!(swept[0].delivery, DeliveryStatus::Failed);
        assert!(again.is_empty(), "swept once");
        for untouched in [local.id, received.id] {
            let kept = messages.find(untouched).await.unwrap().unwrap();
            assert_eq!(kept.delivery, DeliveryStatus::Pending);
        }
    }

    pub async fn only_its_sender_edits_a_message(
        conversations: &dyn Conversations,
        messages: &dyn Messages,
        alice: &Account,
    ) {
        let dm = conversations
            .open_dm(&alice.actor_uri, &remote("bob"), None)
            .await
            .unwrap();
        let sent = messages
            .record(&new_message(dm, &alice.actor_uri))
            .await
            .unwrap();

        assert_eq!(
            messages
                .edit(sent.id, &remote("bob"), &ciphertext(2))
                .await
                .unwrap(),
            None
        );
        let edited = messages
            .edit(sent.id, &alice.actor_uri, &ciphertext(2))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(edited.ciphertext, ciphertext(2));
        assert!(edited.edited_at.is_some());
        assert_eq!(messages.find(sent.id).await.unwrap(), Some(edited));

        let by_activity = messages
            .edit_by_activity(&sent.activity_uri, &alice.actor_uri, &ciphertext(3))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_activity.ciphertext, ciphertext(3));
        assert_eq!(
            messages
                .edit_by_activity(&sent.activity_uri, &remote("bob"), &ciphertext(4))
                .await
                .unwrap(),
            None
        );
    }

    pub async fn history_is_newest_first_in_pages_before_a_cursor(
        conversations: &dyn Conversations,
        messages: &dyn Messages,
        alice: &Account,
    ) {
        let dm = conversations
            .open_dm(&alice.actor_uri, &remote("bob"), None)
            .await
            .unwrap();
        let mut sent = Vec::new();
        for _ in 0..3 {
            sent.push(
                messages
                    .record(&new_message(dm, &alice.actor_uri))
                    .await
                    .unwrap(),
            );
        }

        let first = messages.history(dm, None, None, 2).await.unwrap();
        let cursor = HistoryCursor {
            created_at: first[1].created_at,
            id: first[1].id.as_uuid(),
        };
        let second = messages.history(dm, Some(cursor), None, 2).await.unwrap();

        assert_eq!(
            first.iter().map(|m| m.id).collect::<Vec<_>>(),
            vec![sent[2].id, sent[1].id]
        );
        assert_eq!(
            second.iter().map(|m| m.id).collect::<Vec<_>>(),
            vec![sent[0].id]
        );
        let other = conversations
            .open_dm(&alice.actor_uri, &remote("cy"), None)
            .await
            .unwrap();
        assert!(
            messages
                .history(other, None, None, 10)
                .await
                .unwrap()
                .is_empty()
        );
    }

    pub async fn a_delivery_outcome_is_recorded_on_the_message(
        conversations: &dyn Conversations,
        messages: &dyn Messages,
        alice: &Account,
    ) {
        let dm = conversations
            .open_dm(&alice.actor_uri, &remote("bob"), None)
            .await
            .unwrap();
        let sent = messages
            .record(&new_message(dm, &alice.actor_uri))
            .await
            .unwrap();

        messages
            .set_delivery(sent.id, DeliveryStatus::Delivered)
            .await
            .unwrap();

        assert_eq!(
            messages.find(sent.id).await.unwrap().unwrap().delivery,
            DeliveryStatus::Delivered
        );
    }
}

#[cfg(test)]
mod tests;
