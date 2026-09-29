//! In-memory fakes of the messaging ports and the contract every store must satisfy.

use std::collections::HashMap;
use std::sync::Mutex;

use time::OffsetDateTime;

use crate::identity::{Account, ActorUri, InstanceOrigin, RemoteActor};
use crate::{AttachmentId, ConversationId, MessageId, UserId};

use bytes::Bytes;

use super::{
    Attachment, Attachments, BlobTokenError, BlobTokens, ByteStream, Conversation,
    ConversationKind, ConversationSummary, Conversations, DeliveryFailed, DeliveryStatus,
    DirectDelivery, GroupName, GroupNotifier, GroupSnapshot, HistoryCursor, Member, MemberView,
    Message, MessageEvent, MessageFederation, MessageNotifier, MessageStoreError, Messages,
    MlsCiphertext, NewMessage, ObjectStore, ObjectStoreError, RemoteAttachment, RemoteFiles, Role,
    may_hold_dm,
};

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
    /// Every membership ever held; `active` is false once the member left.
    members: Vec<Membership>,
    messages: Vec<Message>,
    uploads: Vec<Upload>,
    reads: HashMap<(UserId, ConversationId), OffsetDateTime>,
}

struct Membership {
    conversation: ConversationId,
    member: Member,
    active: bool,
}

struct Upload {
    attachment: Attachment,
    recorded_at: OffsetDateTime,
}

impl State {
    fn active_members(&self, id: ConversationId) -> Vec<Member> {
        self.members
            .iter()
            .filter(|m| m.conversation == id && m.active)
            .map(|m| m.member.clone())
            .collect()
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

    fn create(&mut self, id: ConversationId, kind: ConversationKind, name: Option<String>) {
        self.conversations.push(Conversation {
            id,
            kind,
            name,
            created_at: OffsetDateTime::now_utc(),
        });
    }

    /// Joins, or re-joins in the role it already had.
    fn add(&mut self, id: ConversationId, actor: &ActorUri) {
        match self
            .members
            .iter_mut()
            .find(|m| m.conversation == id && &m.member.actor_uri == actor)
        {
            Some(existing) => existing.active = true,
            None => self.members.push(Membership {
                conversation: id,
                member: Member {
                    actor_uri: actor.clone(),
                    role: Role::Member,
                },
                active: true,
            }),
        }
    }

    fn add_in_role(&mut self, id: ConversationId, member: &Member) {
        self.add(id, &member.actor_uri);
        let held = self
            .members
            .iter_mut()
            .find(|m| m.conversation == id && m.member.actor_uri == member.actor_uri)
            .expect("just added");
        held.member.role = member.role;
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
                    state.create(pinned, ConversationKind::Dm, None);
                    pinned
                }
                Some(existing) => {
                    let ever: Vec<ActorUri> = state
                        .members
                        .iter()
                        .filter(|m| m.conversation == pinned)
                        .map(|m| m.member.actor_uri.clone())
                        .collect();
                    if may_hold_dm(existing.kind, &ever, a, b) {
                        pinned
                    } else {
                        let id = ConversationId::generate();
                        state.create(id, ConversationKind::Dm, None);
                        id
                    }
                }
            },
            (None, None) => {
                let id = ConversationId::generate();
                state.create(id, ConversationKind::Dm, None);
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

    async fn ever_held(
        &self,
        actor: &ActorUri,
        ids: &[ConversationId],
    ) -> Result<Vec<ConversationId>, MessageStoreError> {
        let state = self.state.lock().unwrap();
        let mut held: Vec<ConversationId> = state
            .members
            .iter()
            .filter(|m| &m.member.actor_uri == actor && ids.contains(&m.conversation))
            .map(|m| m.conversation)
            .collect();
        held.sort();
        held.dedup();
        Ok(held)
    }

    async fn mirror_group(
        &self,
        id: ConversationId,
        snapshot: &GroupSnapshot,
    ) -> Result<Conversation, MessageStoreError> {
        let mut state = self.state.lock().unwrap();
        match state.conversations.iter_mut().find(|c| c.id == id) {
            Some(existing) => {
                if let Some(name) = &snapshot.name
                    && existing.kind == ConversationKind::Group
                {
                    existing.name = Some(name.clone());
                }
            }
            None => state.create(id, ConversationKind::Group, snapshot.name.clone()),
        }
        for member in &snapshot.members {
            state.add_in_role(id, member);
        }
        let group = state.conversations.iter().find(|c| c.id == id).cloned();
        Ok(group.expect("just mirrored"))
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
                }
            })
            .collect();
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
        );
        for member in roster {
            state.add_in_role(id, member);
        }
        let group = state.conversations.iter().find(|c| c.id == id).cloned();
        Ok(group.expect("just created"))
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
    ) -> Result<bool, MessageStoreError> {
        let mut state = self.state.lock().unwrap();
        let held = state
            .members
            .iter_mut()
            .find(|m| m.conversation == id && &m.member.actor_uri == actor && m.active);
        Ok(held.map(|m| m.active = false).is_some())
    }

    async fn set_role(
        &self,
        id: ConversationId,
        actor: &ActorUri,
        role: Role,
    ) -> Result<Option<Member>, MessageStoreError> {
        let mut state = self.state.lock().unwrap();
        let held = state
            .members
            .iter_mut()
            .find(|m| m.conversation == id && &m.member.actor_uri == actor && m.active);
        Ok(held.map(|m| {
            m.member.role = role;
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
        limit: i64,
    ) -> Result<Vec<Message>, MessageStoreError> {
        let state = self.state.lock().unwrap();
        let mut page: Vec<_> = state
            .messages
            .iter()
            .filter(|m| m.conversation == conversation)
            .filter(|m| before.is_none_or(|c| (m.created_at, m.id) < (c.created_at, c.id)))
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
                            && held.member.actor_uri != m.sender
                            && !here.owns(&held.member.actor_uri)
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
}

impl RecordingGroupNotifier {
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
        to: &[RemoteActor],
        message: &Message,
        reply_to: Option<&str>,
        group: &GroupSnapshot,
    ) {
        self.sent.lock().unwrap().push(Outbound::Group {
            from: from.actor_uri.clone(),
            to: to.iter().map(|r| r.actor_uri.clone()).collect(),
            message: message.id,
            reply_to: reply_to.map(str::to_owned),
            group: group.clone(),
        });
    }

    fn send_edit(&self, from: &Account, to: &RemoteActor, message: &Message) {
        self.sent.lock().unwrap().push(Outbound::Edit {
            from: from.actor_uri.clone(),
            to: to.actor_uri.clone(),
            message: message.id,
        });
    }
}

pub mod contract {
    use crate::identity::{Account, ActorUri};
    use crate::messaging::{
        Attachment, Attachments, ConversationKind, Conversations, DeliveryStatus, GroupName,
        GroupSnapshot, HistoryCursor, Member, MessageStoreError, Messages, MlsCiphertext,
        NewMessage, RemoteAttachment, Role,
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
                &GroupSnapshot {
                    name: None,
                    members: roster.clone(),
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

    pub async fn a_mirrored_group_is_created_with_its_name_and_roster(
        conversations: &dyn Conversations,
        alice: &Account,
    ) {
        let id = ConversationId::generate();
        let roster = vec![
            member(&remote("ana"), Role::Admin),
            member(&alice.actor_uri, Role::Member),
        ];

        let group = conversations
            .mirror_group(
                id,
                &GroupSnapshot {
                    name: Some("crew".to_owned()),
                    members: roster.clone(),
                },
            )
            .await
            .unwrap();

        assert_eq!(
            (group.id, group.kind, group.name.as_deref()),
            (id, ConversationKind::Group, Some("crew"))
        );
        assert_eq!(conversations.find(id).await.unwrap(), Some(group));
        assert_eq!(
            sorted(conversations.members(id).await.unwrap()),
            sorted(roster)
        );
    }

    pub async fn mirroring_again_renames_and_converges_without_removing_anyone(
        conversations: &dyn Conversations,
        alice: &Account,
    ) {
        let id = ConversationId::generate();
        let first = GroupSnapshot {
            name: Some("crew".to_owned()),
            members: vec![
                member(&remote("ana"), Role::Admin),
                member(&alice.actor_uri, Role::Member),
            ],
        };
        conversations.mirror_group(id, &first).await.unwrap();

        let renamed = conversations
            .mirror_group(
                id,
                &GroupSnapshot {
                    name: Some("new crew".to_owned()),
                    members: vec![
                        member(&alice.actor_uri, Role::Admin),
                        member(&remote("cy"), Role::Member),
                    ],
                },
            )
            .await
            .unwrap();

        assert_eq!(renamed.name.as_deref(), Some("new crew"));
        assert_eq!(
            sorted(conversations.members(id).await.unwrap()),
            sorted(vec![
                member(&remote("ana"), Role::Admin),
                member(&alice.actor_uri, Role::Admin),
                member(&remote("cy"), Role::Member),
            ])
        );
        let unnamed = conversations
            .mirror_group(
                id,
                &GroupSnapshot {
                    name: None,
                    members: first.members,
                },
            )
            .await
            .unwrap();
        assert_eq!(unnamed.name.as_deref(), Some("new crew"));
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
            .remove_member(group.id, &bob.actor_uri)
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
            .remove_member(left, &bob.actor_uri)
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
                .remove_member(group.id, &bob.actor_uri)
                .await
                .unwrap()
        );
        assert!(
            !conversations
                .remove_member(group.id, &bob.actor_uri)
                .await
                .unwrap()
        );
        assert!(
            !conversations
                .remove_member(group.id, &remote("never"))
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
            .remove_member(group.id, &bob.actor_uri)
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
        assert_eq!(messages.history(dm, None, 10).await.unwrap().len(), 1);
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

        let first = messages.history(dm, None, 2).await.unwrap();
        let cursor = HistoryCursor {
            created_at: first[1].created_at,
            id: first[1].id,
        };
        let second = messages.history(dm, Some(cursor), 2).await.unwrap();

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
        assert!(messages.history(other, None, 10).await.unwrap().is_empty());
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
