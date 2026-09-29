//! The router over the real use cases and in-memory fakes, for route tests.

use std::sync::Arc;

use application::e2ee::{
    AppendCommit, ArchiveMessages, CatchUpCommits, ClaimKeyPackage, ClaimWelcomes, ClearArchive,
    KeyPackageStatus, ListDevices, LoadArchiveSalt, ReadArchive, RegisterDevice, RevokeDevice,
    SendWelcome, SetArchiveSalt, UploadKeyPackages,
};
use application::messaging::{
    AddGroupMember, CreateGroup, DeliverDirectMessage, EditMessage, ListConversations,
    ListGroupMembers, LoadHistory, MarkRead, OpenAttachment, ReadBlob, RemoveGroupMember,
    RenameGroup, SendDirectMessage, SendGroupMessage, SetMemberRole, UploadAttachments,
};
use application::presence::{
    Connect, Disconnect, Heartbeat, OpenPeerStream, ReadPresence, ServePeerPresence, SetPresence,
    StartTyping, WatchConversation,
};
use application::settings::UpdateSettings;
use application::social::{
    AcceptFriendRequest, DeclineFriendRequest, ListFriends, ListIncomingRequests,
    SendFriendRequest, Unfriend,
};
use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::response::IntoResponse;
use domain::UserId;
use domain::e2ee::KeyPackagePolicy;
use domain::e2ee::testing::{
    InMemoryArchive, InMemoryDelivery, InMemoryKeyDirectory, InMemoryRemoteKeyPackages,
    PlainAttester, RecordingDeviceNotifier, RecordingMlsFederation, RecordingMlsNotifier,
};
use domain::identity::testing::{
    InMemoryAccounts, InMemoryRemoteActors, InMemoryTokens, TrustedSignatures,
};
use domain::identity::{Account, Accounts, ActorUri, InstanceOrigin, RemoteActor, RemoteActors};
use domain::messaging::AttachmentLimits;
use domain::messaging::testing::{
    InMemoryMessaging, InMemoryObjects, InMemoryRemoteFiles, PlainBlobTokens,
    RecordingGroupNotifier, RecordingMessageFederation, RecordingMessageNotifier,
};
use domain::presence::testing::{
    InMemoryAudience, InMemoryMissedEvents, QueuedFeed, RecordingBus, RecordingPeerStreams,
};
use domain::presence::{ConnectionTracker, PresenceBoard};
use domain::settings::testing::{InMemorySettingsStore, RecordingSettingsNotifier};
use domain::social::testing::{
    InMemorySocialGraph, RecordingFriendPresence, RecordingSocialFederation,
    RecordingSocialNotifier,
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use crate::{AppState, RateLimiter, router};

pub struct TestApp {
    router: Router,
    tokens: Arc<InMemoryTokens>,
}

impl TestApp {
    /// An instance on `http://localhost:8080`, like `domain::identity::testing::account`'s.
    pub fn with(
        accounts: impl IntoIterator<Item = Account>,
        remote: impl IntoIterator<Item = RemoteActor>,
    ) -> Self {
        let accounts: Arc<dyn Accounts> = Arc::new(InMemoryAccounts::with(accounts));
        let remote_actors: Arc<dyn RemoteActors> = Arc::new(InMemoryRemoteActors::with(remote));
        let graph = Arc::new(InMemorySocialGraph::default());
        let notifier = Arc::new(RecordingSocialNotifier::default());
        let federation = Arc::new(RecordingSocialFederation::default());
        let presence = Arc::new(RecordingFriendPresence::default());
        let tokens = Arc::new(InMemoryTokens::default());
        let origin = InstanceOrigin::parse("http://localhost:8080").unwrap();
        let store = Arc::new(InMemoryMessaging::default());
        let message_notifier = Arc::new(RecordingMessageNotifier::default());
        let message_federation = Arc::new(RecordingMessageFederation::default());
        let group_notifier = Arc::new(RecordingGroupNotifier::default());
        let objects = Arc::new(InMemoryObjects::default());
        let limits = AttachmentLimits {
            max_files: 5,
            max_bytes: 1_000_000,
            blocked_mimes: Vec::new(),
            blocked_extensions: Vec::new(),
        };
        let keys = Arc::new(InMemoryKeyDirectory::default());
        let delivery = Arc::new(InMemoryDelivery::default());
        let archive = Arc::new(InMemoryArchive::default());
        let tracker = Arc::new(ConnectionTracker::default());
        let board = Arc::new(PresenceBoard::default());
        let audience = Arc::new(InMemoryAudience::default());
        let bus = Arc::new(RecordingBus::default());
        let mls_notifier = Arc::new(RecordingMlsNotifier::default());
        let mls_federation = Arc::new(RecordingMlsFederation::default());
        let key_policy = KeyPackagePolicy {
            cap_per_device: 100,
            refill_threshold: 20,
            max_lifetime: time::Duration::days(30),
        };
        let state = AppState {
            auth: tokens.clone(),
            signatures: Arc::new(TrustedSignatures),
            origin: origin.clone(),
            update_settings: Arc::new(UpdateSettings::new(
                Arc::new(InMemorySettingsStore::default()),
                Arc::new(RecordingSettingsNotifier::default()),
            )),
            send_friend_request: Arc::new(SendFriendRequest::new(
                accounts.clone(),
                remote_actors.clone(),
                graph.clone(),
                notifier.clone(),
                federation.clone(),
            )),
            list_incoming_requests: Arc::new(ListIncomingRequests::new(
                accounts.clone(),
                remote_actors.clone(),
                graph.clone(),
            )),
            accept_friend_request: Arc::new(AcceptFriendRequest::new(
                accounts.clone(),
                remote_actors.clone(),
                graph.clone(),
                notifier.clone(),
                federation.clone(),
                presence.clone(),
            )),
            decline_friend_request: Arc::new(DeclineFriendRequest::new(
                accounts.clone(),
                remote_actors.clone(),
                graph.clone(),
                federation.clone(),
            )),
            unfriend: Arc::new(Unfriend::new(
                accounts.clone(),
                remote_actors.clone(),
                graph.clone(),
                notifier,
                federation,
                presence,
            )),
            list_friends: Arc::new(ListFriends::new(graph.clone())),
            send_direct_message: Arc::new(SendDirectMessage::new(
                origin.clone(),
                5,
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                store.clone(),
                message_notifier.clone(),
            )),
            deliver_direct_message: Arc::new(DeliverDirectMessage::new(
                message_federation.clone(),
                store.clone(),
                message_notifier.clone(),
            )),
            send_group_message: Arc::new(SendGroupMessage::new(
                5,
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                store.clone(),
                message_notifier.clone(),
                message_federation.clone(),
            )),
            edit_message: Arc::new(EditMessage::new(
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                store.clone(),
                message_notifier.clone(),
                message_federation,
            )),
            load_history: Arc::new(LoadHistory::new(
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                store.clone(),
            )),
            mark_read: Arc::new(MarkRead::new(accounts.clone(), store.clone())),
            list_conversations: Arc::new(ListConversations::new(accounts.clone(), store.clone())),
            create_group: Arc::new(CreateGroup::new(
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                group_notifier.clone(),
            )),
            list_group_members: Arc::new(ListGroupMembers::new(
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
            )),
            add_group_member: Arc::new(AddGroupMember::new(
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                group_notifier.clone(),
            )),
            remove_group_member: Arc::new(RemoveGroupMember::new(
                accounts.clone(),
                store.clone(),
                group_notifier.clone(),
            )),
            rename_group: Arc::new(RenameGroup::new(
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                group_notifier.clone(),
            )),
            set_member_role: Arc::new(SetMemberRole::new(
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                group_notifier,
            )),
            attachment_limits: limits.clone(),
            upload_attachments: Arc::new(UploadAttachments::new(
                limits,
                accounts.clone(),
                store.clone(),
                objects.clone(),
            )),
            open_attachment: Arc::new(OpenAttachment::new(
                accounts.clone(),
                store.clone(),
                store.clone(),
                store.clone(),
                Arc::new(PlainBlobTokens),
            )),
            read_blob: Arc::new(ReadBlob::new(
                store.clone(),
                Arc::new(PlainBlobTokens),
                objects,
                Arc::new(InMemoryRemoteFiles::default()),
            )),
            register_device: Arc::new(RegisterDevice::new(
                accounts.clone(),
                keys.clone(),
                Arc::new(PlainAttester),
                Arc::new(RecordingDeviceNotifier::default()),
            )),
            list_devices: Arc::new(ListDevices::new(keys.clone())),
            revoke_device: Arc::new(RevokeDevice::new(keys.clone())),
            upload_key_packages: Arc::new(UploadKeyPackages::new(
                key_policy,
                keys.clone(),
                keys.clone(),
            )),
            claim_key_package: Arc::new(ClaimKeyPackage::new(
                origin.clone(),
                key_policy,
                accounts.clone(),
                keys.clone(),
                Arc::new(InMemoryRemoteKeyPackages::default()),
            )),
            key_package_status: Arc::new(KeyPackageStatus::new(key_policy, keys)),
            claim_limiter: Arc::new(RateLimiter::new(60, 1.0)),
            append_commit: Arc::new(AppendCommit::new(
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                delivery.clone(),
                mls_notifier.clone(),
                mls_federation.clone(),
            )),
            catch_up_commits: Arc::new(CatchUpCommits::new(
                accounts.clone(),
                store.clone(),
                delivery.clone(),
            )),
            claim_welcomes: Arc::new(ClaimWelcomes::new(delivery.clone())),
            archive_messages: Arc::new(ArchiveMessages::new(
                accounts.clone(),
                store.clone(),
                archive.clone(),
            )),
            read_archive: Arc::new(ReadArchive::new(archive.clone())),
            clear_archive: Arc::new(ClearArchive::new(archive.clone())),
            load_archive_salt: Arc::new(LoadArchiveSalt::new(archive.clone())),
            set_archive_salt: Arc::new(SetArchiveSalt::new(archive)),
            hub: Arc::new(idp_realtime::WsHub::new()),
            missed_events: Arc::new(InMemoryMissedEvents::default()),
            connect: Arc::new(Connect::new(accounts.clone(), tracker.clone(), bus.clone())),
            disconnect: Arc::new(Disconnect::new(tracker.clone(), bus.clone())),
            heartbeat: Arc::new(Heartbeat::new(tracker, board.clone(), bus.clone())),
            set_presence: Arc::new(SetPresence::new(bus.clone())),
            start_typing: Arc::new(StartTyping::new(store.clone(), bus)),
            watch_conversation: Arc::new(WatchConversation::new(
                origin.clone(),
                store.clone(),
                Arc::new(RecordingPeerStreams::default()),
            )),
            read_presence: Arc::new(ReadPresence::new(
                accounts.clone(),
                board.clone(),
                audience.clone(),
            )),
            serve_peer_presence: Arc::new(ServePeerPresence::new(
                origin.clone(),
                board.clone(),
                audience.clone(),
            )),
            open_peer_stream: Arc::new(OpenPeerStream::new(
                origin.clone(),
                board,
                audience,
                Arc::new(QueuedFeed::default()),
            )),
            typing_limiter: Arc::new(RateLimiter::new(1, 1.0)),
            send_welcome: Arc::new(SendWelcome::new(
                origin.clone(),
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                delivery,
                mls_notifier,
                mls_federation,
            )),
        };
        Self {
            router: router(state),
            tokens,
        }
    }

    /// `caller` signs the request in; `None` sends no Authorization header.
    pub async fn call(
        &self,
        method: Method,
        uri: &str,
        caller: Option<UserId>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(uri);
        if let Some(user) = caller {
            let token = self.tokens.issue(user);
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = match body {
            Some(body) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => request.body(Body::empty()),
        };
        self.send(request.unwrap()).await
    }

    /// A bearer token for `user`, for requests built by hand.
    pub fn token(&self, user: UserId) -> String {
        self.tokens.issue(user)
    }

    /// A request another instance signed, as `peer`.
    pub async fn call_as_peer(
        &self,
        method: Method,
        uri: &str,
        peer: &ActorUri,
        body: Value,
    ) -> (StatusCode, Value) {
        let (name, value) = TrustedSignatures::header(peer);
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(name, value)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        self.send(request).await
    }

    pub async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        Self::body_of(self.router.clone().oneshot(request).await.unwrap()).await
    }

    pub async fn body_of(response: impl IntoResponse) -> (StatusCode, Value) {
        let response = response.into_response();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        // axum's own rejections are plain text: kept as a string, so assertions can show them.
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
        };
        (status, body)
    }
}
