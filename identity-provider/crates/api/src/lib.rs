mod attachments;
pub mod auth;
pub mod background;
pub mod error;
mod groups;
mod history;
mod key_directory;
mod messaging;
mod mls;
mod presence;
pub mod rate_limit;
mod settings;
mod social;
#[cfg(test)]
mod testing;
mod ws;

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
use axum::extract::{DefaultBodyLimit, FromRef};
use axum::routing::{delete, get, patch, post};
use domain::identity::{InstanceOrigin, SignatureVerifier, TokenVerifier};
use domain::messaging::AttachmentLimits;
use domain::presence::MissedEvents;
use idp_realtime::WsHub;

pub use error::ApiError;
pub use rate_limit::RateLimiter;

/// What handlers reach through `State`, built in the composition root.
#[derive(Clone, FromRef)]
pub struct AppState {
    pub auth: Arc<dyn TokenVerifier>,
    pub signatures: Arc<dyn SignatureVerifier>,
    pub origin: InstanceOrigin,
    pub update_settings: Arc<UpdateSettings>,
    pub send_friend_request: Arc<SendFriendRequest>,
    pub list_incoming_requests: Arc<ListIncomingRequests>,
    pub accept_friend_request: Arc<AcceptFriendRequest>,
    pub decline_friend_request: Arc<DeclineFriendRequest>,
    pub unfriend: Arc<Unfriend>,
    pub list_friends: Arc<ListFriends>,
    pub send_direct_message: Arc<SendDirectMessage>,
    pub deliver_direct_message: Arc<DeliverDirectMessage>,
    pub send_group_message: Arc<SendGroupMessage>,
    pub edit_message: Arc<EditMessage>,
    pub load_history: Arc<LoadHistory>,
    pub mark_read: Arc<MarkRead>,
    pub list_conversations: Arc<ListConversations>,
    pub create_group: Arc<CreateGroup>,
    pub list_group_members: Arc<ListGroupMembers>,
    pub add_group_member: Arc<AddGroupMember>,
    pub remove_group_member: Arc<RemoveGroupMember>,
    pub rename_group: Arc<RenameGroup>,
    pub set_member_role: Arc<SetMemberRole>,
    pub attachment_limits: AttachmentLimits,
    pub upload_attachments: Arc<UploadAttachments>,
    pub open_attachment: Arc<OpenAttachment>,
    pub read_blob: Arc<ReadBlob>,
    pub register_device: Arc<RegisterDevice>,
    pub list_devices: Arc<ListDevices>,
    pub revoke_device: Arc<RevokeDevice>,
    pub upload_key_packages: Arc<UploadKeyPackages>,
    pub claim_key_package: Arc<ClaimKeyPackage>,
    pub key_package_status: Arc<KeyPackageStatus>,
    /// Claims hand out other accounts' single-use KeyPackages: bounded per requester.
    pub claim_limiter: Arc<RateLimiter>,
    pub append_commit: Arc<AppendCommit>,
    pub catch_up_commits: Arc<CatchUpCommits>,
    pub claim_welcomes: Arc<ClaimWelcomes>,
    pub send_welcome: Arc<SendWelcome>,
    pub archive_messages: Arc<ArchiveMessages>,
    pub read_archive: Arc<ReadArchive>,
    pub clear_archive: Arc<ClearArchive>,
    pub load_archive_salt: Arc<LoadArchiveSalt>,
    pub set_archive_salt: Arc<SetArchiveSalt>,
    /// The live connections, which the WebSocket registers with.
    pub hub: Arc<WsHub>,
    pub missed_events: Arc<dyn MissedEvents>,
    pub connect: Arc<Connect>,
    pub disconnect: Arc<Disconnect>,
    pub heartbeat: Arc<Heartbeat>,
    pub set_presence: Arc<SetPresence>,
    pub start_typing: Arc<StartTyping>,
    pub watch_conversation: Arc<WatchConversation>,
    pub read_presence: Arc<ReadPresence>,
    pub serve_peer_presence: Arc<ServePeerPresence>,
    pub open_peer_stream: Arc<OpenPeerStream>,
    #[from_ref(skip)]
    pub typing_limiter: Arc<RateLimiter>,
}

pub fn router(state: AppState) -> Router {
    // Every file of an upload at its largest, plus headroom for the multipart framing.
    let upload_limit = state.attachment_limits.max_files
        * usize::try_from(state.attachment_limits.max_bytes).unwrap_or(usize::MAX)
        + 1024 * 1024;
    Router::new()
        .route(
            "/api/attachments",
            post(attachments::upload).layer(DefaultBodyLimit::max(upload_limit)),
        )
        .route("/api/attachments/{id}", get(attachments::open))
        .route("/api/attachments/{id}/blob", get(attachments::blob))
        .route(
            "/api/keys/devices",
            get(key_directory::devices).post(key_directory::register),
        )
        .route(
            "/api/keys/devices/{device_id}/revoke",
            post(key_directory::revoke),
        )
        .route("/api/keys/packages", post(key_directory::upload))
        .route("/api/keys/packages/claim", post(key_directory::claim))
        .route("/api/keys/packages/status", get(key_directory::status))
        .route(
            "/api/mls/groups/{conversation_id}/commits",
            post(mls::append).get(mls::catch_up),
        )
        .route(
            "/api/mls/welcomes",
            get(mls::welcomes).post(mls::send_welcome),
        )
        .route(
            "/api/history/messages",
            post(history::upload)
                .get(history::page)
                .delete(history::clear),
        )
        .route(
            "/api/history/salt",
            get(history::salt).post(history::set_salt),
        )
        .route("/api/presence", get(presence::read))
        .route("/api/presence/batch", post(presence::batch))
        .route("/api/presence/stream", get(presence::stream))
        .route("/api/settings", patch(settings::update_settings))
        .route("/ws", get(ws::upgrade))
        .route("/api/friends", get(social::friends))
        .route("/api/friends/request", post(social::send_request))
        .route("/api/friends/incoming", get(social::incoming))
        .route("/api/friends/{actor_uri}", delete(social::unfriend))
        .route("/api/friends/{friendship_id}/accept", post(social::accept))
        .route(
            "/api/friends/{friendship_id}/reject",
            delete(social::reject),
        )
        .route(
            "/api/dm",
            post(messaging::send_message).get(messaging::conversations),
        )
        .route("/api/dm/{conversation_id}", get(messaging::history))
        .route("/api/dm/{conversation_id}/read", post(messaging::mark_read))
        .route("/api/dm/{message_id}/edit", patch(messaging::edit))
        .route("/api/groups", post(groups::create))
        .route("/api/groups/{conversation_id}", patch(groups::rename))
        .route(
            "/api/groups/{conversation_id}/messages",
            post(messaging::send_group_message),
        )
        .route(
            "/api/groups/{conversation_id}/members",
            get(groups::members).post(groups::add),
        )
        .route(
            "/api/groups/{conversation_id}/members/{actor_uri}",
            delete(groups::remove),
        )
        .route(
            "/api/groups/{conversation_id}/members/{actor_uri}/role",
            post(groups::set_role),
        )
        .with_state(state)
}
