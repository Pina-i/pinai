mod accounts;
mod actors;
mod attachments;
pub mod auth;
pub mod background;
mod blocks;
pub mod error;
mod groups;
mod history;
mod http;
mod inbox;
mod key_directory;
mod messaging;
mod mls;
mod presence;
mod privacy;
mod profile;
pub mod rate_limit;
mod second_factor;
mod settings;
mod sign_in;
mod sign_up;

mod social;
#[cfg(test)]
mod testing;
mod ws;

use std::sync::Arc;

use application::auth::{
    Authorize, ConfirmTotpEnrollment, DisableTotp, ExchangeCode, LogIn, LogOut, PassSecondFactor,
    RegenerateRecoveryCodes, Register, ResendCode, SendTestMail, StartTotpEnrollment, VerifyEmail,
};
use application::e2ee::{
    AppendCommit, ArchiveMessages, CatchUpCommits, ClaimKeyPackage, ClaimWelcomes, ClearArchive,
    KeyPackageStatus, ListDevices, LoadArchiveSalt, ReadArchive, ReceiveCommit, ReceiveWelcome,
    RegisterDevice, RevokeDevice, SendWelcome, SetArchiveSalt, UploadKeyPackages,
};
use application::identity::{FindAccount, SearchAccounts, WebFinger};
use application::messaging::{
    AddGroupMember, CreateGroup, DeliverDirectMessage, DismissGroup, EditMessage,
    ListConversations, ListGroupMembers, LoadHistory, MarkRead, OpenAttachment, ReadBlob,
    ReceiveEdit, ReceiveGroupChange, ReceiveMessage, RemoveGroupMember, RenameGroup,
    SendDirectMessage, SendGroupMessage, ServePeerContent, SetMemberRole, UploadAttachments,
};
use application::presence::{
    Connect, Disconnect, Heartbeat, OpenPeerStream, ReadPresence, ServePeerPresence, SetPresence,
    StartTyping, WatchConversation,
};
use application::profile::{
    ClearAvatar, EditProfile, ReadProfile, ReadUserinfo, ReceiveProfileUpdate, SetAvatar,
};
use application::settings::UpdateSettings;
use application::social::{
    AcceptFriendRequest, Block, DeclineFriendRequest, ListBlocks, ListFriends,
    ListIncomingRequests, ReceiveAccept, ReceiveFollow, ReceiveReject, ReceiveUndoFollow,
    SendFriendRequest, SetContactPolicy, Unblock, Unfriend,
};
use axum::extract::{DefaultBodyLimit, FromRef};
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use axum_extra::extract::cookie::Key;
use connections::Hub;
use domain::identity::{InstanceOrigin, SignatureVerifier, TokenVerifier};
use domain::messaging::AttachmentLimits;
use domain::presence::MissedEvents;
use serde_json::json;
use tokio_util::sync::CancellationToken;

pub use actors::PublicKeyPem;
pub use error::ApiError;
pub use rate_limit::RateLimiter;
pub use sign_in::{Jwks, LoginAttempts, SignInPages};

/// What handlers reach through `State`, built in the composition root.
#[derive(Clone, FromRef)]
pub struct AppState {
    pub auth: Arc<dyn TokenVerifier>,
    /// Signs the session cookie.
    pub cookie_key: Key,
    pub sign_in_pages: SignInPages,
    pub jwks: Jwks,
    pub authorize: Arc<Authorize>,
    pub log_in: Arc<LogIn>,
    pub exchange_code: Arc<ExchangeCode>,
    pub log_out: Arc<LogOut>,
    pub login_attempts: LoginAttempts,
    pub register: Arc<Register>,
    pub verify_email: Arc<VerifyEmail>,
    pub resend_code: Arc<ResendCode>,
    pub send_test_mail: Arc<SendTestMail>,
    pub pass_second_factor: Arc<PassSecondFactor>,
    pub start_totp_enrollment: Arc<StartTotpEnrollment>,
    pub confirm_totp_enrollment: Arc<ConfirmTotpEnrollment>,
    pub disable_totp: Arc<DisableTotp>,
    pub regenerate_recovery_codes: Arc<RegenerateRecoveryCodes>,
    /// Mounts `/dev/*`: a development instance only.
    #[from_ref(skip)]
    pub dev_routes: bool,
    pub signatures: Arc<dyn SignatureVerifier>,
    pub origin: InstanceOrigin,
    /// The web client's origins, allowed cross-origin.
    #[from_ref(skip)]
    pub cors_origins: Vec<String>,
    pub public_key_pem: PublicKeyPem,
    pub find_account: Arc<FindAccount>,
    pub show_person: Arc<application::profile::ShowPerson>,
    pub web_finger: Arc<WebFinger>,
    pub search_accounts: Arc<SearchAccounts>,
    /// What the inbox receives.
    pub receive_follow: Arc<ReceiveFollow>,
    pub receive_accept: Arc<ReceiveAccept>,
    pub receive_reject: Arc<ReceiveReject>,
    pub receive_undo_follow: Arc<ReceiveUndoFollow>,
    pub receive_message: Arc<ReceiveMessage>,
    pub receive_edit: Arc<ReceiveEdit>,
    pub receive_commit: Arc<ReceiveCommit>,
    pub receive_welcome: Arc<ReceiveWelcome>,
    pub receive_profile_update: Arc<ReceiveProfileUpdate>,
    /// A peer's fetch of an attachment uploaded here.
    pub serve_peer_content: Arc<ServePeerContent>,
    pub update_settings: Arc<UpdateSettings>,
    pub read_userinfo: Arc<ReadUserinfo>,
    pub read_profile: Arc<ReadProfile>,
    pub edit_profile: Arc<EditProfile>,
    pub set_avatar: Arc<SetAvatar>,
    pub clear_avatar: Arc<ClearAvatar>,
    pub send_friend_request: Arc<SendFriendRequest>,
    pub list_incoming_requests: Arc<ListIncomingRequests>,
    pub accept_friend_request: Arc<AcceptFriendRequest>,
    pub decline_friend_request: Arc<DeclineFriendRequest>,
    pub unfriend: Arc<Unfriend>,
    pub list_friends: Arc<ListFriends>,
    pub block: Arc<Block>,
    pub unblock: Arc<Unblock>,
    pub list_blocks: Arc<ListBlocks>,
    pub set_contact_policy: Arc<SetContactPolicy>,
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
    pub dismiss_group: Arc<DismissGroup>,
    pub receive_group_change: Arc<ReceiveGroupChange>,
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
    pub hub: Arc<Hub>,
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
    /// Cancelled when the instance stops: the long-lived connections end.
    pub shutdown: CancellationToken,
}

pub fn router(state: AppState) -> Router {
    let dev_routes = state.dev_routes;
    let cors = http::cors(&state.cors_origins);
    // Every file of an upload at its largest, plus headroom for the multipart framing.
    let upload_limit = state.attachment_limits.max_files
        * usize::try_from(state.attachment_limits.max_bytes).unwrap_or(usize::MAX)
        + 1024 * 1024;
    Router::new()
        .route("/health", get(|| async { Json(json!({ "ok": true })) }))
        .route("/.well-known/webfinger", get(actors::web_finger))
        .route("/actor", get(actors::instance_actor))
        .route("/users/{slug}", get(actors::person))
        .route("/users/{slug}/inbox", post(inbox::receive))
        .route("/users/{slug}/outbox", get(actors::outbox))
        .route("/users/{slug}/followers", get(actors::followers))
        .route("/users/{slug}/following", get(actors::following))
        .route("/api/users/search", get(accounts::search))
        .route("/.well-known/openid-configuration", get(sign_in::discovery))
        .route("/.well-known/jwks.json", get(sign_in::jwks))
        .route("/authorize", get(sign_in::authorize))
        .route("/login", post(sign_in::log_in))
        .route("/token", post(sign_in::token))
        .route("/logout", get(sign_in::log_out))
        .route("/register", post(sign_up::register))
        .route("/register-and-login", post(sign_up::register_and_log_in))
        .route("/verify-email-and-login", post(sign_up::verify_email))
        .route("/verify-email/resend", post(sign_up::resend))
        .route("/login/totp", post(second_factor::pass))
        .route("/api/totp/enroll", post(second_factor::enroll))
        .route("/api/totp/enroll/verify", post(second_factor::confirm))
        .route("/api/totp/disable", post(second_factor::disable))
        .route(
            "/api/totp/recovery-codes/regenerate",
            post(second_factor::regenerate),
        )
        .route(
            "/api/attachments",
            post(attachments::upload).layer(DefaultBodyLimit::max(upload_limit)),
        )
        .route("/api/attachments/{id}", get(attachments::open))
        .route("/api/attachments/{id}/blob", get(attachments::blob))
        .route("/api/attachments/{id}/content", get(attachments::content))
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
        .route("/userinfo", get(profile::userinfo))
        .route("/api/profile", patch(profile::edit))
        .route("/api/profiles", get(profile::card))
        .route(
            "/api/avatar",
            put(profile::put_avatar).delete(profile::delete_avatar),
        )
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
        .route("/api/blocks", get(blocks::list).post(blocks::block))
        .route("/api/blocks/{actor_uri}", delete(blocks::unblock))
        .route("/api/privacy", patch(privacy::update))
        .route(
            "/api/dm",
            post(messaging::send_message).get(messaging::conversations),
        )
        .route("/api/dm/{conversation_id}", get(messaging::history))
        .route("/api/dm/{conversation_id}/read", post(messaging::mark_read))
        .route("/api/dm/{message_id}/edit", patch(messaging::edit))
        .route("/api/groups", post(groups::create))
        .route(
            "/api/groups/{conversation_id}",
            patch(groups::rename).delete(groups::dismiss),
        )
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
        .merge(if dev_routes {
            Router::new().route("/dev/send-test-email", post(sign_up::send_test_mail))
        } else {
            Router::new()
        })
        .with_state(state)
        .layer(cors)
        .layer(http::trace())
}
