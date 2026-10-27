//! The router over the real use cases and in-memory fakes, for route tests.

use std::sync::Arc;

use application::auth::{
    Authenticate, Authorize, CompleteSignIn, ConfirmTotpEnrollment, CreateInvitation, DisableTotp,
    ExchangeCode, IssuePasswordReset, LinkDevice, ListInvitations, ListMembers, LogIn, LogOut,
    PassSecondFactor, Refresh, RegenerateRecoveryCodes, Register, RegisterInvited, ResendCode,
    ResetPassword, RevokeInvitation, RevokeToken, SendTestMail, ShowSignIn, SignOutOthers,
    StartTotpEnrollment, VerifyEmail,
};
use application::e2ee::{
    AppendCommit, ArchiveMessages, CatchUpCommits, ClaimKeyPackage, ClaimWelcomes, ClearArchive,
    KeyPackageStatus, ListDevices, LoadArchiveSalt, ReadArchive, ReceiveCommit, ReceiveWelcome,
    RegisterDevice, RevokeDevice, SendWelcome, SetArchiveSalt, UploadKeyPackages,
};
use application::identity::{DescribeInstance, FindAccount, SearchAccounts, WebFinger};
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
    ClearAvatar, EditProfile, ReadUserinfo, ReceiveProfileUpdate, SetAvatar,
};
use application::settings::UpdateSettings;
use application::social::{
    AcceptFriendRequest, Block, DeclineFriendRequest, ListBlocks, ListFriends,
    ListIncomingRequests, ReceiveAccept, ReceiveFollow, ReceiveReject, ReceiveUndoFollow,
    SendFriendRequest, SetContactPolicy, Unblock, Unfriend,
};
use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::Key;
use domain::UserId;
use domain::auth::testing::{
    CountingSuffixes, InMemoryClientSignIns, InMemoryClients, InMemoryCodes,
    InMemoryInstanceMembers, InMemoryPasswordResets, InMemoryRefreshTokens, InMemorySecondFactors,
    InMemorySessions, InMemorySignInAccounts, InMemorySignupCodes, PlainHasher, RecordingMailer,
    RecordingSessionNotifier, RecordingTickets, SpelledTokens, StepAuthenticator, web_client,
};
use domain::auth::{Registrations, WebApp};
use domain::e2ee::KeyPackagePolicy;
use domain::e2ee::testing::{
    InMemoryArchive, InMemoryDelivery, InMemoryKeyDirectory, InMemoryRemoteKeyPackages,
    PlainAttester, RecordingDeviceNotifier, RecordingMlsFederation, RecordingMlsNotifier,
};
use domain::identity::testing::{
    InMemoryAccounts, InMemoryRemoteActors, InMemoryTokens, TrustedSignatures,
};
use domain::identity::{
    Account, Accounts, ActorUri, InstanceIntro, InstanceOrigin, RemoteActor, RemoteActors,
};
use domain::messaging::AttachmentLimits;
use domain::messaging::testing::{
    InMemoryMessaging, InMemoryObjects, InMemoryRemoteFiles, PlainBlobTokens,
    RecordingGroupFederation, RecordingGroupNotifier, RecordingMessageFederation,
    RecordingMessageNotifier,
};
use domain::presence::testing::{
    InMemoryAudience, InMemoryMissedEvents, QueuedFeed, RecordingBus, RecordingPeerStreams,
};
use domain::presence::{ConnectionTracker, PresenceBoard};
use domain::profile::testing::{
    InMemoryAvatars, InMemoryProfiles, RecordingProfileFederation, RecordingProfileNotifier,
    RecordingProfileRefresh,
};
use domain::settings::testing::{InMemorySettingsStore, RecordingSettingsNotifier};
use domain::social::testing::{
    InMemoryContactPolicies, InMemorySocialGraph, RecordingFriendPresence,
    RecordingSocialFederation, RecordingSocialNotifier, StubReachability,
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use crate::{AppState, Jwks, PublicKeyPem, RateLimiter, SignInPages, router};

/// A sign-in page's headers: never cached, under the strict CSP, and sending its `Referer` as
/// `referrer_policy` says.
pub fn assert_page(response: &Response, referrer_policy: &str) {
    let headers = response.headers();
    assert_eq!(headers[header::REFERRER_POLICY], referrer_policy);
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert!(
        headers[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .starts_with("default-src 'none'; script-src 'self'"),
        "{headers:?}"
    );
}

/// Behind the sign-in routes, for tests to seed and look at.
pub struct SignInFakes {
    pub accounts: Arc<InMemorySignInAccounts>,
    pub codes: Arc<InMemoryCodes>,
    pub tickets: Arc<RecordingTickets>,
    pub signup_codes: Arc<InMemorySignupCodes>,
    pub mailer: Arc<RecordingMailer>,
    pub factors: Arc<InMemorySecondFactors>,
    pub sign_ins: Arc<InMemoryClientSignIns>,
    pub sessions: Arc<InMemorySessions>,
    pub ended: Arc<RecordingSessionNotifier>,
    pub refresh_tokens: Arc<InMemoryRefreshTokens>,
    pub resets: Arc<InMemoryPasswordResets>,
}

/// Behind the profile routes: accounts' profiles, their friends and avatars.
pub struct ProfileFakes {
    pub profiles: Arc<InMemoryProfiles>,
    pub avatars: Arc<InMemoryAvatars>,
    pub notifier: Arc<RecordingProfileNotifier>,
    pub federation: Arc<RecordingProfileFederation>,
    pub refresh: Arc<RecordingProfileRefresh>,
}

/// Behind the inbox: what peers' activities change here.
pub struct PeerFakes {
    pub graph: Arc<InMemorySocialGraph>,
    pub message_notifier: Arc<RecordingMessageNotifier>,
}

/// The web client of a development checkout, standing in for the official web app.
fn web_app() -> WebApp {
    WebApp::parse("http://localhost:5173").unwrap()
}

/// What the actor documents publish as the instance key.
pub const PUBLIC_KEY_PEM: &str =
    "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAtest\n-----END PUBLIC KEY-----\n";

pub struct TestApp {
    router: Router,
    tokens: Arc<InMemoryTokens>,
    /// Cancelling it stops the instance.
    pub shutdown: tokio_util::sync::CancellationToken,
    pub sign_in: SignInFakes,
    pub profile: ProfileFakes,
    pub peers: PeerFakes,
    /// Open to every pair until a test says otherwise.
    pub reach: Arc<StubReachability>,
    /// The presence states the instance has heard.
    pub board: Arc<PresenceBoard>,
}

impl TestApp {
    /// An instance on `http://localhost:8080`, like `domain::identity::testing::account`'s.
    pub fn with(
        accounts: impl IntoIterator<Item = Account>,
        remote: impl IntoIterator<Item = RemoteActor>,
    ) -> Self {
        Self::knowing(accounts, InMemoryRemoteActors::with(remote))
    }

    /// The same, with other instances as `remote_actors` has them — some down, say.
    pub fn knowing(
        accounts: impl IntoIterator<Item = Account>,
        remote_actors: InMemoryRemoteActors,
    ) -> Self {
        Self::built(
            accounts,
            remote_actors,
            Some(web_app()),
            Registrations::Open,
        )
    }

    /// An instance that knows of no official web app: joining by invitation ends on a page.
    pub fn without_web_app() -> Self {
        Self::built(
            [],
            InMemoryRemoteActors::default(),
            None,
            Registrations::Open,
        )
    }

    /// An instance where only the invited sign up.
    pub fn invite_only() -> Self {
        Self::built(
            [],
            InMemoryRemoteActors::default(),
            Some(web_app()),
            Registrations::Invite,
        )
    }

    fn built(
        accounts: impl IntoIterator<Item = Account>,
        remote_actors: InMemoryRemoteActors,
        web_app: Option<WebApp>,
        registrations: Registrations,
    ) -> Self {
        let accounts: Arc<dyn Accounts> = Arc::new(InMemoryAccounts::with(accounts));
        let remote_actors: Arc<dyn RemoteActors> = Arc::new(remote_actors);
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
        let group_federation = Arc::new(RecordingGroupFederation::default());
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
        let device_notifier = Arc::new(RecordingDeviceNotifier::default());
        let mls_federation = Arc::new(RecordingMlsFederation::default());
        let key_policy = KeyPackagePolicy {
            cap_per_device: 100,
            refill_threshold: 20,
            max_lifetime: time::Duration::days(30),
        };
        let sign_in_accounts = Arc::new(InMemorySignInAccounts::default());
        let sign_in_sessions = Arc::new(InMemorySessions::default());
        let sign_in_tickets = Arc::new(RecordingTickets::default());
        let authenticator = Arc::new(StepAuthenticator::default());
        let sign_in = SignInFakes {
            resets: Arc::new(InMemoryPasswordResets::over(
                sign_in_accounts.clone(),
                sign_in_sessions.clone(),
                sign_in_tickets.clone(),
            )),
            signup_codes: Arc::new(InMemorySignupCodes::confirming(sign_in_accounts.clone())),
            factors: Arc::new(InMemorySecondFactors::for_accounts(
                sign_in_accounts.clone(),
            )),
            accounts: sign_in_accounts,
            codes: Arc::new(InMemoryCodes::default()),
            tickets: sign_in_tickets,
            mailer: Arc::new(RecordingMailer::default()),
            sign_ins: Arc::new(InMemoryClientSignIns::default()),
            sessions: sign_in_sessions,
            ended: Arc::new(RecordingSessionNotifier::default()),
            refresh_tokens: Arc::new(InMemoryRefreshTokens::default()),
        };
        let complete = Arc::new(CompleteSignIn::new(
            sign_in.sign_ins.clone(),
            sign_in.codes.clone(),
            sign_in.sessions.clone(),
            sign_in.ended.clone(),
        ));
        let clients = Arc::new(InMemoryClients::with([
            web_client(),
            domain::auth::desktop_client(&origin),
        ]));
        let shutdown = tokio_util::sync::CancellationToken::new();
        let reach = Arc::new(StubReachability::default());
        let contact_policies = Arc::new(InMemoryContactPolicies::default());
        let peers = PeerFakes {
            graph: graph.clone(),
            message_notifier: message_notifier.clone(),
        };
        let settings = Arc::new(InMemorySettingsStore::default());
        let profile = ProfileFakes {
            profiles: Arc::new(InMemoryProfiles::default()),
            avatars: Arc::new(InMemoryAvatars::default()),
            notifier: Arc::new(RecordingProfileNotifier::default()),
            federation: Arc::new(RecordingProfileFederation::default()),
            refresh: Arc::new(RecordingProfileRefresh::default()),
        };
        let describe_instance = Arc::new(DescribeInstance::new(
            InstanceIntro::new(&origin, Some("Aotearoa"), Some("Design and type people.")).unwrap(),
            registrations,
            accounts.clone(),
        ));
        let state = AppState {
            authenticate: Arc::new(Authenticate::new(tokens.clone(), sign_in.sessions.clone())),
            cookie_key: Key::from(&[7u8; 64]),
            sign_in_pages: SignInPages::new(
                describe_instance.clone(),
                Arc::new(ShowSignIn::new(
                    clients.clone(),
                    sign_in.tickets.clone(),
                    sign_in.accounts.clone(),
                    sign_in.resets.clone(),
                )),
                origin.clone(),
                false,
            ),
            jwks: Jwks(Arc::new(
                serde_json::json!({ "keys": [{ "kid": "test-key" }] }),
            )),
            authorize: Arc::new(Authorize::new(
                clients.clone(),
                sign_in.accounts.clone(),
                sign_in.codes.clone(),
                sign_in.sign_ins.clone(),
                sign_in.sessions.clone(),
            )),
            log_in: Arc::new(LogIn::new(
                clients.clone(),
                sign_in.accounts.clone(),
                Arc::new(PlainHasher::default()),
                sign_in.tickets.clone(),
                sign_in.signup_codes.clone(),
                sign_in.mailer.clone(),
                complete.clone(),
            )),
            exchange_code: Arc::new(ExchangeCode::new(
                clients.clone(),
                sign_in.codes.clone(),
                sign_in.accounts.clone(),
                Arc::new(SpelledTokens),
                sign_in.sessions.clone(),
                sign_in.refresh_tokens.clone(),
            )),
            revoke_token: Arc::new(RevokeToken::new(
                sign_in.refresh_tokens.clone(),
                sign_in.sessions.clone(),
                sign_in.ended.clone(),
            )),
            refresh: Arc::new(Refresh::new(
                sign_in.refresh_tokens.clone(),
                sign_in.sessions.clone(),
                sign_in.ended.clone(),
                sign_in.accounts.clone(),
                Arc::new(SpelledTokens),
            )),
            log_out: Arc::new(LogOut::new(
                clients.clone(),
                sign_in.sessions.clone(),
                sign_in.ended.clone(),
            )),
            link_device: Arc::new(LinkDevice::new(
                keys.clone(),
                sign_in.sessions.clone(),
                sign_in.ended.clone(),
            )),
            sign_out_others: Arc::new(SignOutOthers::new(
                sign_in.sessions.clone(),
                sign_in.ended.clone(),
            )),
            login_attempts: crate::LoginAttempts::new(),
            register: Arc::new(Register::new(
                origin.clone(),
                registrations,
                clients.clone(),
                sign_in.accounts.clone(),
                sign_in.accounts.clone(),
                Arc::new(PlainHasher::default()),
                Arc::new(CountingSuffixes::default()),
                sign_in.signup_codes.clone(),
                sign_in.mailer.clone(),
            )),
            register_invited: Arc::new(RegisterInvited::new(
                origin.clone(),
                registrations,
                web_app.clone(),
                sign_in.accounts.clone(),
                sign_in.accounts.clone(),
                sign_in.accounts.clone(),
                Arc::new(PlainHasher::default()),
                Arc::new(CountingSuffixes::default()),
                complete.clone(),
            )),
            create_invitation: Arc::new(CreateInvitation::new(
                registrations,
                sign_in.accounts.clone(),
                sign_in.accounts.clone(),
            )),
            list_invitations: Arc::new(ListInvitations::new(
                sign_in.accounts.clone(),
                sign_in.accounts.clone(),
            )),
            revoke_invitation: Arc::new(RevokeInvitation::new(
                sign_in.accounts.clone(),
                sign_in.accounts.clone(),
            )),
            list_members: Arc::new(ListMembers::new(
                sign_in.accounts.clone(),
                Arc::new(InMemoryInstanceMembers::over(
                    sign_in.accounts.clone(),
                    sign_in.sessions.clone(),
                )),
                board.clone(),
            )),
            issue_password_reset: Arc::new(IssuePasswordReset::new(
                sign_in.accounts.clone(),
                sign_in.resets.clone(),
            )),
            reset_password: Arc::new(ResetPassword::new(
                origin.clone(),
                web_app,
                Arc::new(PlainHasher::default()),
                sign_in.resets.clone(),
                sign_in.ended.clone(),
            )),
            verify_email: Arc::new(VerifyEmail::new(
                clients.clone(),
                sign_in.accounts.clone(),
                sign_in.signup_codes.clone(),
                complete.clone(),
            )),
            resend_code: Arc::new(ResendCode::new(
                sign_in.accounts.clone(),
                sign_in.signup_codes.clone(),
                sign_in.mailer.clone(),
            )),
            send_test_mail: Arc::new(SendTestMail::new(sign_in.mailer.clone())),
            dev_routes: true,
            pass_second_factor: Arc::new(PassSecondFactor::new(
                sign_in.tickets.clone(),
                sign_in.factors.clone(),
                authenticator.clone(),
                complete,
            )),
            start_totp_enrollment: Arc::new(StartTotpEnrollment::new(
                origin.clone(),
                sign_in.accounts.clone(),
                sign_in.factors.clone(),
                authenticator.clone(),
            )),
            confirm_totp_enrollment: Arc::new(ConfirmTotpEnrollment::new(
                sign_in.factors.clone(),
                authenticator.clone(),
            )),
            disable_totp: Arc::new(DisableTotp::new(
                sign_in.accounts.clone(),
                sign_in.factors.clone(),
                authenticator.clone(),
            )),
            regenerate_recovery_codes: Arc::new(RegenerateRecoveryCodes::new(
                sign_in.accounts.clone(),
                sign_in.factors.clone(),
                authenticator,
            )),
            signatures: Arc::new(TrustedSignatures),
            origin: origin.clone(),
            describe_instance,
            public_key_pem: PublicKeyPem(Arc::from(PUBLIC_KEY_PEM)),
            find_account: Arc::new(FindAccount::new(origin.clone(), accounts.clone())),
            show_person: Arc::new(application::profile::ShowPerson::new(
                origin.clone(),
                accounts.clone(),
                profile.profiles.clone(),
            )),
            web_finger: Arc::new(WebFinger::new(origin.clone(), accounts.clone())),
            search_accounts: Arc::new(SearchAccounts::new(accounts.clone())),
            receive_follow: Arc::new(ReceiveFollow::new(
                accounts.clone(),
                remote_actors.clone(),
                graph.clone(),
                reach.clone(),
                notifier.clone(),
                federation.clone(),
            )),
            receive_accept: Arc::new(ReceiveAccept::new(
                accounts.clone(),
                remote_actors.clone(),
                graph.clone(),
                notifier.clone(),
                presence.clone(),
                profile.profiles.clone(),
                profile.federation.clone(),
            )),
            receive_reject: Arc::new(ReceiveReject::new(graph.clone())),
            receive_undo_follow: Arc::new(ReceiveUndoFollow::new(
                accounts.clone(),
                remote_actors.clone(),
                graph.clone(),
                notifier.clone(),
                presence.clone(),
            )),
            receive_message: Arc::new(ReceiveMessage::new(
                limits.clone(),
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                store.clone(),
                reach.clone(),
                message_notifier.clone(),
                group_notifier.clone(),
            )),
            receive_edit: Arc::new(ReceiveEdit::new(
                store.clone(),
                store.clone(),
                reach.clone(),
                message_notifier.clone(),
            )),
            receive_commit: Arc::new(ReceiveCommit::new(
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                delivery.clone(),
                reach.clone(),
                mls_notifier.clone(),
                group_notifier.clone(),
                store.clone(),
            )),
            receive_welcome: Arc::new(ReceiveWelcome::new(
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                delivery.clone(),
                reach.clone(),
                mls_notifier.clone(),
                group_notifier.clone(),
                store.clone(),
            )),
            receive_profile_update: Arc::new(ReceiveProfileUpdate::new(
                origin.clone(),
                profile.profiles.clone(),
                profile.profiles.clone(),
                profile.notifier.clone(),
            )),
            serve_peer_content: Arc::new(ServePeerContent::new(
                store.clone(),
                store.clone(),
                store.clone(),
                objects.clone(),
            )),
            update_settings: Arc::new(UpdateSettings::new(
                settings.clone(),
                Arc::new(RecordingSettingsNotifier::default()),
            )),
            read_userinfo: Arc::new(ReadUserinfo::new(
                origin.clone(),
                profile.profiles.clone(),
                settings.clone(),
                contact_policies.clone(),
            )),
            read_profile: Arc::new(application::profile::ReadProfile::new(
                accounts.clone(),
                profile.profiles.clone(),
                profile.refresh.clone(),
            )),
            edit_profile: Arc::new(EditProfile::new(
                origin.clone(),
                profile.profiles.clone(),
                settings,
                contact_policies.clone(),
                profile.profiles.clone(),
                profile.notifier.clone(),
                profile.federation.clone(),
            )),
            set_avatar: Arc::new(SetAvatar::new(
                profile.profiles.clone(),
                profile.avatars.clone(),
                profile.profiles.clone(),
                profile.notifier.clone(),
                profile.federation.clone(),
            )),
            clear_avatar: Arc::new(ClearAvatar::new(
                profile.profiles.clone(),
                profile.avatars.clone(),
                profile.profiles.clone(),
                profile.notifier.clone(),
                profile.federation.clone(),
            )),
            send_friend_request: Arc::new(SendFriendRequest::new(
                accounts.clone(),
                remote_actors.clone(),
                graph.clone(),
                reach.clone(),
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
                profile.profiles.clone(),
                profile.federation.clone(),
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
                notifier.clone(),
                federation.clone(),
                presence.clone(),
            )),
            list_friends: Arc::new(ListFriends::new(graph.clone())),
            block: Arc::new(Block::new(
                accounts.clone(),
                remote_actors.clone(),
                graph.clone(),
                notifier.clone(),
                federation,
                presence,
            )),
            unblock: Arc::new(Unblock::new(graph.clone(), notifier)),
            list_blocks: Arc::new(ListBlocks::new(graph.clone())),
            set_contact_policy: Arc::new(SetContactPolicy::new(contact_policies.clone())),
            send_direct_message: Arc::new(SendDirectMessage::new(
                origin.clone(),
                5,
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                store.clone(),
                reach.clone(),
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
                store.clone(),
                store.clone(),
                message_notifier.clone(),
                message_federation.clone(),
            )),
            edit_message: Arc::new(EditMessage::new(
                accounts.clone(),
                store.clone(),
                store.clone(),
                reach.clone(),
                message_notifier.clone(),
                message_federation,
            )),
            load_history: Arc::new(LoadHistory::new(
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                store.clone(),
                store.clone(),
            )),
            mark_read: Arc::new(MarkRead::new(accounts.clone(), store.clone())),
            list_conversations: Arc::new(ListConversations::new(accounts.clone(), store.clone())),
            create_group: Arc::new(CreateGroup::new(
                origin.clone(),
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                reach.clone(),
                group_notifier.clone(),
                store.clone(),
            )),
            list_group_members: Arc::new(ListGroupMembers::new(
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
            )),
            add_group_member: Arc::new(AddGroupMember::new(
                origin.clone(),
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                reach.clone(),
                group_notifier.clone(),
                group_federation.clone(),
                store.clone(),
            )),
            remove_group_member: Arc::new(RemoveGroupMember::new(
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                group_notifier.clone(),
                group_federation.clone(),
                store.clone(),
            )),
            dismiss_group: Arc::new(DismissGroup::new(accounts.clone(), store.clone())),
            receive_group_change: Arc::new(ReceiveGroupChange::new(
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                reach.clone(),
                group_notifier.clone(),
                store.clone(),
            )),
            rename_group: Arc::new(RenameGroup::new(
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                group_notifier.clone(),
                group_federation.clone(),
                store.clone(),
            )),
            set_member_role: Arc::new(SetMemberRole::new(
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                group_notifier,
                group_federation,
                store.clone(),
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
                device_notifier.clone(),
            )),
            list_devices: Arc::new(ListDevices::new(keys.clone(), sign_in.sessions.clone())),
            revoke_device: Arc::new(RevokeDevice::new(
                keys.clone(),
                sign_in.sessions.clone(),
                sign_in.ended.clone(),
            )),
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
                reach.clone(),
                device_notifier,
            )),
            key_package_status: Arc::new(KeyPackageStatus::new(key_policy, keys)),
            claim_limiter: Arc::new(RateLimiter::new(60, 1.0)),
            append_commit: Arc::new(AppendCommit::new(
                accounts.clone(),
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
            hub: Arc::new(connections::Hub::new()),
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
                board.clone(),
                audience,
                Arc::new(QueuedFeed::held_open()),
            )),
            typing_limiter: Arc::new(RateLimiter::new(1, 1.0)),
            shutdown: shutdown.clone(),
            send_welcome: Arc::new(SendWelcome::new(
                origin.clone(),
                accounts.clone(),
                remote_actors.clone(),
                store.clone(),
                delivery,
                reach.clone(),
                mls_notifier,
                mls_federation,
            )),
        };
        Self {
            router: router(state),
            tokens,
            shutdown,
            sign_in,
            profile,
            peers,
            reach,
            board,
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
            let token = self.token(user);
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

    /// A bearer token belonging to `session`.
    pub fn token_in(&self, user: UserId, session: domain::SessionId) -> String {
        self.tokens.issue(user, session)
    }

    /// A bearer token for `user`, for requests built by hand: a live session's.
    pub fn token(&self, user: UserId) -> String {
        let session = self.sign_in.sessions.live(user);
        self.tokens.issue(user, session)
    }

    /// The same, the password typed on that session at `at`.
    pub fn token_signed_in_at(&self, user: UserId, at: time::OffsetDateTime) -> String {
        let session = self.sign_in.sessions.live(user);
        self.tokens.issue_signed_in_at(user, session, at)
    }

    /// A request another instance signed, as `peer`, with the `Digest` of its body.
    pub async fn call_as_peer(
        &self,
        method: Method,
        uri: &str,
        peer: &ActorUri,
        body: Value,
    ) -> (StatusCode, Value) {
        let body = body.to_string();
        self.send(Self::signed(
            method,
            uri,
            peer,
            &body,
            &TrustedSignatures::digest(body.as_bytes()),
        ))
        .await
    }

    /// A request `peer` signed over `digest`, whatever `body` is.
    pub fn signed(
        method: Method,
        uri: &str,
        peer: &ActorUri,
        body: &str,
        digest: &str,
    ) -> Request<Body> {
        let (name, value) = TrustedSignatures::header(peer);
        Request::builder()
            .method(method)
            .uri(uri)
            .header(name, value)
            .header("digest", digest)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap()
    }

    pub async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        Self::body_of(self.respond(request).await).await
    }

    /// The response as it is, headers and all.
    pub async fn respond(&self, request: Request<Body>) -> axum::response::Response {
        self.router.clone().oneshot(request).await.unwrap()
    }

    /// A page's status and its HTML.
    pub async fn html_of(response: impl IntoResponse) -> (StatusCode, String) {
        let response = response.into_response();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
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
