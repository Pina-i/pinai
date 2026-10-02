//! The composition root: every adapter and use case built by hand, the HTTP server and the
//! background tasks, all stopped together.

use std::sync::Arc;
use std::time::Duration;

use application::messaging::{
    AddGroupMember, CreateGroup, DeliverDirectMessage, DismissGroup, EditMessage,
    ListConversations, ListGroupMembers, LoadHistory, MarkRead, OpenAttachment, ReadBlob,
    ReceiveEdit, ReceiveGroupChange, ReceiveMessage, RemoveGroupMember, RenameGroup,
    SendDirectMessage, SendGroupMessage, ServePeerContent, SetMemberRole, SweepOrphanAttachments,
    SweepStaleDeliveries, UploadAttachments,
};
use application::social::{
    AcceptFriendRequest, Block, DeclineFriendRequest, ListBlocks, ListFriends,
    ListIncomingRequests, ReceiveAccept, ReceiveFollow, ReceiveReject, ReceiveUndoFollow,
    SendFriendRequest, SetContactPolicy, Unblock, Unfriend,
};
use axum::Router;
use connections::Hub;
use federation_transport::{KeyCache, UrlPolicy};
use jwt_utils::load_ed_keypair_from_pem;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::configuration::{Config, DEV_SESSION_SECRET};
use crate::keys::SessionKeys;

/// How long open connections have to finish once the instance stops.
const DRAIN: Duration = Duration::from_secs(10);

pub struct Application {
    listener: TcpListener,
    router: Router,
    tasks: JoinSet<()>,
    stop: CancellationToken,
}

impl Application {
    /// Connects to Postgres, Redis and the object store, runs the migrations, builds every
    /// adapter and use case, and starts the background tasks. The caller binds `listener`, so
    /// that `config.domain` can name the port it got.
    pub async fn build(config: Config, listener: TcpListener) -> anyhow::Result<Self> {
        if config.session_secret == DEV_SESSION_SECRET {
            warn!("SESSION_SECRET is using the insecure dev default — set it in production");
        }
        let stop = CancellationToken::new();
        let mut tasks = JoinSet::new();

        // Connect to PostgreSQL
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(&config.database_url)
            .await
            .map_err(|e| anyhow::anyhow!("database connection failed: {e}"))?;
        info!("database connected");

        // Run migrations
        infrastructure::MIGRATOR
            .run(&pool)
            .await
            .map_err(|e| anyhow::anyhow!("migration failed: {e}"))?;
        info!("migrations applied");

        // Load Ed25519 signing keypair
        let keypair = load_ed_keypair_from_pem(&config.jwt_private_key_path, &config.jwt_key_id)
            .map_err(|e| anyhow::anyhow!("key loading failed: {e}"))?;
        info!(kid = %keypair.kid, "JWT signing key loaded");

        let keys = SessionKeys::from_secret(&config.session_secret);
        let cookie_key = keys.cookies.clone();

        // Initialize S3-compatible storage (optional — skipped if env vars not set)
        let storage = if config.storage_enabled() {
            use infrastructure::storage::{StorageClient, StorageConfig};

            let scfg = StorageConfig {
                endpoint: config.storage_endpoint.clone().unwrap(),
                access_key: config.storage_access_key.clone().unwrap(),
                secret_key: config.storage_secret_key.clone().unwrap(),
                bucket_avatars: config.storage_bucket_avatars.clone(),
                bucket_attachments: config.storage_bucket_attachments.clone(),
                public_url: config
                    .storage_public_url
                    .clone()
                    .unwrap_or_else(|| config.storage_endpoint.clone().unwrap()),
            };

            let client = StorageClient::new(&scfg)
                .await
                .map_err(|e| anyhow::anyhow!("storage init failed: {e}"))?;
            client
                .ensure_buckets()
                .await
                .map_err(|e| anyhow::anyhow!("bucket init failed: {e}"))?;
            info!("object storage connected");
            Some(client)
        } else {
            warn!("STORAGE_ENDPOINT not set — object storage disabled");
            None
        };

        // Connect to Redis (event broker)
        let broker = infrastructure::broker::RedisBroker::connect(&config.redis_url)
            .await
            .map_err(|e| anyhow::anyhow!("redis connection failed: {e}"))?;
        info!("redis broker connected");

        let hub = Arc::new(Hub::new());
        let keypair = Arc::new(keypair);
        let config = Arc::new(config);
        let broker_arc = Arc::new(broker);

        // Connects on the first send: the IdP boots even when the relay is not up yet.
        let mailer: Arc<dyn domain::auth::SignupMailer> = Arc::new(
            infrastructure::email::SmtpSignupMailer::new(infrastructure::email::SmtpSettings {
                host: config.smtp_host.clone(),
                port: config.smtp_port,
                username: config.smtp_username.clone(),
                password: config.smtp_password.clone(),
                from: config.smtp_from.clone(),
                starttls: config.smtp_starttls,
                issuer_host: config.domain.clone(),
            })
            .map_err(|e| anyhow::anyhow!("email sender init failed: {e}"))?,
        );
        info!(host = %config.smtp_host, port = config.smtp_port, "email sender ready");

        let email_otp_pepper = Arc::new(config.email_otp_pepper.clone());

        // An https issuer means production: peers must be https and must not resolve
        // into private address space. The alice/bob dev pair federates over
        // http://localhost, so a plain-http issuer relaxes both.
        let url_policy = UrlPolicy::from_issuer(&config.issuer());
        info!(
            require_https = url_policy.require_https,
            allow_private_networks = url_policy.allow_private_networks,
            "federation peer URL policy"
        );

        // Layer crates: adapters, then use cases, then the new API's state.
        let origin = domain::identity::InstanceOrigin::parse(&config.issuer())
            .map_err(|e| anyhow::anyhow!("the issuer is not a valid origin: {e}"))?;
        let settings_store: Arc<dyn domain::settings::SettingsStore> =
            Arc::new(infrastructure::postgres::PgSettingsStore::new(pool.clone()));
        let update_settings = Arc::new(application::settings::UpdateSettings::new(
            Arc::clone(&settings_store),
            Arc::new(infrastructure::realtime::HubSettingsNotifier::new(
                Arc::clone(&hub),
            )),
        ));

        let profiles: Arc<dyn domain::profile::Profiles> =
            Arc::new(infrastructure::postgres::PgProfiles::new(pool.clone()));
        let profile_audience: Arc<dyn domain::profile::ProfileAudience> = Arc::new(
            infrastructure::postgres::PgProfileAudience::new(pool.clone()),
        );
        let profile_notifier: Arc<dyn domain::profile::ProfileNotifier> = Arc::new(
            infrastructure::realtime::HubProfileNotifier::new(Arc::clone(&hub)),
        );
        let profile_federation: Arc<dyn domain::profile::ProfileFederation> = Arc::new(
            infrastructure::federation::ApProfileFederation::new(Arc::clone(&keypair), url_policy),
        );
        let avatars: Arc<dyn domain::profile::AvatarStore> =
            Arc::new(infrastructure::storage::S3AvatarStore::new(storage.clone()));
        let receive_profile_update = Arc::new(application::profile::ReceiveProfileUpdate::new(
            origin.clone(),
            Arc::new(infrastructure::postgres::PgPeerProfiles::new(pool.clone())),
            Arc::clone(&profile_audience),
            Arc::clone(&profile_notifier),
        ));

        let accounts: Arc<dyn domain::identity::Accounts> =
            Arc::new(infrastructure::postgres::PgAccounts::new(pool.clone()));
        let remote_actors: Arc<dyn domain::identity::RemoteActors> =
            Arc::new(infrastructure::federation::FederatedRemoteActors::new(
                pool.clone(),
                origin.scheme().to_owned(),
                url_policy,
            ));
        // One for both fan-outs, so an actor that couldn't be resolved is left alone by both.
        let inboxes = Arc::new(infrastructure::federation::Inboxes::new(
            origin.clone(),
            Arc::clone(&remote_actors),
        ));
        let graph: Arc<dyn domain::social::SocialGraph> =
            Arc::new(infrastructure::postgres::PgSocialGraph::new(pool.clone()));
        let reach: Arc<dyn domain::social::Reachability> =
            Arc::new(infrastructure::postgres::PgReachability::new(pool.clone()));
        let contact_policies: Arc<dyn domain::social::ContactPolicies> = Arc::new(
            infrastructure::postgres::PgContactPolicies::new(pool.clone()),
        );
        let social_notifier: Arc<dyn domain::social::SocialNotifier> = Arc::new(
            infrastructure::realtime::HubSocialNotifier::new(Arc::clone(&hub)),
        );
        let social_federation: Arc<dyn domain::social::SocialFederation> = Arc::new(
            infrastructure::federation::ApSocialFederation::new(Arc::clone(&keypair), url_policy),
        );
        let poll_targets = Arc::new(domain::presence::PollTargets::new(origin.clone()));
        let friend_presence: Arc<dyn domain::social::FriendPresence> = poll_targets.clone();

        let conversations: Arc<dyn domain::messaging::Conversations> =
            Arc::new(infrastructure::postgres::PgConversations::new(pool.clone()));
        let messages: Arc<dyn domain::messaging::Messages> =
            Arc::new(infrastructure::postgres::PgMessages::new(pool.clone()));
        let message_notifier: Arc<dyn domain::messaging::MessageNotifier> =
            Arc::new(infrastructure::realtime::HubMessageNotifier::new(
                Arc::clone(&hub),
                Arc::clone(&broker_arc),
            ));
        let group_notifier: Arc<dyn domain::messaging::GroupNotifier> = Arc::new(
            infrastructure::realtime::HubGroupNotifier::new(Arc::clone(&hub)),
        );
        let group_events: Arc<dyn domain::messaging::GroupEvents> =
            Arc::new(infrastructure::postgres::PgGroupEvents::new(pool.clone()));
        let group_federation: Arc<dyn domain::messaging::GroupFederation> =
            Arc::new(infrastructure::federation::ApGroupFederation::new(
                Arc::clone(&keypair),
                url_policy,
                Arc::clone(&inboxes),
            ));
        let message_federation: Arc<dyn domain::messaging::MessageFederation> =
            Arc::new(infrastructure::federation::ApMessageFederation::new(
                Arc::clone(&keypair),
                url_policy,
                Arc::clone(&inboxes),
                config.issuer(),
            ));
        let attachment_limits = domain::messaging::AttachmentLimits {
            max_files: config.attachment_max_files_per_message,
            max_bytes: i64::try_from(config.attachment_max_byte_size).unwrap_or(i64::MAX),
            blocked_mimes: config.attachment_blocked_mimes.clone(),
            blocked_extensions: config.attachment_blocked_extensions.clone(),
        };
        let send_direct_message = Arc::new(SendDirectMessage::new(
            origin.clone(),
            config.attachment_max_files_per_message,
            Arc::clone(&accounts),
            Arc::clone(&remote_actors),
            Arc::clone(&conversations),
            Arc::clone(&messages),
            Arc::clone(&reach),
            Arc::clone(&message_notifier),
        ));
        let deliver_direct_message = Arc::new(DeliverDirectMessage::new(
            Arc::clone(&message_federation),
            Arc::clone(&messages),
            Arc::clone(&message_notifier),
        ));
        let receive_message = Arc::new(ReceiveMessage::new(
            attachment_limits.clone(),
            Arc::clone(&accounts),
            Arc::clone(&remote_actors),
            Arc::clone(&conversations),
            Arc::clone(&messages),
            Arc::clone(&reach),
            Arc::clone(&message_notifier),
            Arc::clone(&group_notifier),
        ));
        let receive_edit = Arc::new(ReceiveEdit::new(
            Arc::clone(&conversations),
            Arc::clone(&messages),
            Arc::clone(&reach),
            Arc::clone(&message_notifier),
        ));
        let attachments: Arc<dyn domain::messaging::Attachments> =
            Arc::new(infrastructure::postgres::PgAttachments::new(pool.clone()));
        let objects: Arc<dyn domain::messaging::ObjectStore> =
            Arc::new(infrastructure::storage::S3ObjectStore::new(storage.clone()));
        let upload_attachments = Arc::new(UploadAttachments::new(
            attachment_limits.clone(),
            Arc::clone(&accounts),
            Arc::clone(&attachments),
            Arc::clone(&objects),
        ));
        let open_attachment = Arc::new(OpenAttachment::new(
            Arc::clone(&accounts),
            Arc::clone(&attachments),
            Arc::clone(&messages),
            Arc::clone(&conversations),
            Arc::new(infrastructure::blob_tokens::HmacBlobTokens::new(
                keys.attachment_links.clone(),
                config.attachment_url_ttl,
            )),
        ));
        let read_blob = Arc::new(ReadBlob::new(
            Arc::clone(&attachments),
            Arc::new(infrastructure::blob_tokens::HmacBlobTokens::new(
                keys.attachment_links.clone(),
                config.attachment_url_ttl,
            )),
            Arc::clone(&objects),
            Arc::new(infrastructure::federation::SignedRemoteFiles::new(
                Arc::clone(&keypair),
                config.issuer(),
                url_policy,
            )),
        ));
        let serve_peer_content = Arc::new(ServePeerContent::new(
            Arc::clone(&attachments),
            Arc::clone(&messages),
            Arc::clone(&conversations),
            Arc::clone(&objects),
        ));
        let sweep_orphan_attachments = Arc::new(SweepOrphanAttachments::new(
            time::Duration::try_from(config.attachment_orphan_ttl)
                .map_err(|e| anyhow::anyhow!("attachment orphan TTL: {e}"))?,
            Arc::clone(&attachments),
            Arc::clone(&objects),
        ));

        // The grace outlasts any delivery: the federation client gives up after 5 s.
        let sweep_stale_deliveries = Arc::new(SweepStaleDeliveries::new(
            time::Duration::minutes(5),
            Arc::clone(&accounts),
            Arc::clone(&messages),
            Arc::clone(&message_notifier),
        ));
        let tracker = Arc::new(domain::presence::ConnectionTracker::default());
        let board = Arc::new(domain::presence::PresenceBoard::default());
        let bus: Arc<dyn domain::presence::SignalBus> =
            Arc::new(infrastructure::presence::RedisSignalBus::new(
                Arc::clone(&broker_arc),
                config.domain.clone(),
            ));
        let presence_notifier: Arc<dyn domain::presence::PresenceNotifier> = Arc::new(
            infrastructure::realtime::HubPresenceNotifier::new(Arc::clone(&hub)),
        );
        let audience: Arc<dyn domain::presence::PresenceAudience> = Arc::new(
            infrastructure::postgres::PgPresenceAudience::new(pool.clone()),
        );
        let apply_presence = Arc::new(application::presence::ApplyPresence::new(
            Arc::clone(&board),
            Arc::clone(&audience),
            Arc::clone(&presence_notifier),
        ));
        let deliver_typing = Arc::new(application::presence::DeliverTyping::new(
            Arc::clone(&accounts),
            Arc::clone(&conversations),
            presence_notifier,
        ));
        let sweep_idle = Arc::new(application::presence::SweepIdle::new(
            Arc::clone(&tracker),
            Arc::clone(&board),
            Arc::clone(&bus),
        ));
        let poll_peers = Arc::new(application::presence::PollPeers::new(
            poll_targets,
            Arc::clone(&audience),
            Arc::new(infrastructure::federation::SignedPeerPresence::new(
                Arc::clone(&keypair),
                origin.clone(),
                url_policy,
            )),
            Arc::clone(&board),
            Arc::clone(&bus),
        ));
        let receive_peer_signal = Arc::new(application::presence::ReceivePeerSignal::new(
            Arc::clone(&bus),
        ));
        let (peer_streams, peer_signals) = infrastructure::federation::SsePeerStreams::new(
            Arc::clone(&keypair),
            origin.clone(),
            url_policy,
        );
        let archive: Arc<dyn domain::e2ee::HistoryArchive> = Arc::new(
            infrastructure::postgres::PgHistoryArchive::new(pool.clone()),
        );
        let commits: Arc<dyn domain::e2ee::CommitLog> =
            Arc::new(infrastructure::postgres::PgCommitLog::new(pool.clone()));
        let welcomes: Arc<dyn domain::e2ee::Welcomes> =
            Arc::new(infrastructure::postgres::PgWelcomes::new(pool.clone()));
        let mls_notifier: Arc<dyn domain::e2ee::MlsNotifier> = Arc::new(
            infrastructure::realtime::HubMlsNotifier::new(Arc::clone(&hub)),
        );
        let mls_federation: Arc<dyn domain::e2ee::MlsFederation> =
            Arc::new(infrastructure::federation::ApMlsFederation::new(
                Arc::clone(&keypair),
                url_policy,
                Arc::clone(&inboxes),
            ));
        let receive_commit = Arc::new(application::e2ee::ReceiveCommit::new(
            Arc::clone(&accounts),
            Arc::clone(&remote_actors),
            Arc::clone(&conversations),
            Arc::clone(&commits),
            Arc::clone(&reach),
            Arc::clone(&mls_notifier),
            Arc::clone(&group_notifier),
            Arc::clone(&group_events),
        ));
        let receive_welcome = Arc::new(application::e2ee::ReceiveWelcome::new(
            Arc::clone(&accounts),
            Arc::clone(&remote_actors),
            Arc::clone(&conversations),
            Arc::clone(&welcomes),
            Arc::clone(&reach),
            Arc::clone(&mls_notifier),
            Arc::clone(&group_notifier),
            Arc::clone(&group_events),
        ));
        let sweep_welcomes = Arc::new(application::e2ee::SweepWelcomes::new(Arc::clone(&welcomes)));
        let send_group_message = Arc::new(SendGroupMessage::new(
            config.attachment_max_files_per_message,
            Arc::clone(&accounts),
            Arc::clone(&conversations),
            Arc::clone(&messages),
            Arc::clone(&message_notifier),
            Arc::clone(&message_federation),
        ));
        let edit_message = Arc::new(EditMessage::new(
            Arc::clone(&accounts),
            Arc::clone(&conversations),
            Arc::clone(&messages),
            Arc::clone(&reach),
            Arc::clone(&message_notifier),
            Arc::clone(&message_federation),
        ));
        let load_history = Arc::new(LoadHistory::new(
            Arc::clone(&accounts),
            Arc::clone(&remote_actors),
            Arc::clone(&conversations),
            Arc::clone(&messages),
            Arc::clone(&group_events),
        ));
        let mark_read = Arc::new(MarkRead::new(
            Arc::clone(&accounts),
            Arc::clone(&conversations),
        ));
        let list_conversations = Arc::new(ListConversations::new(
            Arc::clone(&accounts),
            Arc::clone(&conversations),
        ));

        let key_cache = Arc::new(KeyCache::new(url_policy));
        let devices: Arc<dyn domain::e2ee::Devices> =
            Arc::new(infrastructure::postgres::PgDevices::new(pool.clone()));
        let key_packages: Arc<dyn domain::e2ee::KeyPackages> =
            Arc::new(infrastructure::postgres::PgKeyPackages::new(pool.clone()));
        let key_package_policy = domain::e2ee::KeyPackagePolicy {
            cap_per_device: config.e2ee_keypackage_cap_per_device,
            refill_threshold: config.e2ee_keypackage_refill_threshold,
            max_lifetime: time::Duration::try_from(config.e2ee_keypackage_lifetime)
                .map_err(|e| anyhow::anyhow!("KeyPackage lifetime: {e}"))?,
        };
        let device_notifier: Arc<dyn domain::e2ee::DeviceNotifier> = Arc::new(
            infrastructure::realtime::HubDeviceNotifier::new(Arc::clone(&hub)),
        );
        let sweep_key_packages = Arc::new(application::e2ee::SweepKeyPackages::new(Arc::clone(
            &key_packages,
        )));

        let clients: Arc<dyn domain::auth::Clients> =
            Arc::new(infrastructure::postgres::PgClients::new(pool.clone()));
        let sign_in_accounts: Arc<dyn domain::auth::SignInAccounts> = Arc::new(
            infrastructure::postgres::PgSignInAccounts::new(pool.clone()),
        );
        let authorization_codes: Arc<dyn domain::auth::AuthorizationCodes> = Arc::new(
            infrastructure::postgres::PgAuthorizationCodes::new(pool.clone()),
        );
        let jwks = serde_json::to_value(jwt_utils::JwkSet::from_keypairs(&[&keypair]))?;
        let hasher: Arc<dyn domain::auth::PasswordHasher> =
            Arc::new(infrastructure::auth::Argon2Hasher::new());
        let login_tickets: Arc<dyn domain::auth::LoginTickets> =
            Arc::new(infrastructure::postgres::PgLoginTickets::new(pool.clone()));
        let signup_codes: Arc<dyn domain::auth::SignupCodes> =
            Arc::new(infrastructure::postgres::PgSignupCodes::new(
                pool.clone(),
                Arc::clone(&email_otp_pepper),
            ));
        let second_factors: Arc<dyn domain::auth::SecondFactors> =
            Arc::new(infrastructure::postgres::PgSecondFactors::new(
                pool.clone(),
                Arc::clone(&email_otp_pepper),
            ));
        let authenticator: Arc<dyn domain::auth::Authenticator> =
            Arc::new(infrastructure::auth::TotpAuthenticator);
        let sign_ups: Arc<dyn domain::auth::SignUps> =
            Arc::new(infrastructure::postgres::PgSignUps::new(pool.clone()));
        let sweep_signups = Arc::new(application::auth::SweepSignups::new(
            Arc::clone(&signup_codes),
            login_tickets.clone(),
            sign_ups.clone(),
        ));

        let receive_follow = Arc::new(ReceiveFollow::new(
            Arc::clone(&accounts),
            Arc::clone(&remote_actors),
            Arc::clone(&graph),
            Arc::clone(&reach),
            Arc::clone(&social_notifier),
            Arc::clone(&social_federation),
        ));
        let receive_accept = Arc::new(ReceiveAccept::new(
            Arc::clone(&accounts),
            Arc::clone(&remote_actors),
            Arc::clone(&graph),
            Arc::clone(&social_notifier),
            Arc::clone(&friend_presence),
            Arc::clone(&profiles),
            Arc::clone(&profile_federation),
        ));
        let receive_reject = Arc::new(ReceiveReject::new(Arc::clone(&graph)));

        let receive_undo_follow = Arc::new(ReceiveUndoFollow::new(
            Arc::clone(&accounts),
            Arc::clone(&remote_actors),
            Arc::clone(&graph),
            Arc::clone(&social_notifier),
            Arc::clone(&friend_presence),
        ));

        let api_state = api::AppState {
            auth: Arc::new(infrastructure::auth::JwtTokenVerifier::new(
                Arc::clone(&keypair),
                config.issuer(),
            )),
            cookie_key: cookie_key.clone(),
            sign_in_pages: api::SignInPages {
                frontend_url: config.frontend_url.clone(),
                secure_cookies: config.secure_cookies(),
            },
            jwks: api::Jwks(Arc::new(jwks)),
            authorize: Arc::new(application::auth::Authorize::new(
                Arc::clone(&clients),
                Arc::clone(&sign_in_accounts),
                Arc::clone(&authorization_codes),
            )),
            log_in: Arc::new(application::auth::LogIn::new(
                Arc::clone(&clients),
                Arc::clone(&sign_in_accounts),
                Arc::clone(&hasher),
                Arc::clone(&authorization_codes),
                Arc::clone(&login_tickets),
                Arc::clone(&signup_codes),
                Arc::clone(&mailer),
            )),
            register: Arc::new(application::auth::Register::new(
                origin.clone(),
                Arc::clone(&clients),
                Arc::clone(&sign_in_accounts),
                Arc::clone(&sign_ups),
                Arc::clone(&hasher),
                Arc::new(infrastructure::auth::RandomSuffixes),
                Arc::clone(&signup_codes),
                Arc::clone(&mailer),
            )),
            verify_email: Arc::new(application::auth::VerifyEmail::new(
                Arc::clone(&clients),
                Arc::clone(&sign_in_accounts),
                Arc::clone(&signup_codes),
                Arc::clone(&authorization_codes),
            )),
            resend_code: Arc::new(application::auth::ResendCode::new(
                Arc::clone(&sign_in_accounts),
                Arc::clone(&signup_codes),
                Arc::clone(&mailer),
            )),
            send_test_mail: Arc::new(application::auth::SendTestMail::new(Arc::clone(&mailer))),
            dev_routes: config.environment.is_dev(),
            pass_second_factor: Arc::new(application::auth::PassSecondFactor::new(
                Arc::clone(&login_tickets),
                Arc::clone(&second_factors),
                Arc::clone(&authenticator),
                Arc::clone(&authorization_codes),
            )),
            start_totp_enrollment: Arc::new(application::auth::StartTotpEnrollment::new(
                origin.clone(),
                Arc::clone(&sign_in_accounts),
                Arc::clone(&second_factors),
                Arc::clone(&authenticator),
            )),
            confirm_totp_enrollment: Arc::new(application::auth::ConfirmTotpEnrollment::new(
                Arc::clone(&second_factors),
                Arc::clone(&authenticator),
            )),
            disable_totp: Arc::new(application::auth::DisableTotp::new(
                Arc::clone(&sign_in_accounts),
                Arc::clone(&second_factors),
                Arc::clone(&authenticator),
            )),
            regenerate_recovery_codes: Arc::new(application::auth::RegenerateRecoveryCodes::new(
                Arc::clone(&sign_in_accounts),
                Arc::clone(&second_factors),
                Arc::clone(&authenticator),
            )),
            exchange_code: Arc::new(application::auth::ExchangeCode::new(
                Arc::clone(&clients),
                authorization_codes,
                sign_in_accounts,
                Arc::new(infrastructure::auth::JwtTokenIssuer::new(
                    Arc::clone(&keypair),
                    config.issuer(),
                )),
            )),
            log_out: Arc::new(application::auth::LogOut::new(clients)),
            login_attempts: api::LoginAttempts::new(),
            origin: origin.clone(),
            cors_origins: config.cors_origins.clone(),
            public_key_pem: api::PublicKeyPem(Arc::from(keypair.public_key_pem.as_str())),
            find_account: Arc::new(application::identity::FindAccount::new(
                origin.clone(),
                Arc::clone(&accounts),
            )),
            show_person: Arc::new(application::profile::ShowPerson::new(
                origin.clone(),
                Arc::clone(&accounts),
                Arc::clone(&profiles),
            )),
            web_finger: Arc::new(application::identity::WebFinger::new(
                origin.clone(),
                Arc::clone(&accounts),
            )),
            search_accounts: Arc::new(application::identity::SearchAccounts::new(Arc::clone(
                &accounts,
            ))),
            receive_follow,
            receive_accept,
            receive_reject,
            receive_undo_follow,
            receive_message,
            receive_edit,
            receive_commit,
            receive_welcome,
            receive_profile_update,
            serve_peer_content,
            update_settings,
            read_userinfo: Arc::new(application::profile::ReadUserinfo::new(
                origin.clone(),
                Arc::clone(&profiles),
                Arc::clone(&settings_store),
                Arc::clone(&contact_policies),
            )),
            read_profile: Arc::new(application::profile::ReadProfile::new(
                Arc::clone(&accounts),
                Arc::new(infrastructure::postgres::PgProfileCards::new(pool.clone())),
                Arc::new(infrastructure::federation::BackgroundProfileRefresh::new(
                    Arc::clone(&remote_actors),
                )),
            )),
            edit_profile: Arc::new(application::profile::EditProfile::new(
                origin.clone(),
                Arc::clone(&profiles),
                settings_store,
                Arc::clone(&contact_policies),
                Arc::clone(&profile_audience),
                Arc::clone(&profile_notifier),
                Arc::clone(&profile_federation),
            )),
            set_avatar: Arc::new(application::profile::SetAvatar::new(
                Arc::clone(&profiles),
                Arc::clone(&avatars),
                Arc::clone(&profile_audience),
                Arc::clone(&profile_notifier),
                Arc::clone(&profile_federation),
            )),
            clear_avatar: Arc::new(application::profile::ClearAvatar::new(
                Arc::clone(&profiles),
                avatars,
                profile_audience,
                profile_notifier,
                Arc::clone(&profile_federation),
            )),
            send_friend_request: Arc::new(SendFriendRequest::new(
                Arc::clone(&accounts),
                Arc::clone(&remote_actors),
                Arc::clone(&graph),
                Arc::clone(&reach),
                Arc::clone(&social_notifier),
                Arc::clone(&social_federation),
            )),
            list_incoming_requests: Arc::new(ListIncomingRequests::new(
                Arc::clone(&accounts),
                Arc::clone(&remote_actors),
                Arc::clone(&graph),
            )),
            accept_friend_request: Arc::new(AcceptFriendRequest::new(
                Arc::clone(&accounts),
                Arc::clone(&remote_actors),
                Arc::clone(&graph),
                Arc::clone(&social_notifier),
                Arc::clone(&social_federation),
                Arc::clone(&friend_presence),
                profiles,
                profile_federation,
            )),
            decline_friend_request: Arc::new(DeclineFriendRequest::new(
                Arc::clone(&accounts),
                Arc::clone(&remote_actors),
                Arc::clone(&graph),
                Arc::clone(&social_federation),
            )),
            unfriend: Arc::new(Unfriend::new(
                Arc::clone(&accounts),
                Arc::clone(&remote_actors),
                Arc::clone(&graph),
                Arc::clone(&social_notifier),
                Arc::clone(&social_federation),
                Arc::clone(&friend_presence),
            )),
            list_friends: Arc::new(ListFriends::new(Arc::clone(&graph))),
            block: Arc::new(Block::new(
                Arc::clone(&accounts),
                Arc::clone(&remote_actors),
                Arc::clone(&graph),
                Arc::clone(&social_notifier),
                Arc::clone(&social_federation),
                Arc::clone(&friend_presence),
            )),
            unblock: Arc::new(Unblock::new(
                Arc::clone(&graph),
                Arc::clone(&social_notifier),
            )),
            list_blocks: Arc::new(ListBlocks::new(Arc::clone(&graph))),
            set_contact_policy: Arc::new(SetContactPolicy::new(Arc::clone(&contact_policies))),
            send_direct_message: Arc::clone(&send_direct_message),
            deliver_direct_message: Arc::clone(&deliver_direct_message),
            send_group_message,
            edit_message,
            load_history,
            mark_read,
            list_conversations,
            create_group: Arc::new(CreateGroup::new(
                origin.clone(),
                Arc::clone(&accounts),
                Arc::clone(&remote_actors),
                Arc::clone(&conversations),
                Arc::clone(&reach),
                Arc::clone(&group_notifier),
                Arc::clone(&group_events),
            )),
            list_group_members: Arc::new(ListGroupMembers::new(
                Arc::clone(&accounts),
                Arc::clone(&remote_actors),
                Arc::clone(&conversations),
            )),
            add_group_member: Arc::new(AddGroupMember::new(
                origin.clone(),
                Arc::clone(&accounts),
                Arc::clone(&remote_actors),
                Arc::clone(&conversations),
                Arc::clone(&reach),
                Arc::clone(&group_notifier),
                Arc::clone(&group_federation),
                Arc::clone(&group_events),
            )),
            remove_group_member: Arc::new(RemoveGroupMember::new(
                Arc::clone(&accounts),
                Arc::clone(&remote_actors),
                Arc::clone(&conversations),
                Arc::clone(&group_notifier),
                Arc::clone(&group_federation),
                Arc::clone(&group_events),
            )),
            dismiss_group: Arc::new(DismissGroup::new(
                Arc::clone(&accounts),
                Arc::clone(&conversations),
            )),
            receive_group_change: Arc::new(ReceiveGroupChange::new(
                Arc::clone(&accounts),
                Arc::clone(&remote_actors),
                Arc::clone(&conversations),
                Arc::clone(&group_notifier),
                Arc::clone(&group_events),
            )),
            rename_group: Arc::new(RenameGroup::new(
                Arc::clone(&accounts),
                Arc::clone(&remote_actors),
                Arc::clone(&conversations),
                Arc::clone(&group_notifier),
                Arc::clone(&group_federation),
                Arc::clone(&group_events),
            )),
            set_member_role: Arc::new(SetMemberRole::new(
                Arc::clone(&accounts),
                Arc::clone(&remote_actors),
                Arc::clone(&conversations),
                Arc::clone(&group_notifier),
                Arc::clone(&group_federation),
                Arc::clone(&group_events),
            )),
            attachment_limits: attachment_limits.clone(),
            upload_attachments,
            open_attachment,
            read_blob,
            signatures: Arc::new(infrastructure::federation::HttpSignatureVerifier::new(
                Arc::clone(&key_cache),
            )),
            register_device: Arc::new(application::e2ee::RegisterDevice::new(
                Arc::clone(&accounts),
                Arc::clone(&devices),
                Arc::new(infrastructure::attestation::Ed25519DeviceAttester::new(
                    Arc::clone(&keypair),
                )),
                Arc::clone(&device_notifier),
            )),
            list_devices: Arc::new(application::e2ee::ListDevices::new(Arc::clone(&devices))),
            revoke_device: Arc::new(application::e2ee::RevokeDevice::new(Arc::clone(&devices))),
            upload_key_packages: Arc::new(application::e2ee::UploadKeyPackages::new(
                key_package_policy,
                devices,
                Arc::clone(&key_packages),
            )),
            claim_key_package: Arc::new(application::e2ee::ClaimKeyPackage::new(
                origin.clone(),
                key_package_policy,
                Arc::clone(&accounts),
                Arc::clone(&key_packages),
                Arc::new(infrastructure::federation::SignedRemoteKeyPackages::new(
                    Arc::clone(&keypair),
                    url_policy,
                )),
                Arc::clone(&reach),
                device_notifier,
            )),
            key_package_status: Arc::new(application::e2ee::KeyPackageStatus::new(
                key_package_policy,
                key_packages,
            )),
            // A fresh requester can claim 60 at once, then one a second.
            claim_limiter: Arc::new(api::RateLimiter::new(60, 1.0)),
            append_commit: Arc::new(application::e2ee::AppendCommit::new(
                Arc::clone(&accounts),
                Arc::clone(&conversations),
                Arc::clone(&commits),
                Arc::clone(&mls_notifier),
                Arc::clone(&mls_federation),
            )),
            catch_up_commits: Arc::new(application::e2ee::CatchUpCommits::new(
                Arc::clone(&accounts),
                Arc::clone(&conversations),
                commits,
            )),
            claim_welcomes: Arc::new(application::e2ee::ClaimWelcomes::new(Arc::clone(&welcomes))),
            archive_messages: Arc::new(application::e2ee::ArchiveMessages::new(
                Arc::clone(&accounts),
                Arc::clone(&conversations),
                Arc::clone(&archive),
            )),
            read_archive: Arc::new(application::e2ee::ReadArchive::new(Arc::clone(&archive))),
            clear_archive: Arc::new(application::e2ee::ClearArchive::new(Arc::clone(&archive))),
            load_archive_salt: Arc::new(application::e2ee::LoadArchiveSalt::new(Arc::clone(
                &archive,
            ))),
            set_archive_salt: Arc::new(application::e2ee::SetArchiveSalt::new(archive)),
            hub: Arc::clone(&hub),
            missed_events: Arc::new(infrastructure::presence::BrokerMissedEvents::new(
                Arc::clone(&broker_arc),
            )),
            connect: Arc::new(application::presence::Connect::new(
                Arc::clone(&accounts),
                Arc::clone(&tracker),
                Arc::clone(&bus),
            )),
            disconnect: Arc::new(application::presence::Disconnect::new(
                Arc::clone(&tracker),
                Arc::clone(&bus),
            )),
            heartbeat: Arc::new(application::presence::Heartbeat::new(
                tracker,
                Arc::clone(&board),
                Arc::clone(&bus),
            )),
            set_presence: Arc::new(application::presence::SetPresence::new(Arc::clone(&bus))),
            start_typing: Arc::new(application::presence::StartTyping::new(
                Arc::clone(&conversations),
                bus,
            )),
            watch_conversation: Arc::new(application::presence::WatchConversation::new(
                origin.clone(),
                Arc::clone(&conversations),
                Arc::new(peer_streams),
            )),
            read_presence: Arc::new(application::presence::ReadPresence::new(
                Arc::clone(&accounts),
                Arc::clone(&board),
                Arc::clone(&audience),
            )),
            serve_peer_presence: Arc::new(application::presence::ServePeerPresence::new(
                origin.clone(),
                Arc::clone(&board),
                Arc::clone(&audience),
            )),
            // Each peer's stream listens on the bus through its own subscription.
            open_peer_stream: Arc::new(application::presence::OpenPeerStream::new(
                origin.clone(),
                board,
                audience,
                Arc::new(infrastructure::presence::RedisSignalFeed::new(
                    config.redis_url.clone(),
                    config.domain.clone(),
                )),
            )),
            // One `typing_start` a second an account.
            typing_limiter: Arc::new(api::RateLimiter::new(1, 1.0)),
            shutdown: stop.clone(),
            send_welcome: Arc::new(application::e2ee::SendWelcome::new(
                origin.clone(),
                Arc::clone(&accounts),
                Arc::clone(&remote_actors),
                Arc::clone(&conversations),
                welcomes,
                Arc::clone(&reach),
                mls_notifier,
                mls_federation,
            )),
        };

        // The presence bus, to the accounts that hear of it; idle connections, every minute.
        let signals = infrastructure::presence::signals(&config.redis_url, &config.domain).await?;
        tasks.spawn(api::background::relay_signals(
            signals,
            apply_presence,
            deliver_typing,
            stop.clone(),
        ));
        tasks.spawn(api::background::sweep_idle_connections(
            sweep_idle,
            stop.clone(),
        ));

        // Other instances' presence: polled for friends lists, streamed for open conversations.
        tasks.spawn(api::background::poll_peers(poll_peers, stop.clone()));
        tasks.spawn(api::background::relay_peer_signals(
            peer_signals,
            receive_peer_signal,
            stop.clone(),
        ));

        info!("presence system started");

        // Fail the remote DMs a crash left `pending`.
        tasks.spawn(api::background::sweep_stale_deliveries(
            sweep_stale_deliveries,
            stop.clone(),
        ));

        // Spent signup codes and login tickets, and the accounts never confirmed.
        tasks.spawn(api::background::sweep_signups(sweep_signups, stop.clone()));

        // Reap MLS KeyPackages and Welcomes past their use.
        tasks.spawn(api::background::sweep_key_packages(
            sweep_key_packages,
            stop.clone(),
        ));
        tasks.spawn(api::background::sweep_welcomes(
            sweep_welcomes,
            stop.clone(),
        ));
        // Reap uploads never sent.
        tasks.spawn(api::background::sweep_orphan_attachments(
            sweep_orphan_attachments,
            stop.clone(),
        ));

        Ok(Self {
            listener,
            router: api::router(api_state),
            tasks,
            stop,
        })
    }

    pub fn port(&self) -> u16 {
        self.listener
            .local_addr()
            .map(|addr| addr.port())
            .unwrap_or_default()
    }

    /// Cancelled, it stops the instance: no new connection, the open requests answered, the
    /// long-lived connections told to go, the background tasks ended.
    pub fn stop_token(&self) -> CancellationToken {
        self.stop.clone()
    }

    pub async fn run_until_stopped(self) -> anyhow::Result<()> {
        let Self {
            listener,
            router,
            mut tasks,
            stop,
        } = self;
        let serving = axum::serve(listener, router)
            .with_graceful_shutdown(stop.clone().cancelled_owned())
            .into_future();
        let drained = async {
            stop.cancelled().await;
            tokio::time::sleep(DRAIN).await;
        };
        tokio::select! {
            served = serving => served?,
            () = drained => warn!("connections still open after the drain, dropped"),
        }
        stop.cancel();
        while let Some(task) = tasks.join_next().await {
            if let Err(e) = task {
                tracing::error!(error = ?e, "a background task failed");
            }
        }
        info!("stopped");
        Ok(())
    }
}
