use std::sync::Arc;

use application::messaging::{
    AddGroupMember, CreateGroup, DeliverDirectMessage, EditMessage, ListConversations,
    ListGroupMembers, LoadHistory, MarkRead, OpenAttachment, ReadBlob, ReceiveEdit, ReceiveMessage,
    RemoveGroupMember, RenameGroup, SendDirectMessage, SendGroupMessage, ServePeerContent,
    SetMemberRole, SweepOrphanAttachments, SweepStaleDeliveries, UploadAttachments,
};
use application::social::{
    AcceptFriendRequest, DeclineFriendRequest, ListFriends, ListIncomingRequests, ReceiveAccept,
    ReceiveFollow, ReceiveReject, ReceiveUndoFollow, SendFriendRequest, Unfriend,
};
use axum_extra::extract::cookie::Key;
use sqlx::postgres::PgPoolOptions;
use tracing::{info, warn};

use federation_transport::{KeyCache, UrlPolicy};
use idp_config::{Config, DEV_SESSION_SECRET};
use idp_email::{EmailConfig, EmailSender, LettreSmtpSender};
use idp_realtime::WsHub;
use idp_state::AppState;
use jwt_utils::load_ed_keypair_from_pem;

mod router;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file if present (ignored in production where env vars are set directly)
    dotenvy::dotenv().ok();

    // Initialize tracing — RUST_LOG controls level, LOG_FORMAT=json for production
    observability::init_tracing("identity-provider");

    // Load config
    let config = Config::from_env().map_err(|e| anyhow::anyhow!("Config error: {e}"))?;
    info!(domain = %config.domain, port = config.port, "starting identity-provider");

    // Warn on insecure dev defaults
    if config.session_secret == DEV_SESSION_SECRET {
        warn!("SESSION_SECRET is using the insecure dev default — set it in production");
    }

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

    // Expand session secret to the 64 bytes required by Key::from.
    // For production, SESSION_SECRET should already be 64+ random bytes.
    let secret = config.session_secret.as_bytes();
    let mut key_material = [0u8; 64];
    for (i, dst) in key_material.iter_mut().enumerate() {
        *dst = secret[i % secret.len()];
    }
    let cookie_key = Key::from(&key_material);

    // Initialize S3-compatible storage (optional — skipped if env vars not set)
    let storage = if config.storage_enabled() {
        use idp_storage::{StorageClient, StorageConfig};

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
    let broker = idp_broker::RedisBroker::connect(&config.redis_url)
        .await
        .map_err(|e| anyhow::anyhow!("redis connection failed: {e}"))?;
    info!("redis broker connected");

    // Build shared state
    let hub = Arc::new(WsHub::new());
    let keypair = Arc::new(keypair);
    let config = Arc::new(config);
    let broker_arc: Arc<dyn idp_broker::EventBroker> = Arc::new(broker);

    // Outbound email transport. Builds the transport eagerly but the first TCP
    // connection happens on the first `send_signup_otp` call, so the IdP boots
    // even when Mailpit isn't reachable yet.
    let email_sender: Arc<dyn EmailSender> = {
        let cfg = EmailConfig {
            host: config.smtp_host.clone(),
            port: config.smtp_port,
            username: config.smtp_username.clone(),
            password: config.smtp_password.clone(),
            from: config.smtp_from.clone(),
            starttls: config.smtp_starttls,
            issuer_host: config.domain.clone(),
        };
        Arc::new(
            LettreSmtpSender::from_config(cfg)
                .map_err(|e| anyhow::anyhow!("email sender init failed: {e}"))?,
        )
    };
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
    let load_settings = Arc::new(application::settings::LoadSettings::new(settings_store));

    let accounts: Arc<dyn domain::identity::Accounts> =
        Arc::new(infrastructure::postgres::PgAccounts::new(pool.clone()));
    let remote_actors: Arc<dyn domain::identity::RemoteActors> =
        Arc::new(infrastructure::federation::FederatedRemoteActors::new(
            pool.clone(),
            origin.scheme().to_owned(),
            url_policy,
        ));
    let graph: Arc<dyn domain::social::SocialGraph> =
        Arc::new(infrastructure::postgres::PgSocialGraph::new(pool.clone()));
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
    let message_federation: Arc<dyn domain::messaging::MessageFederation> =
        Arc::new(infrastructure::federation::ApMessageFederation::new(
            Arc::clone(&keypair),
            url_policy,
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
        Arc::clone(&message_notifier),
        Arc::clone(&group_notifier),
    ));
    let receive_edit = Arc::new(ReceiveEdit::new(
        Arc::clone(&messages),
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
            config.session_secret.as_bytes().to_vec(),
            config.attachment_url_ttl,
        )),
    ));
    let read_blob = Arc::new(ReadBlob::new(
        Arc::clone(&attachments),
        Arc::new(infrastructure::blob_tokens::HmacBlobTokens::new(
            config.session_secret.as_bytes().to_vec(),
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
    let receive_peer_signal = Arc::new(application::presence::ReceivePeerSignal::new(Arc::clone(
        &bus,
    )));
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
    let mls_federation: Arc<dyn domain::e2ee::MlsFederation> = Arc::new(
        infrastructure::federation::ApMlsFederation::new(Arc::clone(&keypair), url_policy),
    );
    let receive_commit = Arc::new(application::e2ee::ReceiveCommit::new(
        Arc::clone(&accounts),
        Arc::clone(&conversations),
        Arc::clone(&commits),
        Arc::clone(&mls_notifier),
    ));
    let receive_welcome = Arc::new(application::e2ee::ReceiveWelcome::new(
        Arc::clone(&accounts),
        Arc::clone(&conversations),
        Arc::clone(&welcomes),
        Arc::clone(&mls_notifier),
        Arc::clone(&group_notifier),
    ));
    let sweep_welcomes = Arc::new(application::e2ee::SweepWelcomes::new(Arc::clone(&welcomes)));
    let send_group_message = Arc::new(SendGroupMessage::new(
        config.attachment_max_files_per_message,
        Arc::clone(&accounts),
        Arc::clone(&remote_actors),
        Arc::clone(&conversations),
        Arc::clone(&messages),
        Arc::clone(&message_notifier),
        Arc::clone(&message_federation),
    ));
    let edit_message = Arc::new(EditMessage::new(
        Arc::clone(&accounts),
        Arc::clone(&remote_actors),
        Arc::clone(&conversations),
        Arc::clone(&messages),
        Arc::clone(&message_notifier),
        Arc::clone(&message_federation),
    ));
    let load_history = Arc::new(LoadHistory::new(
        Arc::clone(&accounts),
        Arc::clone(&remote_actors),
        Arc::clone(&conversations),
        Arc::clone(&messages),
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
    let sweep_key_packages = Arc::new(application::e2ee::SweepKeyPackages::new(Arc::clone(
        &key_packages,
    )));

    let api_state = api::AppState {
        auth: Arc::new(infrastructure::auth::JwtTokenVerifier::new(
            Arc::clone(&keypair),
            config.issuer(),
        )),
        origin: origin.clone(),
        update_settings,
        send_friend_request: Arc::new(SendFriendRequest::new(
            Arc::clone(&accounts),
            Arc::clone(&remote_actors),
            Arc::clone(&graph),
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
        send_direct_message: Arc::clone(&send_direct_message),
        deliver_direct_message: Arc::clone(&deliver_direct_message),
        send_group_message,
        edit_message,
        load_history,
        mark_read,
        list_conversations,
        create_group: Arc::new(CreateGroup::new(
            Arc::clone(&accounts),
            Arc::clone(&remote_actors),
            Arc::clone(&conversations),
            Arc::clone(&group_notifier),
        )),
        list_group_members: Arc::new(ListGroupMembers::new(
            Arc::clone(&accounts),
            Arc::clone(&remote_actors),
            Arc::clone(&conversations),
        )),
        add_group_member: Arc::new(AddGroupMember::new(
            Arc::clone(&accounts),
            Arc::clone(&remote_actors),
            Arc::clone(&conversations),
            Arc::clone(&group_notifier),
        )),
        remove_group_member: Arc::new(RemoveGroupMember::new(
            Arc::clone(&accounts),
            Arc::clone(&conversations),
            Arc::clone(&group_notifier),
        )),
        rename_group: Arc::new(RenameGroup::new(
            Arc::clone(&accounts),
            Arc::clone(&remote_actors),
            Arc::clone(&conversations),
            Arc::clone(&group_notifier),
        )),
        set_member_role: Arc::new(SetMemberRole::new(
            Arc::clone(&accounts),
            Arc::clone(&remote_actors),
            Arc::clone(&conversations),
            Arc::clone(&group_notifier),
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
            Arc::new(infrastructure::realtime::HubDeviceNotifier::new(
                Arc::clone(&hub),
            )),
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
        )),
        key_package_status: Arc::new(application::e2ee::KeyPackageStatus::new(
            key_package_policy,
            key_packages,
        )),
        // A fresh requester can claim 60 at once, then one a second.
        claim_limiter: Arc::new(api::RateLimiter::new(60, 1.0)),
        append_commit: Arc::new(application::e2ee::AppendCommit::new(
            Arc::clone(&accounts),
            Arc::clone(&remote_actors),
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
        send_welcome: Arc::new(application::e2ee::SendWelcome::new(
            origin.clone(),
            Arc::clone(&accounts),
            Arc::clone(&remote_actors),
            Arc::clone(&conversations),
            welcomes,
            mls_notifier,
            mls_federation,
        )),
    };
    let receive_follow = Arc::new(ReceiveFollow::new(
        Arc::clone(&accounts),
        Arc::clone(&remote_actors),
        Arc::clone(&graph),
        Arc::clone(&social_notifier),
        Arc::clone(&social_federation),
    ));
    let receive_accept = Arc::new(ReceiveAccept::new(
        Arc::clone(&accounts),
        Arc::clone(&remote_actors),
        Arc::clone(&graph),
        Arc::clone(&social_notifier),
        Arc::clone(&friend_presence),
    ));
    let receive_reject = Arc::new(ReceiveReject::new(Arc::clone(&graph)));

    let receive_undo_follow = Arc::new(ReceiveUndoFollow::new(
        accounts,
        remote_actors,
        graph,
        social_notifier,
        friend_presence,
    ));

    let state = AppState {
        pool: pool.clone(),
        keypair: Arc::clone(&keypair),
        config: Arc::clone(&config),
        cookie_key,
        storage,
        hub: Arc::clone(&hub),
        broker: Arc::clone(&broker_arc),
        email: Arc::clone(&email_sender),
        email_otp_pepper: Arc::clone(&email_otp_pepper),
        url_policy,
        key_cache,
        origin,
        load_settings,
        receive_follow,
        receive_accept,
        receive_reject,
        receive_undo_follow,
        send_direct_message,
        deliver_direct_message,
        receive_message,
        receive_edit,
        receive_commit,
        receive_welcome,
        serve_peer_content,
    };

    // The presence bus, to the accounts that hear of it; idle connections, every minute.
    let signals = infrastructure::presence::signals(&config.redis_url, &config.domain).await?;
    tokio::spawn(api::background::relay_signals(
        signals,
        apply_presence,
        deliver_typing,
    ));
    tokio::spawn(api::background::sweep_idle_connections(sweep_idle));

    // Other instances' presence: polled for friends lists, streamed for open conversations.
    tokio::spawn(api::background::poll_peers(poll_peers));
    tokio::spawn(api::background::relay_peer_signals(
        peer_signals,
        receive_peer_signal,
    ));

    info!("presence system started");

    // Fail the remote DMs a crash left `pending`.
    tokio::spawn(api::background::sweep_stale_deliveries(
        sweep_stale_deliveries,
    ));

    // Spawn signup-verification reaper (expired OTPs + abandoned accounts).
    {
        let pool_for_reaper = pool.clone();
        tokio::spawn(async move {
            idp_auth::signup_reaper::run_signup_reaper(pool_for_reaper).await;
        });
    }

    // Reap MLS KeyPackages and Welcomes past their use.
    tokio::spawn(api::background::sweep_key_packages(sweep_key_packages));
    tokio::spawn(api::background::sweep_welcomes(sweep_welcomes));
    // Reap uploads never sent.
    tokio::spawn(api::background::sweep_orphan_attachments(
        sweep_orphan_attachments,
    ));

    // Build the Axum router
    let app = router::build(state, api::router(api_state));

    // Start listening
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!(addr = %addr, "listening");

    axum::serve(listener, app).await?;
    Ok(())
}
