use std::sync::Arc;

use axum_extra::extract::cookie::Key;
use sqlx::postgres::PgPoolOptions;
use tracing::{info, warn};

use idp_config::Config;
use idp_db::run_migrations;
use idp_email::{EmailConfig, EmailSender, LettreSmtpSender};
use idp_presence::remote::RemotePresenceRegistry;
use idp_presence::store::PresenceStore;
use idp_presence::sweep::HeartbeatTracker;
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
    let dev_secret = "dev-only-insecure-session-secret-change-in-production-00000000";
    if config.session_secret == dev_secret {
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
    run_migrations(&pool)
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

    // Build presence components
    let presence_store = Arc::new(PresenceStore::new());
    let heartbeat_tracker = Arc::new(HeartbeatTracker::new());
    let remote_registry = Arc::new(RemotePresenceRegistry::new());

    // Build shared state
    let hub = Arc::new(WsHub::new());
    let keypair = Arc::new(keypair);
    let config = Arc::new(config);
    let broker_arc: Arc<dyn idp_broker::EventBroker> = Arc::new(broker);

    // Wire SSE deps onto the registry so it can spawn outbound connections.
    remote_registry.set_sse_deps(
        Arc::clone(&keypair),
        Arc::clone(&config),
        Arc::clone(&broker_arc),
    );

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

    let state = AppState {
        pool: pool.clone(),
        keypair: Arc::clone(&keypair),
        config: Arc::clone(&config),
        cookie_key,
        storage,
        hub: Arc::clone(&hub),
        broker: Arc::clone(&broker_arc),
        presence_store: Some(Arc::clone(&presence_store)),
        heartbeat_tracker: Some(Arc::clone(&heartbeat_tracker)),
        remote_registry: Some(Arc::clone(&remote_registry)),
        email: Arc::clone(&email_sender),
        email_otp_pepper: Arc::clone(&email_otp_pepper),
    };

    // Spawn presence background tasks
    {
        let store = Arc::clone(&presence_store);
        let pool2 = pool.clone();
        let hub2 = Arc::clone(&hub);
        let redis_url = config.redis_url.clone();
        let domain = config.domain.clone();
        tokio::spawn(async move {
            idp_presence::subscriber::run_presence_subscriber(
                &redis_url, &domain, store, pool2, hub2,
            )
            .await;
        });
    }

    {
        let tracker = Arc::clone(&heartbeat_tracker);
        let store = Arc::clone(&presence_store);
        let broker2 = Arc::clone(&state.broker);
        let domain = config.domain.clone();
        tokio::spawn(async move {
            idp_presence::sweep::run_heartbeat_sweep(tracker, store, broker2, domain).await;
        });
    }

    {
        let registry = Arc::clone(&remote_registry);
        let store = Arc::clone(&presence_store);
        let broker3 = Arc::clone(&state.broker);
        let pool3 = pool.clone();
        let keypair2 = Arc::clone(&keypair);
        let config2 = Arc::clone(&config);
        tokio::spawn(async move {
            idp_presence::remote::run_batch_poller(
                registry, store, broker3, pool3, keypair2, config2,
            )
            .await;
        });
    }

    info!("presence system started");

    // Spawn signup-verification reaper (expired OTPs + abandoned accounts).
    {
        let pool_for_reaper = pool.clone();
        tokio::spawn(async move {
            idp_auth::signup_reaper::run_signup_reaper(pool_for_reaper).await;
        });
    }

    // Spawn DM-attachment orphan-sweep background task.
    {
        let pool_for_sweep = pool.clone();
        let storage_for_sweep = state.storage.clone();
        let config_for_sweep = Arc::clone(&config);
        tokio::spawn(async move {
            idp_messaging::orphan_sweep::run_orphan_sweep(
                pool_for_sweep,
                storage_for_sweep,
                config_for_sweep,
            )
            .await;
        });
    }

    // Build the Axum router
    let app = router::build(state);

    // Start listening
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!(addr = %addr, "listening");

    axum::serve(listener, app).await?;
    Ok(())
}
