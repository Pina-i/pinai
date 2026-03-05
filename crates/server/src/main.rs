use std::sync::Arc;

use axum_extra::extract::cookie::Key;
use sqlx::postgres::PgPoolOptions;
use tracing::{info, warn};

use idp_config::Config;
use idp_db::run_migrations;
use idp_oidc::AppState;
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

    // Build shared state
    let state = AppState {
        pool,
        keypair: Arc::new(keypair),
        config: Arc::new(config.clone()),
        cookie_key,
        storage,
    };

    // Build the Axum router
    let app = router::build(state);

    // Start listening
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!(addr = %addr, "listening");

    axum::serve(listener, app).await?;
    Ok(())
}
