use std::sync::Arc;

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use idp_broker::EventBroker;
use idp_config::Config;
use idp_db::PgPool;
use idp_storage::StorageClient;
use jwt_utils::EdKeyPair;

use crate::ws::WsHub;

/// Shared application state injected into every Axum handler via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub keypair: Arc<EdKeyPair>,
    pub config: Arc<Config>,
    /// HMAC key for signing/verifying session cookies.
    pub cookie_key: Key,
    /// S3-compatible object storage (None when storage is not configured).
    pub storage: Option<StorageClient>,
    /// WebSocket connection hub for real-time event delivery.
    pub hub: Arc<WsHub>,
    /// Event broker for durable event delivery (Redis Streams) and presence (pub-sub).
    pub broker: Arc<dyn EventBroker>,
}

/// Allow `SignedCookieJar` to extract the key from `AppState`.
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}
