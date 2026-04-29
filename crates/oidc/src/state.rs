use std::sync::Arc;

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use idp_broker::EventBroker;
use idp_config::Config;
use idp_db::PgPool;
use idp_storage::StorageClient;
use jwt_utils::EdKeyPair;

use crate::presence::remote::RemotePresenceRegistry;
use crate::presence::store::PresenceStore;
use crate::presence::sweep::HeartbeatTracker;
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
    /// In-memory presence state store (online/away/offline per actor).
    pub presence_store: Option<Arc<PresenceStore>>,
    /// Per-connection heartbeat tracker for idle detection.
    pub heartbeat_tracker: Option<Arc<HeartbeatTracker>>,
    /// Outbound presence connections to remote IdPs (batch poll + per-domain SSE).
    pub remote_registry: Option<Arc<RemotePresenceRegistry>>,
}

/// Allow `SignedCookieJar` to extract the key from `AppState`.
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}
