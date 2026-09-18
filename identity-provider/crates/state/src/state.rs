use std::sync::Arc;

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use idp_broker::EventBroker;
use idp_config::Config;
use idp_db::PgPool;
use idp_email::EmailSender;
use idp_storage::StorageClient;
use jwt_utils::EdKeyPair;

use idp_presence::remote::RemotePresenceRegistry;
use idp_presence::store::PresenceStore;
use idp_presence::sweep::HeartbeatTracker;
use idp_realtime::WsHub;

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
    /// Outbound email transport (signup OTPs, future password resets).
    pub email: Arc<dyn EmailSender>,
    /// HMAC pepper for email OTP code hashes. Never logged or stored.
    pub email_otp_pepper: Arc<Vec<u8>>,
}

/// Allow `SignedCookieJar` to extract the key from `AppState`.
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}
