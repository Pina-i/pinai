use std::sync::Arc;

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use federation_transport::{KeyCache, UrlPolicy};
use idp_broker::EventBroker;
use idp_config::Config;
use idp_db::PgPool;
use idp_email::EmailSender;
use idp_storage::StorageClient;
use jwt_utils::EdKeyPair;

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
    /// Outbound email transport (signup OTPs, future password resets).
    pub email: Arc<dyn EmailSender>,
    /// HMAC pepper for email OTP code hashes. Never logged or stored.
    pub email_otp_pepper: Arc<Vec<u8>>,
    /// What a peer URL may be — an https issuer is treated as production.
    pub url_policy: UrlPolicy,
    /// Verifying keys for inbound HTTP Signatures.
    pub key_cache: Arc<KeyCache>,
    /// This instance's scheme and domain — owns every local actor URI.
    pub origin: domain::identity::InstanceOrigin,
    /// The account's settings document, read by `/userinfo` and the profile endpoint.
    pub load_settings: Arc<application::settings::LoadSettings>,
    /// The friendship activities the inbox receives.
    pub receive_follow: Arc<application::social::ReceiveFollow>,
    pub receive_accept: Arc<application::social::ReceiveAccept>,
    pub receive_reject: Arc<application::social::ReceiveReject>,
    pub receive_undo_follow: Arc<application::social::ReceiveUndoFollow>,
    /// The WebSocket `send_dm`, and the second half of a message to another instance.
    pub send_direct_message: Arc<application::messaging::SendDirectMessage>,
    pub deliver_direct_message: Arc<application::messaging::DeliverDirectMessage>,
    /// The MLS messages the inbox receives.
    pub receive_message: Arc<application::messaging::ReceiveMessage>,
    pub receive_edit: Arc<application::messaging::ReceiveEdit>,
    pub receive_commit: Arc<application::e2ee::ReceiveCommit>,
    pub receive_welcome: Arc<application::e2ee::ReceiveWelcome>,
    /// A peer's fetch of an attachment uploaded here.
    pub serve_peer_content: Arc<application::messaging::ServePeerContent>,
}

impl AppState {
    /// Whether a raw actor URI names an account on this instance.
    pub fn is_local_actor(&self, uri: &str) -> bool {
        domain::identity::ActorUri::parse(uri).is_ok_and(|uri| self.origin.owns(&uri))
    }
}

/// Allow `SignedCookieJar` to extract the key from `AppState`.
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}
