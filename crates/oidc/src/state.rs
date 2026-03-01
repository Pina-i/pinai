use std::sync::Arc;

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use idp_config::Config;
use idp_db::PgPool;
use jwt_utils::EdKeyPair;

/// Shared application state injected into every Axum handler via `State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub keypair: Arc<EdKeyPair>,
    pub config: Arc<Config>,
    /// HMAC key for signing/verifying session cookies.
    pub cookie_key: Key,
}

/// Allow `SignedCookieJar` to extract the key from `AppState`.
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}
