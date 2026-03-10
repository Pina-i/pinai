use axum::{
    extract::Query,
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::cookie::SignedCookieJar;
use serde::Deserialize;

use crate::cookies::clear_session_cookie;

#[derive(Debug, Deserialize)]
pub struct LogoutParams {
    /// Where to send the user after logout. Must be an http/https URL.
    pub post_logout_redirect_uri: Option<String>,
}

/// GET /logout — clear the session cookie and redirect.
#[tracing::instrument(skip_all, fields(redirect_uri = ?params.post_logout_redirect_uri))]
pub async fn get_logout(
    jar: SignedCookieJar,
    Query(params): Query<LogoutParams>,
) -> impl IntoResponse {
    let updated_jar = jar.remove(clear_session_cookie());

    let redirect_to = match params.post_logout_redirect_uri.as_deref() {
        Some(uri) if is_safe_redirect(uri) => {
            tracing::info!(redirect_uri = %uri, "session cookie cleared, redirecting after logout");
            uri.to_owned()
        }
        Some(uri) => {
            tracing::warn!(redirect_uri = %uri, "unsafe post_logout_redirect_uri rejected, falling back to /");
            "/".to_owned()
        }
        None => {
            tracing::info!("session cookie cleared, no redirect URI provided");
            "/".to_owned()
        }
    };

    (updated_jar, Redirect::to(&redirect_to))
}

/// Only allow http:// and https:// redirect targets to prevent open-redirect XSS.
fn is_safe_redirect(uri: &str) -> bool {
    uri.starts_with("http://") || uri.starts_with("https://")
}
