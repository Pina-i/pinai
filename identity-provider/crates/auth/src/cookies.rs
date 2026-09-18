use axum_extra::extract::cookie::{Cookie, SameSite};
use uuid::Uuid;

pub const SESSION_COOKIE_NAME: &str = "idp_session";

/// Build a signed session cookie containing the user's UUID.
/// `secure` should be `true` in production (HTTPS), `false` on localhost.
pub fn build_session_cookie(user_id: Uuid, secure: bool) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE_NAME, user_id.to_string()))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(time::Duration::days(30))
        .secure(secure)
        .build()
}

/// Build a placeholder cookie suitable for `SignedCookieJar::remove`.
/// The jar's `remove` method handles setting max_age=0 / expires=epoch.
pub fn clear_session_cookie() -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE_NAME, "")).path("/").build()
}

/// URL-encode a string (percent-encode non-unreserved characters).
pub fn urlencoded(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
                vec![c]
            } else {
                format!("%{:02X}", c as u32).chars().collect()
            }
        })
        .collect()
}
