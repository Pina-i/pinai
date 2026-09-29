use axum::http::HeaderName;
use axum::{
    http::{HeaderValue, Method},
    routing::{get, patch, post, put},
    Json, Router,
};
use serde_json::json;
use tower_http::{
    cors::CorsLayer,
    trace::{DefaultOnResponse, TraceLayer},
};
use tracing::Level;

use idp_auth::{
    authorize::get_authorize,
    avatar::{delete_avatar, put_avatar},
    dev::post_send_test_email,
    discovery::{jwks, openid_configuration},
    login::post_login,
    logout::get_logout,
    profile::update_profile,
    register::{post_register, post_register_and_login},
    token::post_token,
    totp::{
        post_disable as post_totp_disable, post_enroll as post_totp_enroll,
        post_enroll_verify as post_totp_enroll_verify, post_login_totp,
        post_regenerate_recovery_codes as post_totp_regenerate_recovery_codes,
    },
    userinfo::get_userinfo,
    verify_email::{post_resend_verification, post_verify_email_and_login},
};
use idp_federation::{
    actor::{get_actor, get_instance_actor},
    attachments::get_attachment_content,
    inbox::post_inbox,
    outbox::{get_followers as get_ap_followers, get_following as get_ap_following, get_outbox},
    webfinger::get_webfinger,
};
use idp_social::search_users;
use idp_state::AppState;

/// `api` carries the routes already moved to the layer crates; see `idp_api::router`.
pub fn build(state: AppState, api: Router) -> Router {
    let origins: Vec<HeaderValue> = state
        .config
        .cors_origins
        .iter()
        .filter_map(|o| o.parse::<HeaderValue>().ok())
        .collect();

    // Explicit header allowlist — Firefox/Gecko treats `Access-Control-Allow-Headers: *`
    // as not covering `Authorization`, so the wildcard would silently drop our
    // Bearer-auth on every cross-origin request. Listing the headers we
    // actually send (and the ones browsers' fetch preflight asks about) is
    // both more correct and warning-free.
    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::OPTIONS,
        ])
        .allow_headers([
            HeaderName::from_static("authorization"),
            HeaderName::from_static("content-type"),
            HeaderName::from_static("accept"),
            HeaderName::from_static("x-requested-with"),
        ])
        .allow_credentials(false);

    // HTTP request/response tracing — one span per request with method, path, status, latency.
    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(|request: &axum::http::Request<axum::body::Body>| {
            tracing::info_span!(
                "request",
                method = %request.method(),
                uri = %logged_uri(request.uri()),
                version = ?request.version(),
            )
        })
        .on_response(DefaultOnResponse::new().level(Level::INFO));

    let is_dev = state.config.environment.is_dev();

    let router = Router::new()
        // ── Well-known (OIDC + WebFinger) ────────────────────────────────────
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/.well-known/jwks.json", get(jwks))
        .route("/.well-known/webfinger", get(get_webfinger))
        // ── OIDC flow ─────────────────────────────────────────────────────────
        .route("/authorize", get(get_authorize))
        .route("/login", post(post_login))
        .route("/token", post(post_token))
        .route("/userinfo", get(get_userinfo))
        // ── User management ───────────────────────────────────────────────────
        .route("/register", post(post_register))
        .route("/register-and-login", post(post_register_and_login))
        .route("/verify-email-and-login", post(post_verify_email_and_login))
        .route("/verify-email/resend", post(post_resend_verification))
        .route("/login/totp", post(post_login_totp))
        .route("/api/totp/enroll", post(post_totp_enroll))
        .route("/api/totp/enroll/verify", post(post_totp_enroll_verify))
        .route("/api/totp/disable", post(post_totp_disable))
        .route(
            "/api/totp/recovery-codes/regenerate",
            post(post_totp_regenerate_recovery_codes),
        )
        .route("/logout", get(get_logout))
        // ── ActivityPub actor endpoints ───────────────────────────────────────
        .route("/actor", get(get_instance_actor))
        .route("/users/{username}", get(get_actor))
        .route("/users/{username}/inbox", post(post_inbox))
        .route("/users/{username}/outbox", get(get_outbox))
        .route("/users/{username}/followers", get(get_ap_followers))
        .route("/users/{username}/following", get(get_ap_following))
        // ── User search (Bearer-auth); the friend routes are in `api` ────────
        .route("/api/users/search", get(search_users))
        // ── Avatar API (Bearer-auth) ────────────────────────────────────
        .route("/api/avatar", put(put_avatar).delete(delete_avatar))
        // ── Profile API (Bearer-auth) ───────────────────────────────────
        .route("/api/profile", patch(update_profile))
        // ── E2EE — key directory, Delivery Service, history archive — is in `api` ──
        // ── Attachments: upload, open and blob are in `api` ─────────────
        // HTTP-Signature auth — peer-IdP-facing source of truth for local attachments.
        .route("/api/attachments/{id}/content", get(get_attachment_content))
        // ── WebSocket ────────────────────────────────────────────────────────
        // ── Health check ──────────────────────────────────────────────────────
        .route("/health", get(|| async { Json(json!({ "ok": true })) }));

    // Dev-only routes — never registered in production.
    let router = if is_dev {
        router.route("/dev/send-test-email", post(post_send_test_email))
    } else {
        router
    };

    router
        .with_state(state)
        .merge(api)
        .layer(cors)
        .layer(trace_layer)
}

/// A request's URI as logged: the path only — a query can carry a credential (`/ws?token=`, a
/// blob URL's token).
fn logged_uri(uri: &axum::http::Uri) -> String {
    uri.path().to_owned()
}

#[cfg(test)]
mod tests;
