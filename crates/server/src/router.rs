use axum::{
    http::{HeaderValue, Method},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde_json::json;
use tower_http::{
    cors::{AllowHeaders, CorsLayer},
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
};
use tracing::Level;

use idp_oidc::{
    authorize::get_authorize,
    avatar::{delete_avatar, put_avatar},
    discovery::{jwks, openid_configuration},
    federation::{
        actor::get_actor,
        follow::{
            accept_follow, delete_follow, get_followers, get_following, get_incoming_requests,
            post_follow, reject_follow, search_users,
        },
        inbox::post_inbox,
        messages::{get_conversation, list_conversations, send_message},
        outbox::{
            get_followers as get_ap_followers, get_following as get_ap_following, get_outbox,
        },
        webfinger::get_webfinger,
    },
    login::post_login,
    logout::get_logout,
    register::{post_register, post_register_and_login},
    token::post_token,
    userinfo::get_userinfo,
    ws::ws_upgrade,
    AppState,
};

pub fn build(state: AppState) -> Router {
    let origins: Vec<HeaderValue> = state
        .config
        .cors_origins
        .iter()
        .filter_map(|o| o.parse::<HeaderValue>().ok())
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers(AllowHeaders::any())
        .allow_credentials(false);

    // HTTP request/response tracing — one span per request with method, path, status, latency.
    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_response(DefaultOnResponse::new().level(Level::INFO));

    Router::new()
        // ── Well-known (OIDC + WebFinger) ────────────────────────────────────
        .route("/.well-known/openid-configuration", get(openid_configuration))
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
        .route("/logout", get(get_logout))

        // ── ActivityPub actor endpoints ───────────────────────────────────────
        .route("/users/{handle}", get(get_actor))
        .route("/users/{handle}/inbox", post(post_inbox))
        .route("/users/{handle}/outbox", get(get_outbox))
        .route("/users/{handle}/followers", get(get_ap_followers))
        .route("/users/{handle}/following", get(get_ap_following))

        // ── Social graph REST API (Bearer-auth) ───────────────────────────────
        .route("/api/users/search", get(search_users))
        .route("/api/follow", post(post_follow))
        .route("/api/follow/incoming", get(get_incoming_requests))
        .route("/api/follow/{address}", delete(delete_follow))
        .route("/api/follow/{follow_id}/accept", post(accept_follow))
        .route("/api/follow/{follow_id}/reject", post(reject_follow))
        .route("/api/following", get(get_following))
        .route("/api/followers", get(get_followers))

        // ── Direct Messages REST API (Bearer-auth) ────────────────────────────
        .route("/api/dm", post(send_message).get(list_conversations))
        .route("/api/dm/{address}", get(get_conversation))

        // ── Avatar API (Bearer-auth) ────────────────────────────────────
        .route("/api/avatar", put(put_avatar).delete(delete_avatar))

        // ── WebSocket ────────────────────────────────────────────────────────
        .route("/ws", get(ws_upgrade))

        // ── Health check ──────────────────────────────────────────────────────
        .route("/health", get(|| async { Json(json!({ "ok": true })) }))

        .with_state(state)
        .layer(cors)
        .layer(trace_layer)
}
