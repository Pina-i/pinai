use axum::{
    http::{HeaderValue, Method},
    routing::{delete, get, patch, post, put},
    Json, Router,
};
use serde_json::json;
use tower_http::{
    cors::{AllowHeaders, CorsLayer},
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
};
use tracing::Level;

use idp_federation::{
    actor::{get_actor, get_instance_actor},
    inbox::post_inbox,
    outbox::{
        get_followers as get_ap_followers, get_following as get_ap_following, get_outbox,
    },
    webfinger::get_webfinger,
};
use idp_messaging::{
    add_reaction, edit_message, get_conversation, list_conversations, remove_reaction,
    send_message,
};
use idp_social::{
    accept_friendship, delete_friendship, get_friends, get_incoming_requests,
    post_friend_request, reject_friendship, search_users,
};
use idp_auth::{
    authorize::get_authorize,
    avatar::{delete_avatar, put_avatar},
    discovery::{jwks, openid_configuration},
    login::post_login,
    logout::get_logout,
    presence::handlers::{get_presence, post_presence_batch},
    presence::sse::get_presence_stream,
    register::{post_register, post_register_and_login},
    token::post_token,
    userinfo::get_userinfo,
    ws::ws_upgrade,
};
use idp_state::AppState;

pub fn build(state: AppState) -> Router {
    let origins: Vec<HeaderValue> = state
        .config
        .cors_origins
        .iter()
        .filter_map(|o| o.parse::<HeaderValue>().ok())
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::PATCH, Method::OPTIONS])
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
        .route("/actor", get(get_instance_actor))
        .route("/users/{username}", get(get_actor))
        .route("/users/{username}/inbox", post(post_inbox))
        .route("/users/{username}/outbox", get(get_outbox))
        .route("/users/{username}/followers", get(get_ap_followers))
        .route("/users/{username}/following", get(get_ap_following))

        // ── Friendship REST API (Bearer-auth) ───────────────────────────────
        .route("/api/users/search", get(search_users))
        .route("/api/friends/request", post(post_friend_request))
        .route("/api/friends/incoming", get(get_incoming_requests))
        .route("/api/friends/{actor_uri}", delete(delete_friendship))
        .route("/api/friends/{friendship_id}/accept", post(accept_friendship))
        .route("/api/friends/{friendship_id}/reject", delete(reject_friendship))
        .route("/api/friends", get(get_friends))

        // ── Direct Messages REST API (Bearer-auth) ────────────────────────────
        .route("/api/dm", post(send_message).get(list_conversations))
        .route("/api/dm/{conversation_id}", get(get_conversation))
        .route("/api/dm/{message_id}/edit", patch(edit_message))
        .route("/api/dm/{message_id}/reactions", post(add_reaction).delete(remove_reaction))

        // ── Avatar API (Bearer-auth) ────────────────────────────────────
        .route("/api/avatar", put(put_avatar).delete(delete_avatar))

        // ── Presence API ────────────────────────────────────────────────────
        .route("/api/presence", get(get_presence))
        .route("/api/presence/stream", get(get_presence_stream))
        .route("/api/presence/batch", post(post_presence_batch))

        // ── WebSocket ────────────────────────────────────────────────────────
        .route("/ws", get(ws_upgrade))

        // ── Health check ──────────────────────────────────────────────────────
        .route("/health", get(|| async { Json(json!({ "ok": true })) }))

        .with_state(state)
        .layer(cors)
        .layer(trace_layer)
}
