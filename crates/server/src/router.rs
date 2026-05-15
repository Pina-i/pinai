use axum::{
    extract::DefaultBodyLimit,
    http::{HeaderValue, Method},
    routing::{delete, get, patch, post, put},
    Json, Router,
};
use serde_json::json;
use axum::http::HeaderName;
use tower_http::{
    cors::CorsLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
};
use tracing::Level;

use idp_federation::{
    actor::{get_actor, get_instance_actor},
    attachments::get_attachment_content,
    inbox::post_inbox,
    outbox::{
        get_followers as get_ap_followers, get_following as get_ap_following, get_outbox,
    },
    webfinger::get_webfinger,
};
use idp_messaging::{
    attachments::{get_attachment, upload_attachments},
    blob::get_attachment_blob,
    edit_message, get_conversation, list_conversations, mark_read, send_message,
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
    profile::update_profile,
    register::{post_register, post_register_and_login},
    token::post_token,
    userinfo::get_userinfo,
    ws::ws_upgrade,
};
use idp_e2ee::{
    delete_history, get_commits_since, get_devices, get_history_page, get_history_salt,
    get_packages_status, get_welcomes, post_commit, post_history_batch, post_history_salt,
    post_packages, post_packages_claim, post_welcome, register_device, revoke_device,
};
use idp_state::AppState;

pub fn build(state: AppState) -> Router {
    let origins: Vec<HeaderValue> = state
        .config
        .cors_origins
        .iter()
        .filter_map(|o| o.parse::<HeaderValue>().ok())
        .collect();

    // Body-size cap for the attachment-upload endpoint:
    // (max files per request) * (max bytes per file) + 1 MiB headroom for
    // multipart-boundary overhead.
    let attachment_body_limit: usize = (state
        .config
        .attachment_max_files_per_message as u64
        * state.config.attachment_max_byte_size
        + 1024 * 1024) as usize;

    // Explicit header allowlist — Firefox/Gecko treats `Access-Control-Allow-Headers: *`
    // as not covering `Authorization`, so the wildcard would silently drop our
    // Bearer-auth on every cross-origin request. Listing the headers we
    // actually send (and the ones browsers' fetch preflight asks about) is
    // both more correct and warning-free.
    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::PATCH, Method::OPTIONS])
        .allow_headers([
            HeaderName::from_static("authorization"),
            HeaderName::from_static("content-type"),
            HeaderName::from_static("accept"),
            HeaderName::from_static("x-requested-with"),
        ])
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
        // Reactions are gone — they're MLS application messages of
        // `kind = "reaction"`, indistinguishable from text on the wire and
        // computed client-side from the decrypted MLS stream (Phase 3).
        .route("/api/dm", post(send_message).get(list_conversations))
        .route("/api/dm/{conversation_id}", get(get_conversation))
        .route("/api/dm/{conversation_id}/read", post(mark_read))
        .route("/api/dm/{message_id}/edit", patch(edit_message))

        // ── Avatar API (Bearer-auth) ────────────────────────────────────
        .route("/api/avatar", put(put_avatar).delete(delete_avatar))

        // ── Profile API (Bearer-auth) ───────────────────────────────────
        .route("/api/profile", patch(update_profile))

        // ── E2EE key directory ──────────────────────────────────────────
        // KeyPackages: POST + status are Bearer (own device);
        // claim accepts Bearer (local cross-add) or HTTP-Sig (peer cross-add).
        .route("/api/keys/packages", post(post_packages))
        .route("/api/keys/packages/claim", post(post_packages_claim))
        .route("/api/keys/packages/status", get(get_packages_status))
        // Devices — list, register/renew/rotate Device Root Key, revoke.
        .route("/api/keys/devices", get(get_devices).post(register_device))
        .route("/api/keys/devices/{device_id}/revoke", post(revoke_device))

        // ── History backup ─────────────────────────────────────────────
        .route(
            "/api/history/messages",
            post(post_history_batch).get(get_history_page).delete(delete_history),
        )
        .route(
            "/api/history/salt",
            get(get_history_salt).post(post_history_salt),
        )

        // ── MLS Delivery Service (Bearer-auth) ──────────────────────────
        // Commits: ordered append per group with `409` on epoch race;
        // catch-up via `?since=<epoch>`. Welcomes: per-device atomic claim.
        .route(
            "/api/mls/groups/{conversation_id}/commits",
            post(post_commit).get(get_commits_since),
        )
        .route("/api/mls/welcomes", get(get_welcomes).post(post_welcome))

        // ── DM Attachments API ──────────────────────────────────────────
        // Upload: per-route body limit overrides Axum's 2 MiB default.
        .route(
            "/api/attachments",
            post(upload_attachments).layer(DefaultBodyLimit::max(attachment_body_limit)),
        )
        // Bearer auth — returns the token-protected blob URL.
        .route("/api/attachments/{id}", get(get_attachment))
        // Token auth (token in query string) — redirects to RustFS or proxies remote.
        .route("/api/attachments/{id}/blob", get(get_attachment_blob))
        // HTTP-Signature auth — peer-IdP-facing source of truth for local attachments.
        .route("/api/attachments/{id}/content", get(get_attachment_content))

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
