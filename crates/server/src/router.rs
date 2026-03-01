use axum::{
    http::{HeaderValue, Method},
    routing::{get, post},
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
    discovery::{jwks, openid_configuration},
    login::post_login,
    logout::get_logout,
    register::{post_register, post_register_and_login},
    token::post_token,
    userinfo::get_userinfo,
    AppState,
};

pub fn build(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin([
            "http://localhost:5173".parse::<HeaderValue>().unwrap(),
            "http://localhost:3000".parse::<HeaderValue>().unwrap(),
        ])
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(AllowHeaders::any())
        .allow_credentials(false);

    // HTTP request/response tracing — one span per request with method, path, status, latency.
    // Visible at INFO level so it works in production without extra configuration.
    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_response(DefaultOnResponse::new().level(Level::INFO));

    Router::new()
        // Well-known endpoints
        .route("/.well-known/openid-configuration", get(openid_configuration))
        .route("/.well-known/jwks.json", get(jwks))
        // OIDC flow
        .route("/authorize", get(get_authorize))
        .route("/login", post(post_login))
        .route("/token", post(post_token))
        .route("/userinfo", get(get_userinfo))
        // User management
        .route("/register", post(post_register))
        .route("/register-and-login", post(post_register_and_login))
        .route("/logout", get(get_logout))
        // Health check
        .route("/health", get(|| async { Json(json!({ "ok": true })) }))
        // Apply state and middleware (outermost last: trace → cors → routes)
        .with_state(state)
        .layer(cors)
        .layer(trace_layer)
}
