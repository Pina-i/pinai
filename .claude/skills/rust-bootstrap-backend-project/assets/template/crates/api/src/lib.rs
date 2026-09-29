pub mod error;
mod health;

use axum::Router;
use axum::routing::get;

pub use error::ApiError;

/// What handlers reach through `State`: the use cases, as `Arc`s, built in `app`.
#[derive(Clone, Default)]
pub struct AppState {}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health::health))
        .with_state(state)
}

#[cfg(test)]
mod tests;
