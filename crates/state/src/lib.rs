//! Shared application state and error type used by every HTTP/WS handler in the
//! workspace. This crate is the integration seam: domain crates depend on it
//! to read shared infrastructure (PgPool, broker, hub, presence registries),
//! and the `server` crate constructs the concrete `AppState` at startup.

pub mod error;
pub mod state;

pub use error::{OidcError, OidcErrorBody};
pub use state::AppState;
