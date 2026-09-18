//! Presence and typing-indicator domain: state store, heartbeat sweep, fan-out
//! to local WebSocket clients, and inter-IdP SSE outbound clients. HTTP handlers
//! that depend on the OIDC `AppState` live in the `idp-oidc` crate (transitional)
//! until the auth split is completed.

pub mod fanout;
pub mod remote;
pub mod sse_client;
pub mod store;
pub mod subscriber;
pub mod sweep;
pub mod types;

pub use store::PresenceStore;
