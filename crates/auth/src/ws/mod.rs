//! Axum WebSocket upgrade handler. The transport primitives (`WsHub`,
//! `WsEvent`, `WsClientMessage`) live in the `idp-realtime` crate; this
//! module owns the cross-domain handler that talks to federation, presence,
//! and the database.

pub mod handler;

pub use handler::ws_upgrade;

// Re-exported for backward-compat with existing callers inside this crate.
pub use idp_realtime::WsHub;
