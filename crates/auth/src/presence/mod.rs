//! Presence-related HTTP/SSE handlers that still depend on `AppState`.
//! The pure presence domain (store, sweep, fanout, subscriber, remote registry,
//! SSE client, types) lives in the `idp-presence` crate.

pub mod handlers;
pub mod sse;

// Transitional re-exports so callers inside this crate keep working
// (`crate::presence::types`, `crate::presence::store`, etc.).
pub use idp_presence::{fanout, remote, sse_client, store, subscriber, sweep, types, PresenceStore};
