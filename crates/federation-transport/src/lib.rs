//! Server-to-server federation transport, shared by every service that speaks
//! ActivityPub: WebFinger actor resolution, signed delivery, and inbound
//! signature + digest verification.
//!
//! Every outbound request goes through one screened, bounded HTTP client, and
//! inbound verification reads keys through a [`KeyCache`].
//!
//! Domain handling — which activity verbs a service accepts and what they do —
//! stays in the service.

pub mod actor;
pub mod error;
pub mod http;
pub mod keycache;
pub mod sign;
pub mod verify;

pub use actor::{resolve_remote_actor, RemoteActor};
pub use error::TransportError;
pub use http::UrlPolicy;
pub use keycache::KeyCache;
pub use sign::{signed_post, Signer};
pub use verify::{verify_body_digest, verify_http_signature};
