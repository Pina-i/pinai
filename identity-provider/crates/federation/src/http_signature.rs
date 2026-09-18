//! Inbound HTTP Signature verification for server-to-server endpoints.
//!
//! Re-exported from `federation-transport` so existing call sites keep their
//! import path. `?` converts `TransportError` into `OidcError`.

pub use federation_transport::{verify_body_digest, verify_http_signature};
