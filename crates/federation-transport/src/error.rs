/// Failures from the server-to-server transport.
///
/// Deliberately not an HTTP error type: each service maps these onto its own
/// error representation.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Denied(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Upstream(String),
}
