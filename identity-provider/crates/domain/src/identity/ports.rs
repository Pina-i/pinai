use time::{Duration, OffsetDateTime};

use crate::{SessionId, UserId};

use super::{Account, ActorUri, FederatedAddress, Handle, RemoteActor};

/// The local accounts other contexts address.
#[async_trait::async_trait]
pub trait Accounts: Send + Sync {
    async fn find(&self, id: UserId) -> Result<Option<Account>, AccountsError>;
    async fn find_by_handle(&self, handle: &Handle) -> Result<Option<Account>, AccountsError>;
    async fn find_by_uri(&self, uri: &ActorUri) -> Result<Option<Account>, AccountsError>;
    /// The accounts whose handle holds `fragment`, in any case, by handle; at most `limit`.
    async fn search(&self, fragment: &str, limit: i64) -> Result<Vec<Account>, AccountsError>;
    /// How many local accounts there are.
    async fn count(&self) -> Result<u64, AccountsError>;
}

#[derive(Debug, thiserror::Error)]
pub enum AccountsError {
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

/// Accounts on other instances: resolved by address (WebFinger), and remembered.
#[async_trait::async_trait]
pub trait RemoteActors: Send + Sync {
    async fn resolve(&self, address: &FederatedAddress) -> Result<RemoteActor, RemoteActorsError>;
    /// A remote actor this instance already knows (cached), without asking its instance.
    async fn find(&self, uri: &ActorUri) -> Result<Option<RemoteActor>, RemoteActorsError>;
    /// Learn a remote actor from its URI — one that reached this instance first, like a Follow —
    /// and remember it. `NotFound` when the URI does not name an account this instance can address.
    async fn discover(&self, uri: &ActorUri) -> Result<RemoteActor, RemoteActorsError>;
}

#[derive(Debug, thiserror::Error)]
pub enum RemoteActorsError {
    #[error("no such remote account")]
    NotFound,
    #[error("the peer's address is not allowed: {0}")]
    Refused(String),
    /// The account's instance failed to answer, or answered something no instance would.
    #[error("the account's instance did not answer: {0}")]
    Unavailable(String),
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

/// What an access token says: whose it is, the session it belongs to, and when the account last
/// typed its password on that session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bearer {
    pub user: UserId,
    pub session: SessionId,
    pub authenticated_at: OffsetDateTime,
}

/// How recent a password a sensitive action takes: revoking a device, signing out the others,
/// turning the second factor on, clearing the history backup, giving a member a reset link.
pub const RECENT_SIGN_IN: Duration = Duration::minutes(10);

impl Bearer {
    /// The password was typed within [`RECENT_SIGN_IN`]: a renewal or a silent sign-in since
    /// doesn't count, only the password.
    pub fn signed_in_recently(&self, now: OffsetDateTime) -> bool {
        now - self.authenticated_at <= RECENT_SIGN_IN
    }
}

/// Checks the access tokens this instance issued, by their signature and expiry alone: whether
/// their session still lives is asked of the sessions.
pub trait TokenVerifier: Send + Sync {
    fn verify(&self, token: &str) -> Result<Bearer, TokenError>;
}

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("invalid or expired access token")]
    Invalid,
    #[error("the token's subject is not a user id")]
    BadSubject,
    #[error("the token's session has ended")]
    SessionEnded,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

/// Who made a request: an account of this instance, by its bearer token, or another instance,
/// by an HTTP Signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requester {
    User(UserId),
    Peer(ActorUri),
}

/// A request as its HTTP Signature covers it.
#[derive(Debug, Clone)]
pub struct SignedRequest {
    /// Lower-case, as signed: `post`.
    pub method: String,
    /// Path and query.
    pub target: String,
    pub headers: Vec<(String, String)>,
    /// The body as received, when the request has one: the signature must then cover a
    /// `Digest` of it.
    pub body: Option<Vec<u8>>,
}

/// Checks the HTTP Signature of a request another instance sent, and names the actor whose
/// key signed it.
#[async_trait::async_trait]
pub trait SignatureVerifier: Send + Sync {
    async fn verify(&self, request: &SignedRequest) -> Result<ActorUri, SignatureError>;
}

/// Malformed is the peer's mistake; refused, a signature that does not hold.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("{0}")]
    Malformed(String),
    #[error("{0}")]
    Refused(String),
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}
