//! Who a request is from: a bearer token names a local user, an HTTP Signature another instance.

use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use domain::UserId;
use domain::identity::{
    ActorUri, Requester, SignatureError, SignatureVerifier, SignedRequest, TokenError,
    TokenVerifier,
};

use crate::ApiError;

/// The user a request's bearer token belongs to.
pub struct Authenticated(pub UserId);

impl<S> FromRequestParts<S> for Authenticated
where
    Arc<dyn TokenVerifier>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| ApiError::invalid_client("Missing or invalid Authorization header"))?;
        let user = Arc::<dyn TokenVerifier>::from_ref(state).verify(token)?;
        Ok(Self(user))
    }
}

impl From<TokenError> for ApiError {
    fn from(error: TokenError) -> Self {
        match error {
            TokenError::Invalid => ApiError::invalid_client("Invalid or expired access token"),
            TokenError::BadSubject => ApiError::invalid_client("Invalid subject claim"),
        }
    }
}

/// A local user by bearer token, or else another instance by its HTTP Signature — never both:
/// a token present decides.
pub struct Caller(pub Requester);

impl<S> FromRequestParts<S> for Caller
where
    Arc<dyn TokenVerifier>: FromRef<S>,
    Arc<dyn SignatureVerifier>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        if parts.headers.contains_key(AUTHORIZATION) {
            let Authenticated(user) = Authenticated::from_request_parts(parts, state).await?;
            return Ok(Self(Requester::User(user)));
        }
        let SignedPeer(peer) = SignedPeer::from_request_parts(parts, state).await?;
        Ok(Self(Requester::Peer(peer)))
    }
}

/// Another instance, by the HTTP Signature over the request: the actor its key belongs to.
pub struct SignedPeer(pub ActorUri);

impl<S> FromRequestParts<S> for SignedPeer
where
    Arc<dyn SignatureVerifier>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let request = SignedRequest {
            method: parts.method.as_str().to_lowercase(),
            target: parts
                .uri
                .path_and_query()
                .map_or_else(|| parts.uri.path().to_owned(), |target| target.to_string()),
            headers: parts
                .headers
                .iter()
                .filter_map(|(name, value)| {
                    Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
                })
                .collect(),
        };
        let peer = Arc::<dyn SignatureVerifier>::from_ref(state)
            .verify(&request)
            .await?;
        Ok(Self(peer))
    }
}

impl From<SignatureError> for ApiError {
    fn from(error: SignatureError) -> Self {
        match error {
            SignatureError::Malformed(reason) => ApiError::bad_request(reason),
            SignatureError::Refused(reason) => {
                ApiError::new(axum::http::StatusCode::FORBIDDEN, "access_denied", reason)
            }
            SignatureError::Unexpected(e) => ApiError::internal(e),
        }
    }
}
