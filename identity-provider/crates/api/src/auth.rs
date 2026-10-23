//! Who a request is from: a bearer token names a local user, an HTTP Signature another instance.

use std::sync::Arc;

use application::auth::Authenticate;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{FromRef, FromRequest, FromRequestParts, Request};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, Uri};
use domain::UserId;
use domain::identity::{
    ActorUri, Bearer, RECENT_SIGN_IN, Requester, SignatureError, SignatureVerifier, SignedRequest,
    TokenError,
};
use time::OffsetDateTime;

use serde::de::DeserializeOwned;

use crate::ApiError;

/// The user a request's bearer token belongs to, while its session lives.
pub struct Authenticated(pub UserId);

impl<S> FromRequestParts<S> for Authenticated
where
    Arc<Authenticate>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let SignedIn(bearer) = SignedIn::from_request_parts(parts, state).await?;
        Ok(Self(bearer.user))
    }
}

/// The same, with the session the token belongs to: for the routes about that session.
pub struct SignedIn(pub Bearer);

impl<S> FromRequestParts<S> for SignedIn
where
    Arc<Authenticate>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| {
                ApiError::invalid_token("Missing or invalid Authorization header", false)
            })?;
        let bearer = Arc::<Authenticate>::from_ref(state)
            .execute(token, OffsetDateTime::now_utc())
            .await?;
        Ok(Self(bearer))
    }
}

/// The same, for a sensitive action: the account's password typed on this session within
/// [`RECENT_SIGN_IN`].
pub struct RecentlySignedIn(pub Bearer);

impl<S> FromRequestParts<S> for RecentlySignedIn
where
    Arc<Authenticate>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let SignedIn(bearer) = SignedIn::from_request_parts(parts, state).await?;
        if !bearer.signed_in_recently(OffsetDateTime::now_utc()) {
            return Err(ApiError::insufficient_user_authentication(RECENT_SIGN_IN));
        }
        Ok(Self(bearer))
    }
}

impl From<TokenError> for ApiError {
    fn from(error: TokenError) -> Self {
        match error {
            TokenError::Invalid => ApiError::invalid_token("Invalid or expired access token", true),
            TokenError::BadSubject => ApiError::invalid_token("Invalid subject claim", true),
            TokenError::SessionEnded => ApiError::invalid_token("The session has ended", true),
            TokenError::Unexpected(e) => ApiError::internal(e),
        }
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
        let request = signed(&parts.method, &parts.uri, &parts.headers, None);
        let peer = Arc::<dyn SignatureVerifier>::from_ref(state)
            .verify(&request)
            .await?;
        Ok(Self(peer))
    }
}

/// Another instance, by the HTTP Signature over the request and the `Digest` it covers, which
/// the body must match: the actor its key belongs to, and the body as received.
pub struct SignedBody(pub ActorUri, pub Bytes);

impl<S> FromRequest<S> for SignedBody
where
    Arc<dyn SignatureVerifier>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let mut signed = signed(request.method(), request.uri(), request.headers(), None);
        let body = Bytes::from_request(request, state)
            .await
            .map_err(|e| ApiError::new(e.status(), "invalid_request", e.body_text()))?;
        signed.body = Some(body.to_vec());
        let peer = Arc::<dyn SignatureVerifier>::from_ref(state)
            .verify(&signed)
            .await?;
        Ok(Self(peer, body))
    }
}

/// A peer's JSON body, parsed only once its `Digest` is checked.
pub struct SignedJson<T>(pub ActorUri, pub T);

impl<S, T> FromRequest<S> for SignedJson<T>
where
    Arc<dyn SignatureVerifier>: FromRef<S>,
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let SignedBody(peer, body) = SignedBody::from_request(request, state).await?;
        Ok(Self(peer, json(&body)?))
    }
}

/// A local user by bearer token, or else another instance by its HTTP Signature — never both:
/// a token present decides — and the JSON body, a peer's parsed only once its `Digest` is checked.
pub struct CallerJson<T>(pub Requester, pub T);

impl<S, T> FromRequest<S> for CallerJson<T>
where
    Arc<Authenticate>: FromRef<S>,
    Arc<dyn SignatureVerifier>: FromRef<S>,
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        if request.headers().contains_key(AUTHORIZATION) {
            let (mut parts, body) = request.into_parts();
            let Authenticated(user) = Authenticated::from_request_parts(&mut parts, state).await?;
            let Json(body) = Json::<T>::from_request(Request::from_parts(parts, body), state)
                .await
                .map_err(|e| ApiError::new(e.status(), "invalid_request", e.body_text()))?;
            return Ok(Self(Requester::User(user), body));
        }
        let SignedJson(peer, body) = SignedJson::from_request(request, state).await?;
        Ok(Self(Requester::Peer(peer), body))
    }
}

fn json<T: DeserializeOwned>(body: &Bytes) -> Result<T, ApiError> {
    Json::<T>::from_bytes(body)
        .map(|Json(value)| value)
        .map_err(|e| ApiError::new(e.status(), "invalid_request", e.body_text()))
}

/// A request as its HTTP Signature covers it.
fn signed(method: &Method, uri: &Uri, headers: &HeaderMap, body: Option<Vec<u8>>) -> SignedRequest {
    SignedRequest {
        method: method.as_str().to_lowercase(),
        target: uri
            .path_and_query()
            .map_or_else(|| uri.path().to_owned(), |target| target.to_string()),
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
            })
            .collect(),
        body,
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

#[cfg(test)]
mod tests;
