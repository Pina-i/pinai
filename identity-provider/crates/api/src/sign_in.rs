//! OpenID Connect sign-in: `/authorize`, the login page and its form, `/token`, `/logout`, and
//! the documents a client discovers them by — see identity-provider/specs/auth.md § 1.

use std::sync::Arc;

use application::auth::{
    Authorize, AuthorizeCommand, Authorized, ExchangeCode, LogIn, LogOut, LoginOutcome,
    TokenCommand,
};
use axum::extract::{Query, State};
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Form, Json};
use axum_extra::extract::SignedCookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use domain::UserId;
use domain::auth::{AuthError, AuthorizationRequest, desktop_client};
use domain::identity::InstanceOrigin;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::pages::{
    Appearance, Carried, LoginPage, SIGNED_OUT, SameOrigin, SignInPages, cancel, carried, expired,
    login_alert, login_note, render, to,
};
use crate::{ApiError, RateLimiter};

pub const SESSION_COOKIE: &str = "idp_session";

/// Password guesses, per email: a burst, then one a minute.
#[derive(Clone)]
pub struct LoginAttempts(pub Arc<RateLimiter>);

impl LoginAttempts {
    pub fn new() -> Self {
        Self(Arc::new(RateLimiter::new(10, 1.0 / 60.0)))
    }
}

impl Default for LoginAttempts {
    fn default() -> Self {
        Self::new()
    }
}

/// The instance's public keys, as `/.well-known/jwks.json` serves them.
#[derive(Debug, Clone)]
pub struct Jwks(pub Arc<serde_json::Value>);

/// The account a browser signed in as, for 30 days: its id in a cookie signed with the
/// instance's session key.
pub(crate) fn session_cookie(user: UserId, secure: bool) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, user.to_string()))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(time::Duration::days(30))
        .secure(secure)
        .build()
}

fn session_of(jar: &SignedCookieJar) -> Option<UserId> {
    let cookie = jar.get(SESSION_COOKIE)?;
    uuid::Uuid::parse_str(cookie.value()).ok().map(UserId::from)
}

/// Percent-encodes every byte but RFC 3986's unreserved characters.
fn encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

pub(crate) fn url_with(base: &str, pairs: &[(&str, &str)]) -> String {
    let query: Vec<String> = pairs
        .iter()
        .map(|(key, value)| format!("{key}={}", encode(value)))
        .collect();
    format!("{base}?{}", query.join("&"))
}

/// The request's parameters; `extra` goes before the nonce.
pub(crate) fn carrying<'a>(
    request: &'a AuthorizationRequest,
    extra: &[(&'a str, &'a str)],
) -> Vec<(&'a str, &'a str)> {
    let mut pairs = vec![
        ("client_id", request.client.as_str()),
        ("redirect_uri", request.redirect_uri.as_str()),
        ("scope", request.scope.as_str()),
        ("state", request.state.as_str()),
        ("code_challenge", request.challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    pairs.extend_from_slice(extra);
    if let Some(nonce) = &request.nonce {
        pairs.push(("nonce", nonce));
    }
    pairs
}

pub(crate) fn back_with_code(request: &AuthorizationRequest, code: &str) -> Redirect {
    Redirect::to(&url_with(
        &request.redirect_uri,
        &[("code", code), ("state", &request.state)],
    ))
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
    nonce: Option<String>,
    /// How the client is painted, for the sign-in pages to match.
    theme: Option<String>,
    motif: Option<String>,
}

fn authorize_error(error: AuthError) -> ApiError {
    match error {
        AuthError::UnsupportedResponseType => ApiError::bad_request("response_type must be 'code'"),
        AuthError::BadChallengeMethod => {
            ApiError::bad_request("code_challenge_method must be 'S256'")
        }
        AuthError::UnknownClient => ApiError::invalid_client("Unknown client_id"),
        AuthError::UnregisteredRedirect => {
            ApiError::bad_request("redirect_uri is not registered for this client")
        }
        other => ApiError::internal(anyhow::Error::from(other)),
    }
}

/// `GET /authorize` — a browser signed in already goes straight back with a code; any other
/// goes to the login page, carrying the request.
pub async fn authorize(
    State(authorize): State<Arc<Authorize>>,
    State(pages): State<SignInPages>,
    jar: SignedCookieJar,
    Query(params): Query<AuthorizeParams>,
) -> Result<Response, ApiError> {
    let appearance = Appearance::parse(params.theme.as_deref(), params.motif.as_deref());
    let (redirect_uri, state) = (params.redirect_uri.clone(), params.state.clone());
    let command = AuthorizeCommand {
        response_type: params.response_type,
        client_id: params.client_id,
        redirect_uri: params.redirect_uri,
        scope: params.scope,
        state: params.state,
        code_challenge: params.code_challenge,
        code_challenge_method: params.code_challenge_method,
        nonce: params.nonce,
    };
    let authorized = match authorize
        .execute(command, session_of(&jar), OffsetDateTime::now_utc())
        .await
    {
        Ok(authorized) => authorized,
        Err(error @ (AuthError::UnknownClient | AuthError::UnregisteredRedirect)) => {
            return pages.misdirected(error, appearance).await;
        }
        // Raised only once the client and its redirect_uri are known good.
        Err(error @ (AuthError::UnsupportedResponseType | AuthError::BadChallengeMethod)) => {
            let code = match error {
                AuthError::UnsupportedResponseType => "unsupported_response_type",
                _ => "invalid_request",
            };
            let description = authorize_error(error).description().to_owned();
            return Ok(Redirect::to(&url_with(
                &redirect_uri,
                &[
                    ("error", code),
                    ("error_description", &description),
                    ("state", &state),
                ],
            ))
            .into_response());
        }
        Err(error) => return Err(authorize_error(error)),
    };
    Ok(match authorized {
        Authorized::Code { request, code } => {
            back_with_code(&request, code.as_str()).into_response()
        }
        Authorized::SignIn(request) => to("/login", &carried(&request, appearance, &[])),
    })
}

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    /// `register` for the sign-up tab.
    tab: Option<String>,
    error: Option<String>,
    notice: Option<String>,
    #[serde(flatten)]
    carried: Carried,
}

/// `GET /login` — Sign in or Register, for the request carried. A link that carries none, or a
/// broken one, is told it has expired.
pub async fn login_page(
    State(pages): State<SignInPages>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, ApiError> {
    let appearance = query.carried.appearance();
    let Some(request) = query.carried.request() else {
        let notice = expired(query.error.as_deref());
        return pages
            .notice(StatusCode::BAD_REQUEST, notice, appearance)
            .await;
    };
    let client = match pages.show.request(&request).await {
        Ok(client) => client,
        Err(error) => return pages.misdirected(error, appearance).await,
    };
    let register = query.tab.as_deref() == Some("register");
    let (alert, bad) = match query.error.as_deref().and_then(login_alert) {
        Some((alert, field)) => (Some(alert), field),
        None => (None, ""),
    };
    let pairs = carried(&request, appearance, &[]);
    let mut on_register = pairs.clone();
    on_register.push(("tab", "register"));
    let host = pages.host();
    let app_host = client.id.authority();
    let page = LoginPage {
        frame: pages.frame(appearance).await?,
        back: cancel(&request),
        app_name: client.name,
        app_host: (app_host != host).then_some(app_host),
        register,
        sign_in_href: url_with("/login", &pairs),
        register_href: url_with("/login", &on_register),
        alert,
        note: query.notice.as_deref().and_then(login_note),
        bad,
        email_host: host
            .rsplit_once(':')
            .map_or(host.as_str(), |(name, _)| name)
            .to_owned(),
        carried: pairs,
    };
    Ok(render(StatusCode::OK, &page, Some(&request.redirect_uri)))
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    email: String,
    password: String,
    #[serde(flatten)]
    carried: Carried,
}

/// `POST /login` — the login form: back to the client with a code, or on to confirming the
/// address or to the authenticator's code.
pub async fn log_in(
    _: SameOrigin,
    State(log_in): State<Arc<LogIn>>,
    State(pages): State<SignInPages>,
    State(LoginAttempts(attempts)): State<LoginAttempts>,
    jar: SignedCookieJar,
    Form(form): Form<LoginForm>,
) -> Result<Response, ApiError> {
    let appearance = form.carried.appearance();
    let Some(request) = form.carried.request() else {
        return Ok(to("/login", &appearance.pairs()));
    };
    let again = |error: &str| {
        to(
            "/login",
            &carried(&request, appearance, &[("error", error)]),
        )
    };
    // Counted per address in any case, known or not: which is limited never tells who exists.
    if !attempts.allow(&form.email.to_lowercase()) {
        return Ok(again("rate_limited"));
    }
    let outcome = match log_in
        .execute(
            &form.email,
            &form.password,
            &request,
            OffsetDateTime::now_utc(),
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(error @ (AuthError::UnknownClient | AuthError::UnregisteredRedirect)) => {
            return pages.misdirected(error, appearance).await;
        }
        Err(other) => return Err(authorize_error(other)),
    };
    Ok(match outcome {
        LoginOutcome::Refused => again("invalid_credentials"),
        LoginOutcome::Unverified { user, email } => {
            let user = user.to_string();
            let pending = [
                ("pending_user_id", user.as_str()),
                ("pending_email", email.as_str()),
                ("notice", "confirm_email"),
            ];
            to("/verify-email", &carried(&request, appearance, &pending))
        }
        LoginOutcome::SecondFactor(ticket) => {
            let ticket = ticket.to_string();
            let mut pairs = vec![("ticket", ticket.as_str())];
            pairs.extend(appearance.pairs());
            to("/login/totp", &pairs)
        }
        LoginOutcome::SignedIn { user, code } => (
            jar.add(session_cookie(user, pages.secure_cookies)),
            back_with_code(&request, code.as_str()),
        )
            .into_response(),
    })
}

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String,
    code_verifier: String,
}

#[derive(Serialize)]
pub struct TokenBody {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    id_token: String,
}

/// RFC 6749 § 5.1: a token answer — and its refusal — is never stored on the way.
fn uncached() -> [(HeaderName, HeaderValue); 2] {
    [
        (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        (header::PRAGMA, HeaderValue::from_static("no-cache")),
    ]
}

fn token_error(error: AuthError) -> ApiError {
    let [(cache, no_store), (pragma, no_cache)] = uncached();
    token_refusal(error)
        .with_header(cache, no_store)
        .with_header(pragma, no_cache)
}

fn token_refusal(error: AuthError) -> ApiError {
    let refused =
        |description: &str| ApiError::new(StatusCode::BAD_REQUEST, "invalid_grant", description);
    match error {
        AuthError::UnsupportedGrantType => ApiError::new(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "grant_type must be 'authorization_code'",
        ),
        AuthError::UnknownClient => ApiError::invalid_client("Unknown client_id"),
        AuthError::RedirectMismatch => refused("redirect_uri mismatch"),
        AuthError::CodeUnusable => {
            refused("Authorization code is invalid, expired, or already used")
        }
        AuthError::ClientMismatch => refused("client_id mismatch"),
        AuthError::VerifierMismatch => refused("code_verifier does not match code_challenge"),
        other => ApiError::internal(anyhow::Error::from(other)),
    }
}

/// `POST /token` — the code a sign-in ended in, for the account's tokens.
pub async fn token(
    State(exchange): State<Arc<ExchangeCode>>,
    Form(form): Form<TokenForm>,
) -> Result<impl IntoResponse, ApiError> {
    let command = TokenCommand {
        grant_type: form.grant_type,
        code: form.code,
        redirect_uri: form.redirect_uri,
        client_id: form.client_id,
        code_verifier: form.code_verifier,
    };
    let tokens = exchange
        .execute(command, OffsetDateTime::now_utc())
        .await
        .map_err(token_error)?;
    Ok((
        uncached(),
        Json(TokenBody {
            access_token: tokens.access_token,
            token_type: "Bearer",
            expires_in: tokens.expires_in.whole_seconds(),
            id_token: tokens.id_token,
        }),
    ))
}

#[derive(Debug, Deserialize)]
pub struct LogoutParams {
    client_id: Option<String>,
    post_logout_redirect_uri: Option<String>,
}

/// `GET /logout` — the session cookie goes, and the browser with it.
pub async fn log_out(
    State(log_out): State<Arc<LogOut>>,
    jar: SignedCookieJar,
    Query(params): Query<LogoutParams>,
) -> Result<impl IntoResponse, ApiError> {
    let to = log_out
        .execute(
            params.client_id.as_deref(),
            params.post_logout_redirect_uri.as_deref(),
        )
        .await
        .map_err(|e| ApiError::internal(anyhow::Error::from(e)))?
        .unwrap_or_else(|| "/signed-out".to_owned());
    Ok((
        jar.remove(Cookie::build((SESSION_COOKIE, "")).path("/").build()),
        Redirect::to(&to),
    ))
}

/// `GET /signed-out` — where `/logout` lands when it may not go back to the client.
pub async fn signed_out(State(pages): State<SignInPages>) -> Result<Response, ApiError> {
    pages
        .notice(StatusCode::OK, SIGNED_OUT, Appearance::default())
        .await
}

/// `GET /.well-known/openid-configuration` — OpenID Connect Discovery 1.0 § 4.
pub async fn discovery(State(origin): State<InstanceOrigin>) -> Json<serde_json::Value> {
    let base = origin.base_url();
    Json(serde_json::json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "userinfo_endpoint": format!("{base}/userinfo"),
        "jwks_uri": format!("{base}/.well-known/jwks.json"),
        "scopes_supported": ["openid", "profile", "email"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "claims_supported": [
            "sub", "iss", "aud", "client_id", "exp", "iat", "email", "preferred_username", "nonce"
        ],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "client_id_metadata_document_supported": true,
    }))
}

/// `GET /clients/desktop.json` — the official desktop app's client document, as this instance
/// describes it.
pub async fn desktop_document(State(origin): State<InstanceOrigin>) -> impl IntoResponse {
    (
        [(header::CACHE_CONTROL, "public, max-age=86400")],
        Json(desktop_client(&origin).document()),
    )
}

/// `GET /.well-known/jwks.json` — the keys a token this instance signed verifies against.
pub async fn jwks(State(Jwks(keys)): State<Jwks>) -> Json<serde_json::Value> {
    Json((*keys).clone())
}

#[cfg(test)]
mod tests;
