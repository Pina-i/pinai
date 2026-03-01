use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::SignedCookieJar;
use base64ct::{Base64UrlUnpadded, Encoding};
use rand::RngCore;
use serde::Deserialize;
use uuid::Uuid;

use idp_db::repos::{auth_codes, clients, users};

use crate::{
    cookies::{urlencoded, SESSION_COOKIE_NAME},
    AppState, OidcError,
};

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
}

/// GET /authorize
///
/// Validates the authorization request. If the user already has a valid session
/// cookie, issues an auth code immediately (SSO). Otherwise serves the login form.
#[tracing::instrument(skip_all, fields(
    client_id = %params.client_id,
    redirect_uri = %params.redirect_uri,
    response_type = %params.response_type,
))]
pub async fn get_authorize(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(params): Query<AuthorizeParams>,
) -> Result<Response, OidcError> {
    // 1. Validate response_type
    if params.response_type != "code" {
        return Err(OidcError::invalid_request("response_type must be 'code'"));
    }

    // 2. Validate code_challenge_method (S256 only — plain is rejected)
    if params.code_challenge_method != "S256" {
        return Err(OidcError::invalid_request(
            "code_challenge_method must be 'S256'",
        ));
    }

    // 3. Validate client exists
    let client = clients::find_client_by_id(&state.pool, &params.client_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::invalid_client("Unknown client_id"))?;

    tracing::debug!("client validated");

    // 4. Validate redirect_uri (case-sensitive exact match — RFC 6749 §3.1.2)
    if !client.redirect_uris.contains(&params.redirect_uri) {
        return Err(OidcError::invalid_request(
            "redirect_uri is not registered for this client",
        ));
    }

    // 5. Check for an existing session cookie (SSO — skip login form)
    if let Some(cookie) = jar.get(SESSION_COOKIE_NAME) {
        if let Ok(user_id) = Uuid::parse_str(cookie.value()) {
            if users::find_by_id(&state.pool, user_id)
                .await
                .map_err(|e| OidcError::server_error(e.to_string()))?
                .is_some()
            {
                tracing::debug!(user_id = %user_id, "valid session cookie, issuing code via SSO");

                let code = generate_and_store_code(
                    &state.pool,
                    user_id,
                    &params.client_id,
                    &params.redirect_uri,
                    &params.code_challenge,
                    &params.code_challenge_method,
                    &params.scope,
                    params.nonce.as_deref(),
                )
                .await?;

                tracing::info!(user_id = %user_id, "SSO: auth code issued, redirecting");

                let redirect_url = format!(
                    "{}?code={}&state={}",
                    params.redirect_uri,
                    urlencoded(&code),
                    urlencoded(&params.state),
                );
                return Ok(Redirect::to(&redirect_url).into_response());
            }
        }
    }

    tracing::debug!("no session cookie, redirecting to web-client login page");

    // 6. Redirect to the web-client login page with all OIDC params as query string
    let mut query = format!(
        "client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method={}",
        urlencoded(&params.client_id),
        urlencoded(&params.redirect_uri),
        urlencoded(&params.scope),
        urlencoded(&params.state),
        urlencoded(&params.code_challenge),
        urlencoded(&params.code_challenge_method),
    );
    if let Some(n) = &params.nonce {
        query.push_str(&format!("&nonce={}", urlencoded(n)));
    }

    let login_url = format!("{}/login?{}", state.config.frontend_url, query);
    Ok(Redirect::to(&login_url).into_response())
}

/// Generate a random auth code and persist it in the database.

async fn generate_and_store_code(
    pool: &idp_db::PgPool,
    user_id: Uuid,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    code_challenge_method: &str,
    scope: &str,
    nonce: Option<&str>,
) -> Result<String, OidcError> {
    let mut code_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut code_bytes);
    let code = Base64UrlUnpadded::encode_string(&code_bytes);

    auth_codes::create_code(
        pool,
        &code,
        client_id,
        user_id,
        redirect_uri,
        code_challenge,
        code_challenge_method,
        scope,
        nonce,
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    Ok(code)
}

