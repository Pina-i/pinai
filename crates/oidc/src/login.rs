use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    extract::State,
    response::{IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use base64ct::{Base64UrlUnpadded, Encoding};
use rand::RngCore;
use serde::Deserialize;

use idp_db::repos::{auth_codes, users};

use crate::{
    cookies::{build_session_cookie, urlencoded},
    AppState, OidcError,
};

/// Form fields submitted by the login form (POST /login).
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
    // OIDC params passed through as hidden fields
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
}

/// POST /login — validate credentials, issue authorization code, and set session cookie.
#[tracing::instrument(skip_all, fields(username = %form.username, client_id = %form.client_id))]
pub async fn post_login(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<LoginForm>,
) -> Result<Response, OidcError> {
    // 1. Look up the user — redirect back on not found (don't leak whether username exists)
    let user = match users::find_by_username(&state.pool, &form.username)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
    {
        Some(u) => u,
        None => {
            tracing::warn!("login failed: unknown username");
            return Ok(login_error_redirect(&state.config.frontend_url, &form, "Invalid username or password"));
        }
    };

    // 2. Verify Argon2id password hash (constant-time)
    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|_| OidcError::server_error("Failed to parse password hash"))?;

    if Argon2::default()
        .verify_password(form.password.as_bytes(), &parsed_hash)
        .is_err()
    {
        tracing::warn!("login failed: incorrect password");
        return Ok(login_error_redirect(&state.config.frontend_url, &form, "Invalid username or password"));
    }

    // 3. Validate the code_challenge_method (defense in depth)
    if form.code_challenge_method != "S256" {
        return Ok(login_error_redirect(&state.config.frontend_url, &form, "Invalid request"));
    }

    // 4. Generate a random authorization code (32 bytes → 43 base64url chars)
    let mut code_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut code_bytes);
    let code = Base64UrlUnpadded::encode_string(&code_bytes);

    // 5. Store the code in the database
    auth_codes::create_code(
        &state.pool,
        &code,
        &form.client_id,
        user.id,
        &form.redirect_uri,
        &form.code_challenge,
        &form.code_challenge_method,
        &form.scope,
        form.nonce.as_deref(),
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    tracing::debug!(user_id = %user.id, "auth code stored");

    // 6. Set the session cookie (HttpOnly, SameSite=Lax, 30-day max-age)
    let secure = !state.config.domain.starts_with("localhost")
        && !state.config.domain.starts_with("127.");
    let updated_jar = jar.add(build_session_cookie(user.id, secure));

    tracing::info!(user_id = %user.id, "login successful, auth code issued");

    // 7. Redirect back to the client with code + state
    let redirect_url = format!(
        "{}?code={}&state={}",
        form.redirect_uri,
        urlencoded(&code),
        urlencoded(&form.state),
    );

    Ok((updated_jar, Redirect::to(&redirect_url)).into_response())
}

/// Build a redirect back to the web-client login page with an error message in the query string.
/// Used when authentication fails so the browser returns to the login form instead of showing
/// a raw JSON error body.
fn login_error_redirect(frontend_url: &str, form: &LoginForm, error: &str) -> Response {
    let mut query = format!(
        "client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method={}&error={}",
        urlencoded(&form.client_id),
        urlencoded(&form.redirect_uri),
        urlencoded(&form.scope),
        urlencoded(&form.state),
        urlencoded(&form.code_challenge),
        urlencoded(&form.code_challenge_method),
        urlencoded(error),
    );
    if let Some(n) = &form.nonce {
        query.push_str(&format!("&nonce={}", urlencoded(n)));
    }
    Redirect::to(&format!("{}/login?{}", frontend_url, query)).into_response()
}
