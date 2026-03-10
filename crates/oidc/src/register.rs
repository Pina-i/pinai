use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Form, Json,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use idp_db::repos::{auth_codes, clients, users};

use crate::{
    cookies::{build_session_cookie, urlencoded},
    AppState, OidcError,
};

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub id: String,
    pub username: String,
    pub address: String,
    pub email: String,
}

/// POST /register — create a new user account.
#[tracing::instrument(skip_all, fields(username = %body.username, email = %body.email))]
pub async fn post_register(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), OidcError> {
    // 1. Basic validation
    if body.username.is_empty() || body.email.is_empty() || body.password.is_empty() {
        return Err(OidcError::invalid_request("username, email, and password are required"));
    }
    if body.username.len() < 3 {
        return Err(OidcError::invalid_request("username must be at least 3 characters"));
    }
    if body.password.len() < 8 {
        return Err(OidcError::invalid_request("password must be at least 8 characters"));
    }

    // 2. Check for existing username
    if users::find_by_username(&state.pool, &body.username)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .is_some()
    {
        return Err(OidcError::invalid_request("Username already taken"));
    }

    // 3. Check for existing email
    if users::find_by_email(&state.pool, &body.email)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .is_some()
    {
        return Err(OidcError::invalid_request("Email already registered"));
    }

    // 4. Hash password with Argon2id (secure params: m=65536, t=3, p=4)
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4, None)
            .map_err(|_| OidcError::server_error("Failed to build Argon2 params"))?,
    );
    let password_hash = argon2
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|_| OidcError::server_error("Failed to hash password"))?
        .to_string();

    // 5. Derive federation URIs and insert user
    let user_id = uuid::Uuid::new_v4();
    let base = state.config.issuer();
    let slug = format!("{}-{}", body.username, nanoid::nanoid!(5));
    let actor_uri = format!("{}/users/{}", base, slug);
    let inbox_url = format!("{}/users/{}/inbox", base, slug);
    let outbox_url = format!("{}/users/{}/outbox", base, slug);

    let user = users::create_user_with_id(
        &state.pool,
        user_id,
        &body.username,
        &body.email,
        &password_hash,
        &actor_uri,
        &inbox_url,
        &outbox_url,
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    let address = user.federated_address(&state.config.domain);
    tracing::info!(user_id = %user.id, address = %address, "user registered");

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            id: user.id.to_string(),
            address,
            username: user.username,
            email: user.email,
        }),
    ))
}

/// POST /register-and-login — register and immediately start an OIDC flow.
/// Same as /register but also goes through the login flow (for the login page register tab).
#[tracing::instrument(skip_all, fields(username = %form.username, client_id = %form.client_id))]
pub async fn post_register_and_login(
    State(state): State<AppState>,
    jar: axum_extra::extract::cookie::SignedCookieJar,
    Form(form): Form<RegisterAndLoginForm>,
) -> Result<Response, OidcError> {
    // 1. Basic validation — redirect back on user-facing errors
    if form.username.len() < 3 {
        return Ok(register_error_redirect(&state.config.frontend_url, &form, "Username must be at least 3 characters"));
    }
    if form.password.len() < 8 {
        return Ok(register_error_redirect(&state.config.frontend_url, &form, "Password must be at least 8 characters"));
    }

    // 2. Check uniqueness
    if users::find_by_username(&state.pool, &form.username)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .is_some()
    {
        return Ok(register_error_redirect(&state.config.frontend_url, &form, "Username already taken"));
    }
    if users::find_by_email(&state.pool, &form.email)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .is_some()
    {
        return Ok(register_error_redirect(&state.config.frontend_url, &form, "Email already registered"));
    }

    // 3. Validate client + redirect_uri
    let client = clients::find_client_by_id(&state.pool, &form.client_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::invalid_client("Unknown client_id"))?;

    if !client.redirect_uris.contains(&form.redirect_uri) {
        return Err(OidcError::invalid_request("redirect_uri is not registered"));
    }

    // 4. Hash password
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4, None)
            .map_err(|_| OidcError::server_error("Failed to build Argon2 params"))?,
    );
    let password_hash = argon2
        .hash_password(form.password.as_bytes(), &salt)
        .map_err(|_| OidcError::server_error("Failed to hash password"))?
        .to_string();

    // 5. Derive federation URIs and create user
    let user_id = uuid::Uuid::new_v4();
    let base = state.config.issuer();
    let slug = format!("{}-{}", form.username, nanoid::nanoid!(5));
    let actor_uri = format!("{}/users/{}", base, slug);
    let inbox_url = format!("{}/users/{}/inbox", base, slug);
    let outbox_url = format!("{}/users/{}/outbox", base, slug);

    let user = users::create_user_with_id(
        &state.pool,
        user_id,
        &form.username,
        &form.email,
        &password_hash,
        &actor_uri,
        &inbox_url,
        &outbox_url,
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    tracing::info!(user_id = %user.id, username = %user.username, "user registered (register-and-login)");
    tracing::debug!(user_id = %user.id, "issuing auth code for new user");

    // 6. Issue auth code
    let mut code_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut code_bytes);
    let code = Base64UrlUnpadded::encode_string(&code_bytes);

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

    // 7. Set the session cookie
    let secure = !state.config.domain.starts_with("localhost")
        && !state.config.domain.starts_with("127.");
    let updated_jar = jar.add(build_session_cookie(user.id, secure));

    let redirect_url = format!(
        "{}?code={}&state={}",
        form.redirect_uri,
        urlencoded(&code),
        urlencoded(&form.state),
    );
    Ok((updated_jar, Redirect::to(&redirect_url)).into_response())
}

/// Build a redirect back to the web-client login page (register tab) with an error message.
fn register_error_redirect(frontend_url: &str, form: &RegisterAndLoginForm, error: &str) -> Response {
    let mut query = format!(
        "tab=register&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method={}&error={}",
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

#[derive(Debug, serde::Deserialize)]
pub struct RegisterAndLoginForm {
    pub username: String,
    pub email: String,
    pub password: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
}
