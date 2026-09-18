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
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use idp_db::{
    models::User,
    repos::{clients, email_verification_codes, users},
};

use crate::{cookies::urlencoded, email_otp, AppState, OidcError};

/// 10-minute OTP lifetime — matches OIDC auth-code TTL.
pub const SIGNUP_OTP_TTL_SECS: i64 = 600;

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
    pub display_name: String,
    pub address: String,
    pub email: String,
    pub email_verified: bool,
    /// Identifier the client must echo back to `POST /verify-email-and-login`.
    pub pending_user_id: String,
}

/// POST /register — create a new user account and dispatch the signup OTP.
/// Returns 201 with `email_verified: false`; no session is established until
/// the caller completes verification via `/verify-email-and-login`.
#[tracing::instrument(skip_all, fields(username = %body.username, email = %body.email))]
pub async fn post_register(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), OidcError> {
    if body.username.is_empty() || body.email.is_empty() || body.password.is_empty() {
        return Err(OidcError::invalid_request(
            "username, email, and password are required",
        ));
    }
    if body.username.len() < 3 {
        return Err(OidcError::invalid_request(
            "username must be at least 3 characters",
        ));
    }
    if body.password.len() < 8 {
        return Err(OidcError::invalid_request(
            "password must be at least 8 characters",
        ));
    }

    if users::find_by_email(&state.pool, &body.email)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .is_some()
    {
        return Err(OidcError::invalid_request("Email already registered"));
    }

    let user = create_user_record(&state, &body.username, &body.email, &body.password).await?;

    issue_signup_otp(&state, &user).await?;

    let address = user.federated_address(&state.config.domain);
    tracing::info!(
        user_id = %user.id,
        address = %address,
        "user registered (pending email verification)"
    );

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            id: user.id.to_string(),
            pending_user_id: user.id.to_string(),
            address,
            username: user.username.clone(),
            display_name: user.display_name.clone().unwrap_or_default(),
            email: user.email.clone(),
            email_verified: false,
        }),
    ))
}

/// POST /register-and-login — register and immediately redirect to the
/// email-verification page. OIDC params are carried through the redirect so
/// the subsequent `/verify-email-and-login` POST can issue the auth code
/// without the client re-driving the flow.
#[tracing::instrument(skip_all, fields(username = %form.username, client_id = %form.client_id))]
pub async fn post_register_and_login(
    State(state): State<AppState>,
    Form(form): Form<RegisterAndLoginForm>,
) -> Result<Response, OidcError> {
    if form.username.len() < 3 {
        return Ok(register_error_redirect(
            &state.config.frontend_url,
            &form,
            "Username must be at least 3 characters",
        ));
    }
    if form.password.len() < 8 {
        return Ok(register_error_redirect(
            &state.config.frontend_url,
            &form,
            "Password must be at least 8 characters",
        ));
    }

    if users::find_by_email(&state.pool, &form.email)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .is_some()
    {
        return Ok(register_error_redirect(
            &state.config.frontend_url,
            &form,
            "Email already registered",
        ));
    }

    // Validate client + redirect_uri up front so we don't waste an OTP send
    // on a request the verify step would reject anyway.
    let client = clients::find_client_by_id(&state.pool, &form.client_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::invalid_client("Unknown client_id"))?;
    if !client.redirect_uris.contains(&form.redirect_uri) {
        return Err(OidcError::invalid_request("redirect_uri is not registered"));
    }

    let user = create_user_record(&state, &form.username, &form.email, &form.password).await?;

    issue_signup_otp(&state, &user).await?;

    tracing::info!(
        user_id = %user.id,
        "user registered (register-and-login, awaiting verification)"
    );

    Ok(Redirect::to(&verify_email_redirect_url(
        &state.config.frontend_url,
        user.id,
        &user.email,
        &form,
    ))
    .into_response())
}

/// Generate, persist, and email a 6-digit OTP for the given user.
pub async fn issue_signup_otp(state: &AppState, user: &User) -> Result<(), OidcError> {
    let code = email_otp::generate_numeric_otp(email_otp::OTP_LEN);
    let code_hash = email_otp::hash(&code, &state.email_otp_pepper);
    let expires_at = OffsetDateTime::now_utc() + Duration::seconds(SIGNUP_OTP_TTL_SECS);

    email_verification_codes::insert(&state.pool, user.id, &code_hash, expires_at)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let display_name = user
        .display_name
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(&user.username);

    state
        .email
        .send_signup_otp(&user.email, display_name, &code)
        .await
        .map_err(|e| OidcError::server_error(format!("email send failed: {e}")))?;

    tracing::info!(user_id = %user.id, ttl_secs = SIGNUP_OTP_TTL_SECS, "signup OTP dispatched");
    Ok(())
}

/// Argon2id-hash the password and insert the user row with federation URIs.
async fn create_user_record(
    state: &AppState,
    raw_username: &str,
    email: &str,
    password: &str,
) -> Result<User, OidcError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4, None)
            .map_err(|_| OidcError::server_error("Failed to build Argon2 params"))?,
    );
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| OidcError::server_error("Failed to hash password"))?
        .to_string();

    let display_name = raw_username;
    let username = format!("{}_{}", display_name, nanoid::nanoid!(5));
    let user_id = Uuid::new_v4();
    let base = state.config.issuer();
    let actor_uri = format!("{}/users/{}", base, username);
    let inbox_url = format!("{}/users/{}/inbox", base, username);
    let outbox_url = format!("{}/users/{}/outbox", base, username);

    users::create_user_with_id(
        &state.pool,
        user_id,
        &username,
        display_name,
        email,
        &password_hash,
        &actor_uri,
        &inbox_url,
        &outbox_url,
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))
}

/// Redirect URL to the web-client's `/verify-email` page, carrying the
/// pending user id, email, and every OIDC param needed to resume the flow.
fn verify_email_redirect_url(
    frontend_url: &str,
    pending_user_id: Uuid,
    pending_email: &str,
    form: &RegisterAndLoginForm,
) -> String {
    let mut query = format!(
        "pending_user_id={}&pending_email={}&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method={}",
        urlencoded(&pending_user_id.to_string()),
        urlencoded(pending_email),
        urlencoded(&form.client_id),
        urlencoded(&form.redirect_uri),
        urlencoded(&form.scope),
        urlencoded(&form.state),
        urlencoded(&form.code_challenge),
        urlencoded(&form.code_challenge_method),
    );
    if let Some(n) = &form.nonce {
        query.push_str(&format!("&nonce={}", urlencoded(n)));
    }
    format!("{}/verify-email?{}", frontend_url, query)
}

/// Redirect back to the web-client login page (register tab) with an error.
fn register_error_redirect(
    frontend_url: &str,
    form: &RegisterAndLoginForm,
    error: &str,
) -> Response {
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
