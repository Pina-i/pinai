//! Signup email-verification handlers — completes the flow started by
//! `POST /register-and-login`.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::cookie::SignedCookieJar;
use base64ct::{Base64UrlUnpadded, Encoding};
use rand::RngCore;
use serde::Deserialize;
use uuid::Uuid;

use idp_db::repos::{auth_codes, clients, email_verification_codes, users};

use crate::{
    cookies::{build_session_cookie, urlencoded},
    email_otp,
    register::{issue_signup_otp, SIGNUP_OTP_TTL_SECS},
    AppState, OidcError,
};

/// Hard cap on attempts per code row. After this the user must resend.
pub const MAX_OTP_ATTEMPTS: i32 = 5;
/// Resend rate limit — at most this many codes per user per window.
pub const RESEND_MAX_PER_WINDOW: i64 = 5;
/// Resend window. Matches the OTP TTL so a fresh signup always has budget.
pub const RESEND_WINDOW_SECS: i64 = SIGNUP_OTP_TTL_SECS;

#[derive(Debug, Deserialize)]
pub struct VerifyEmailForm {
    pub pending_user_id: Uuid,
    /// Surfaced to the user on the page; carried through so error redirects
    /// keep the email pill populated.
    #[serde(default)]
    pub pending_email: String,
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
}

/// POST /verify-email-and-login — consume the signup OTP, flip
/// `email_verified_at`, issue an OIDC auth code, set the session cookie, and
/// redirect to the OIDC `redirect_uri`. Mirrors `/login`'s success shape so
/// the client sees one consistent "you're in" moment.
#[tracing::instrument(skip_all, fields(pending_user_id = %form.pending_user_id, client_id = %form.client_id))]
pub async fn post_verify_email_and_login(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<VerifyEmailForm>,
) -> Result<Response, OidcError> {
    if form.code.len() != email_otp::OTP_LEN || !form.code.chars().all(|c| c.is_ascii_digit()) {
        return Ok(verify_error_redirect(
            &state.config.frontend_url,
            &form,
            "Enter the 6-digit code",
        ));
    }

    let user = users::find_by_id(&state.pool, form.pending_user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::invalid_request("Unknown user"))?;

    if user.email_verified_at.is_some() {
        // Idempotent path: link already consumed. Don't burn another code —
        // bounce them to the login page and let SSO take over.
        return Ok(Redirect::to(&format!("{}/login", state.config.frontend_url)).into_response());
    }

    let Some(code_row) = email_verification_codes::find_active_for_user(&state.pool, user.id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
    else {
        return Ok(verify_error_redirect(
            &state.config.frontend_url,
            &form,
            "Code expired — request a new one",
        ));
    };

    if code_row.attempts >= MAX_OTP_ATTEMPTS {
        return Ok(verify_error_redirect(
            &state.config.frontend_url,
            &form,
            "Too many attempts — request a new code",
        ));
    }

    if !email_otp::verify(&form.code, &code_row.code_hash, &state.email_otp_pepper) {
        let new_attempts = email_verification_codes::increment_attempts(&state.pool, code_row.id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;
        let remaining = (MAX_OTP_ATTEMPTS - new_attempts).max(0);
        let msg = if remaining == 0 {
            "Too many attempts — request a new code".to_string()
        } else {
            format!("Incorrect code — {} attempt(s) left", remaining)
        };
        return Ok(verify_error_redirect(
            &state.config.frontend_url,
            &form,
            &msg,
        ));
    }

    // Guard PKCE method here too so the verify path can't sneak in `plain`.
    if form.code_challenge_method != "S256" {
        return Err(OidcError::invalid_request(
            "code_challenge_method must be S256",
        ));
    }
    let client = clients::find_client_by_id(&state.pool, &form.client_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::invalid_client("Unknown client_id"))?;
    if !client.redirect_uris.contains(&form.redirect_uri) {
        return Err(OidcError::invalid_request("redirect_uri is not registered"));
    }

    let flipped =
        email_verification_codes::consume_and_verify_user(&state.pool, code_row.id, user.id)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;
    if !flipped {
        // Race: another request consumed this code between fetch and update.
        return Ok(verify_error_redirect(
            &state.config.frontend_url,
            &form,
            "Code already used — try logging in",
        ));
    }

    let mut code_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut code_bytes);
    let auth_code = Base64UrlUnpadded::encode_string(&code_bytes);

    auth_codes::create_code(
        &state.pool,
        &auth_code,
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

    let updated_jar = jar.add(build_session_cookie(user.id, state.config.secure_cookies()));

    tracing::info!(user_id = %user.id, "email verified, login completed");

    let redirect_url = format!(
        "{}?code={}&state={}",
        form.redirect_uri,
        urlencoded(&auth_code),
        urlencoded(&form.state),
    );
    Ok((updated_jar, Redirect::to(&redirect_url)).into_response())
}

fn verify_error_redirect(frontend_url: &str, form: &VerifyEmailForm, error: &str) -> Response {
    let mut query = format!(
        "pending_user_id={}&pending_email={}&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method={}&error={}",
        urlencoded(&form.pending_user_id.to_string()),
        urlencoded(&form.pending_email),
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
    Redirect::to(&format!("{}/verify-email?{}", frontend_url, query)).into_response()
}

/// POST /verify-email/resend — issue a fresh OTP for a still-unverified user.
/// Rate-limited per user to deter mailbox flooding.
#[derive(Debug, Deserialize)]
pub struct ResendRequest {
    pub pending_user_id: Uuid,
}

#[tracing::instrument(skip_all, fields(pending_user_id = %body.pending_user_id))]
pub async fn post_resend_verification(
    State(state): State<AppState>,
    Form(body): Form<ResendRequest>,
) -> Result<StatusCode, OidcError> {
    let user = users::find_by_id(&state.pool, body.pending_user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::not_found("Unknown user"))?;

    if user.email_verified_at.is_some() {
        // Tells the client to redirect to login.
        return Ok(StatusCode::GONE);
    }

    let recent =
        email_verification_codes::count_recent_for_user(&state.pool, user.id, RESEND_WINDOW_SECS)
            .await
            .map_err(|e| OidcError::server_error(e.to_string()))?;

    if recent >= RESEND_MAX_PER_WINDOW {
        tracing::warn!(user_id = %user.id, recent, "resend rate-limited");
        return Ok(StatusCode::TOO_MANY_REQUESTS);
    }

    issue_signup_otp(&state, &user).await?;
    Ok(StatusCode::NO_CONTENT)
}
