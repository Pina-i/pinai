//! TOTP 2FA handlers — login challenge + enrollment + disable + recovery.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Form, Json,
};
use axum_extra::extract::cookie::SignedCookieJar;
use base64ct::{Base64UrlUnpadded, Encoding};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use idp_db::repos::{
    auth_codes, pending_totp_enrollments, pending_totp_logins, recovery_codes, users,
};
use idp_federation::auth::require_auth;
use idp_totp::{
    generate_recovery_codes, generate_secret, hash_recovery_code, provisioning_url,
    secret_to_base32, verify_code, verify_recovery_code,
};

use crate::{
    cookies::{build_session_cookie, urlencoded},
    AppState, OidcError,
};

/// Max attempts per challenge ticket before the user must log in again.
const MAX_LOGIN_TOTP_ATTEMPTS: i32 = 5;

// ─── POST /login/totp ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TotpChallengeForm {
    pub ticket: Uuid,
    /// 6-digit TOTP from the authenticator app, OR
    pub code: Option<String>,
    /// `XXXXX-XXXXX` recovery code typed by a user who lost their device.
    pub recovery_code: Option<String>,
}

/// Consume the TOTP challenge ticket created by `/login` and, on success,
/// issue the OIDC auth code + session that `/login` would normally have issued.
/// All recoverable failures redirect back to `/login/totp` with an `error`
/// param so the form can re-render inline.
#[tracing::instrument(skip_all, fields(ticket = %form.ticket))]
pub async fn post_login_totp(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Form(form): Form<TotpChallengeForm>,
) -> Result<Response, OidcError> {
    let Some(ticket) = pending_totp_logins::find_active(&state.pool, form.ticket)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
    else {
        return Ok(Redirect::to(&format!(
            "{}/login?error={}",
            state.config.frontend_url,
            urlencoded("Sign-in expired — try again")
        ))
        .into_response());
    };

    if ticket.attempts >= MAX_LOGIN_TOTP_ATTEMPTS {
        return Ok(Redirect::to(&format!(
            "{}/login?error={}",
            state.config.frontend_url,
            urlencoded("Too many attempts — sign in again")
        ))
        .into_response());
    }

    let user = users::find_by_id(&state.pool, ticket.user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::server_error("Ticket references missing user"))?;

    let secret = user
        .totp_secret
        .as_deref()
        .ok_or_else(|| OidcError::server_error("Ticket issued for user without TOTP secret"))?;

    let used_recovery = match (form.code.as_deref(), form.recovery_code.as_deref()) {
        (Some(code), _) if !code.is_empty() => {
            let ok =
                verify_code(secret, code).map_err(|e| OidcError::server_error(e.to_string()))?;
            if !ok {
                pending_totp_logins::increment_attempts(&state.pool, ticket.id)
                    .await
                    .map_err(|e| OidcError::server_error(e.to_string()))?;
                return Ok(totp_challenge_error(
                    &state.config.frontend_url,
                    ticket.id,
                    "Incorrect code",
                ));
            }
            false
        }
        (_, Some(rc)) if !rc.is_empty() => {
            let matched = find_and_consume_recovery(&state, user.id, rc).await?;
            if !matched {
                pending_totp_logins::increment_attempts(&state.pool, ticket.id)
                    .await
                    .map_err(|e| OidcError::server_error(e.to_string()))?;
                return Ok(totp_challenge_error(
                    &state.config.frontend_url,
                    ticket.id,
                    "Recovery code not recognised",
                ));
            }
            true
        }
        _ => {
            return Ok(totp_challenge_error(
                &state.config.frontend_url,
                ticket.id,
                "Enter a code or a recovery code",
            ))
        }
    };

    if !pending_totp_logins::consume(&state.pool, ticket.id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
    {
        return Ok(totp_challenge_error(
            &state.config.frontend_url,
            ticket.id,
            "Ticket already consumed",
        ));
    }

    let mut code_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut code_bytes);
    let auth_code = Base64UrlUnpadded::encode_string(&code_bytes);

    auth_codes::create_code(
        &state.pool,
        &auth_code,
        &ticket.client_id,
        user.id,
        &ticket.redirect_uri,
        &ticket.code_challenge,
        &ticket.code_challenge_method,
        &ticket.scope,
        ticket.nonce.as_deref(),
    )
    .await
    .map_err(|e| OidcError::server_error(e.to_string()))?;

    let updated_jar = jar.add(build_session_cookie(user.id, state.config.secure_cookies()));

    tracing::info!(
        user_id = %user.id,
        used_recovery,
        "TOTP challenge passed, session issued"
    );

    let redirect_url = format!(
        "{}?code={}&state={}",
        ticket.redirect_uri,
        urlencoded(&auth_code),
        urlencoded(&ticket.oauth_state),
    );
    Ok((updated_jar, Redirect::to(&redirect_url)).into_response())
}

fn totp_challenge_error(frontend_url: &str, ticket_id: Uuid, error: &str) -> Response {
    Redirect::to(&format!(
        "{}/login/totp?ticket={}&error={}",
        frontend_url,
        urlencoded(&ticket_id.to_string()),
        urlencoded(error),
    ))
    .into_response()
}

/// Iterate the user's unconsumed recovery codes, ct-compare against `submitted`,
/// and consume the first matching row atomically. Returns `true` if a code was
/// found and consumed.
async fn find_and_consume_recovery(
    state: &AppState,
    user_id: Uuid,
    submitted: &str,
) -> Result<bool, OidcError> {
    let codes = recovery_codes::list_unconsumed(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    for row in codes {
        if verify_recovery_code(submitted, &row.code_hash, &state.email_otp_pepper)
            && recovery_codes::consume(&state.pool, row.id)
                .await
                .map_err(|e| OidcError::server_error(e.to_string()))?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

// ─── POST /api/totp/enroll ───────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct EnrollResponse {
    pub secret_base32: String,
    pub provisioning_url: String,
}

/// Generate a fresh authenticator secret, stash it in `pending_totp_enrollments`,
/// and return its base32 + otpauth URL so the client can render a QR.
#[tracing::instrument(skip_all)]
pub async fn post_enroll(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<EnrollResponse>, OidcError> {
    let user_id = require_auth(&state, &headers).await?;
    let user = users::find_by_id(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::invalid_client("User not found"))?;

    if user.totp_enabled {
        return Err(OidcError::invalid_request(
            "TOTP already enabled — disable it first to re-enroll",
        ));
    }

    let secret = generate_secret();
    pending_totp_enrollments::upsert(&state.pool, user.id, &secret)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let issuer = format!("Pina'i ({})", state.config.domain);
    let url = provisioning_url(&secret, &issuer, &user.email)
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    Ok(Json(EnrollResponse {
        secret_base32: secret_to_base32(&secret),
        provisioning_url: url,
    }))
}

// ─── POST /api/totp/enroll/verify ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EnrollVerifyRequest {
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct EnrollVerifyResponse {
    pub recovery_codes: Vec<String>,
}

/// Verify the user's first authenticator code, commit the secret to `users`,
/// and hand back a fresh set of recovery codes (shown once, never re-served).
#[tracing::instrument(skip_all)]
pub async fn post_enroll_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<EnrollVerifyRequest>,
) -> Result<Json<EnrollVerifyResponse>, OidcError> {
    let user_id = require_auth(&state, &headers).await?;

    let pending = pending_totp_enrollments::find_for_user(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| {
            OidcError::invalid_request("No pending enrollment — call /api/totp/enroll first")
        })?;

    let ok = verify_code(&pending.secret, &body.code)
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    if !ok {
        return Err(OidcError::invalid_grant("Incorrect code — try again"));
    }

    users::set_totp_secret_and_enable(&state.pool, user_id, &pending.secret)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    pending_totp_enrollments::delete_for_user(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    let codes = mint_and_store_recovery_codes(&state, user_id).await?;

    tracing::info!(user_id = %user_id, "TOTP enrolled");
    Ok(Json(EnrollVerifyResponse {
        recovery_codes: codes,
    }))
}

// ─── POST /api/totp/disable ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct DisableRequest {
    pub code: String,
}

/// Wipe `totp_secret`, flip `totp_enabled = false`, and delete all recovery
/// codes. Requires a current TOTP code so a passive session can't disarm 2FA.
#[tracing::instrument(skip_all)]
pub async fn post_disable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DisableRequest>,
) -> Result<StatusCode, OidcError> {
    let user_id = require_auth(&state, &headers).await?;
    let user = users::find_by_id(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::invalid_client("User not found"))?;

    if !user.totp_enabled {
        return Err(OidcError::invalid_request("TOTP is not enabled"));
    }

    let secret = user
        .totp_secret
        .as_deref()
        .ok_or_else(|| OidcError::server_error("TOTP enabled but secret missing"))?;

    let ok = verify_code(secret, &body.code).map_err(|e| OidcError::server_error(e.to_string()))?;
    if !ok {
        return Err(OidcError::invalid_grant("Incorrect code"));
    }

    users::disable_totp(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    recovery_codes::delete_all_for_user(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;
    pending_totp_enrollments::delete_for_user(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    tracing::info!(user_id = %user_id, "TOTP disabled");
    Ok(StatusCode::NO_CONTENT)
}

// ─── POST /api/totp/recovery-codes/regenerate ────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RegenerateRequest {
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct RegenerateResponse {
    pub recovery_codes: Vec<String>,
}

/// Invalidate the user's existing recovery codes and hand back a fresh batch.
/// Requires a current TOTP code — same gate as disable.
#[tracing::instrument(skip_all)]
pub async fn post_regenerate_recovery_codes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegenerateRequest>,
) -> Result<Json<RegenerateResponse>, OidcError> {
    let user_id = require_auth(&state, &headers).await?;
    let user = users::find_by_id(&state.pool, user_id)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?
        .ok_or_else(|| OidcError::invalid_client("User not found"))?;

    if !user.totp_enabled {
        return Err(OidcError::invalid_request("TOTP is not enabled"));
    }

    let secret = user
        .totp_secret
        .as_deref()
        .ok_or_else(|| OidcError::server_error("TOTP enabled but secret missing"))?;

    let ok = verify_code(secret, &body.code).map_err(|e| OidcError::server_error(e.to_string()))?;
    if !ok {
        return Err(OidcError::invalid_grant("Incorrect code"));
    }

    let codes = mint_and_store_recovery_codes(&state, user_id).await?;
    tracing::info!(user_id = %user_id, "recovery codes regenerated");
    Ok(Json(RegenerateResponse {
        recovery_codes: codes,
    }))
}

/// Generate a fresh batch of plaintext codes, hash them with the OTP pepper,
/// atomically replace the user's existing rows. Returns the plaintext for
/// one-time display — never stored again on the server.
async fn mint_and_store_recovery_codes(
    state: &AppState,
    user_id: Uuid,
) -> Result<Vec<String>, OidcError> {
    let plaintexts = generate_recovery_codes();
    let hashes: Vec<Vec<u8>> = plaintexts
        .iter()
        .map(|c| hash_recovery_code(c, &state.email_otp_pepper))
        .collect();

    recovery_codes::replace_all(&state.pool, user_id, &hashes)
        .await
        .map_err(|e| OidcError::server_error(e.to_string()))?;

    Ok(plaintexts)
}
