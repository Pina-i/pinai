//! The second factor: `/login/totp`, and `/api/totp/*` to turn it on and off — see
//! identity-provider/specs/01-identity-federation.md § 1.4b.

use std::sync::Arc;

use application::auth::{
    ConfirmTotpEnrollment, DisableTotp, PassSecondFactor, RegenerateRecoveryCodes,
    SecondFactorOutcome, StartTotpEnrollment,
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Form, Json};
use axum_extra::extract::SignedCookieJar;
use domain::TicketId;
use domain::auth::AuthError;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::ApiError;
use crate::auth::Authenticated;
use crate::sign_in::{SignInPages, back_with_code, session_cookie, url_with};

#[derive(Debug, Deserialize)]
pub struct ChallengeForm {
    ticket: uuid::Uuid,
    code: Option<String>,
    recovery_code: Option<String>,
}

/// `POST /login/totp` — the code page: back to the client signed in, or to the page again with
/// the reason, or to the login page when the ticket is gone.
pub async fn pass(
    State(pass): State<Arc<PassSecondFactor>>,
    State(pages): State<SignInPages>,
    jar: SignedCookieJar,
    Form(form): Form<ChallengeForm>,
) -> Result<Response, ApiError> {
    let ticket = TicketId::from(form.ticket);
    let outcome = pass
        .execute(
            ticket,
            form.code.as_deref(),
            form.recovery_code.as_deref(),
            OffsetDateTime::now_utc(),
        )
        .await
        .map_err(|e| ApiError::internal(anyhow::Error::from(e)))?;
    let login = |error: &str| {
        Redirect::to(&url_with(
            &format!("{}/login", pages.frontend_url),
            &[("error", error)],
        ))
        .into_response()
    };
    let again = |error: &str| {
        Redirect::to(&url_with(
            &format!("{}/login/totp", pages.frontend_url),
            &[("ticket", &ticket.to_string()), ("error", error)],
        ))
        .into_response()
    };
    Ok(match outcome {
        SecondFactorOutcome::SignedIn {
            user,
            request,
            code,
        } => (
            jar.add(session_cookie(user, pages.secure_cookies)),
            back_with_code(&request, code.as_str()),
        )
            .into_response(),
        SecondFactorOutcome::Expired => login("Sign-in expired — try again"),
        SecondFactorOutcome::TooManyAttempts => login("Too many attempts — sign in again"),
        SecondFactorOutcome::WrongCode => again("Incorrect code"),
        SecondFactorOutcome::UnknownRecoveryCode => again("Recovery code not recognised"),
        SecondFactorOutcome::Missing => again("Enter a code or a recovery code"),
        SecondFactorOutcome::AlreadyUsed => again("Ticket already consumed"),
    })
}

fn refused(error: AuthError, wrong_code: &'static str) -> ApiError {
    match error {
        AuthError::UnknownUser => ApiError::invalid_client("User not found"),
        AuthError::TotpEnabled => {
            ApiError::bad_request("TOTP already enabled — disable it first to re-enroll")
        }
        AuthError::TotpNotEnabled => ApiError::bad_request("TOTP is not enabled"),
        AuthError::NoEnrollment => {
            ApiError::bad_request("No pending enrollment — call /api/totp/enroll first")
        }
        AuthError::WrongCode => ApiError::new(StatusCode::BAD_REQUEST, "invalid_grant", wrong_code),
        other => ApiError::internal(anyhow::Error::from(other)),
    }
}

#[derive(Serialize)]
pub struct EnrollmentBody {
    secret_base32: String,
    provisioning_url: String,
}

/// `POST /api/totp/enroll` — a secret to scan: the second factor is on once a code confirms it.
pub async fn enroll(
    State(enroll): State<Arc<StartTotpEnrollment>>,
    Authenticated(user): Authenticated,
) -> Result<Json<EnrollmentBody>, ApiError> {
    let enrollment = enroll
        .execute(user)
        .await
        .map_err(|e| refused(e, "Incorrect code"))?;
    Ok(Json(EnrollmentBody {
        secret_base32: enrollment.secret_base32,
        provisioning_url: enrollment.provisioning_url,
    }))
}

#[derive(Debug, Deserialize)]
pub struct CodeBody {
    code: String,
}

#[derive(Serialize)]
pub struct RecoveryCodesBody {
    recovery_codes: Vec<String>,
}

/// `POST /api/totp/enroll/verify` — the app's first code: on, with recovery codes shown once.
pub async fn confirm(
    State(confirm): State<Arc<ConfirmTotpEnrollment>>,
    Authenticated(user): Authenticated,
    Json(body): Json<CodeBody>,
) -> Result<Json<RecoveryCodesBody>, ApiError> {
    let recovery_codes = confirm
        .execute(user, &body.code, OffsetDateTime::now_utc())
        .await
        .map_err(|e| refused(e, "Incorrect code — try again"))?;
    Ok(Json(RecoveryCodesBody { recovery_codes }))
}

/// `POST /api/totp/disable` — off, given a current code.
pub async fn disable(
    State(disable): State<Arc<DisableTotp>>,
    Authenticated(user): Authenticated,
    Json(body): Json<CodeBody>,
) -> Result<StatusCode, ApiError> {
    disable
        .execute(user, &body.code, OffsetDateTime::now_utc())
        .await
        .map_err(|e| refused(e, "Incorrect code"))?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/totp/recovery-codes/regenerate` — a new set, given a current code.
pub async fn regenerate(
    State(regenerate): State<Arc<RegenerateRecoveryCodes>>,
    Authenticated(user): Authenticated,
    Json(body): Json<CodeBody>,
) -> Result<Json<RecoveryCodesBody>, ApiError> {
    let recovery_codes = regenerate
        .execute(user, &body.code, OffsetDateTime::now_utc())
        .await
        .map_err(|e| refused(e, "Incorrect code"))?;
    Ok(Json(RecoveryCodesBody { recovery_codes }))
}

#[cfg(test)]
mod tests;
