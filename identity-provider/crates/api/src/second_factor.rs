//! The second factor: the code page `/login/totp`, and `/api/totp/*` to turn it on and off — see
//! identity-provider/specs/auth.md § 3.

use std::sync::Arc;

use application::auth::{
    ConfirmTotpEnrollment, DisableTotp, PassSecondFactor, RegenerateRecoveryCodes,
    SecondFactorOutcome, StartTotpEnrollment,
};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use axum_extra::extract::SignedCookieJar;
use domain::TicketId;
use domain::auth::AuthError;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::ApiError;
use crate::auth::Authenticated;
use crate::pages::{
    Appearance, SameOrigin, SecondFactorPage, SignInPages, cancel, expired, render, to, totp_alert,
};
use crate::sign_in::{back_with_code, session_cookie, url_with};

#[derive(Debug, Deserialize)]
pub struct ChallengeQuery {
    ticket: Option<String>,
    /// `recovery` for a recovery code.
    mode: Option<String>,
    error: Option<String>,
    theme: Option<String>,
    motif: Option<String>,
}

/// `GET /login/totp` — the code page of a sign-in past its password, while its ticket is open.
pub async fn page(
    State(pages): State<SignInPages>,
    Query(query): Query<ChallengeQuery>,
) -> Result<Response, ApiError> {
    let appearance = Appearance::parse(query.theme.as_deref(), query.motif.as_deref());
    let ticket = query
        .ticket
        .as_deref()
        .and_then(|ticket| uuid::Uuid::parse_str(ticket).ok())
        .map(TicketId::from);
    let request = match ticket {
        Some(ticket) => pages
            .show
            .ticket(ticket, OffsetDateTime::now_utc())
            .await
            .map_err(|e| ApiError::internal(anyhow::Error::from(e)))?,
        None => None,
    };
    let (Some(ticket), Some(request)) = (ticket, request) else {
        let notice = expired(Some("ticket_expired"));
        return pages
            .notice(StatusCode::BAD_REQUEST, notice, appearance)
            .await;
    };
    let ticket = ticket.to_string();
    let recovery = query.mode.as_deref() == Some("recovery");
    let mut carried = vec![("ticket", ticket.as_str())];
    carried.extend(appearance.pairs());
    let mut switch = carried.clone();
    if !recovery {
        switch.push(("mode", "recovery"));
    }
    let page = SecondFactorPage {
        frame: pages.frame(appearance).await?,
        back: cancel(&request),
        recovery,
        switch_href: url_with("/login/totp", &switch),
        alert: query.error.as_deref().and_then(totp_alert),
        carried,
    };
    Ok(render(StatusCode::OK, &page, Some(&request.redirect_uri)))
}

#[derive(Debug, Deserialize)]
pub struct ChallengeForm {
    ticket: uuid::Uuid,
    code: Option<String>,
    recovery_code: Option<String>,
    theme: Option<String>,
    motif: Option<String>,
}

/// `POST /login/totp` — the code page: back to the client signed in, or to the page again with
/// the reason, or to an expired sign-in when the ticket is gone.
pub async fn pass(
    _: SameOrigin,
    State(pass): State<Arc<PassSecondFactor>>,
    State(pages): State<SignInPages>,
    jar: SignedCookieJar,
    Form(form): Form<ChallengeForm>,
) -> Result<Response, ApiError> {
    let appearance = Appearance::parse(form.theme.as_deref(), form.motif.as_deref());
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
    let ended = |error: &str| {
        let mut pairs = vec![("error", error)];
        pairs.extend(appearance.pairs());
        to("/login", &pairs)
    };
    let ticket = ticket.to_string();
    let again = |error: &str| {
        let mut pairs = vec![("ticket", ticket.as_str())];
        if form.recovery_code.is_some() {
            pairs.push(("mode", "recovery"));
        }
        pairs.push(("error", error));
        pairs.extend(appearance.pairs());
        to("/login/totp", &pairs)
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
        SecondFactorOutcome::Expired | SecondFactorOutcome::AlreadyUsed => ended("ticket_expired"),
        SecondFactorOutcome::TooManyAttempts => ended("ticket_exhausted"),
        SecondFactorOutcome::WrongCode => again("totp_incorrect"),
        SecondFactorOutcome::UnknownRecoveryCode => again("recovery_unknown"),
        SecondFactorOutcome::Missing => again("totp_missing"),
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
