//! Registering and confirming an address: `/register`, `/register-and-login`,
//! `/verify-email-and-login`, `/verify-email/resend` — see
//! identity-provider/specs/01-identity-federation.md § 1.4.

use std::sync::Arc;

use application::auth::{
    Register, RegisterCommand, ResendCode, SendTestMail, Verification, VerifyEmail,
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Form, Json};
use axum_extra::extract::SignedCookieJar;
use domain::auth::{AuthError, AuthorizationRequest, ClientId, CodeAttempt, CodeChallenge};
use domain::identity::InstanceOrigin;
use domain::{UserId, ValidationError};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::ApiError;
use crate::sign_in::{SignInPages, back_with_code, carrying, session_cookie, url_with};

/// A rule as the sign-up page shows it: `Username: 2–32 characters: …`.
fn sentence(rule: &ValidationError) -> String {
    let mut field = rule.field.chars();
    let capital: String = field
        .next()
        .map(|c| c.to_uppercase().collect())
        .unwrap_or_default();
    format!("{capital}{}: {}", field.as_str(), rule.reason)
}

fn internal(error: AuthError) -> ApiError {
    ApiError::internal(anyhow::Error::from(error))
}

#[derive(Debug, Deserialize)]
pub struct RegisterBody {
    username: String,
    email: String,
    password: String,
}

#[derive(Serialize)]
pub struct RegisteredBody {
    id: String,
    username: String,
    display_name: String,
    address: String,
    email: String,
    email_verified: bool,
    /// What `/verify-email-and-login` is sent back.
    pending_user_id: String,
}

/// `POST /register` — an account, unconfirmed; no session until its code comes back.
pub async fn register(
    State(register): State<Arc<Register>>,
    State(origin): State<InstanceOrigin>,
    Json(body): Json<RegisterBody>,
) -> Result<(StatusCode, Json<RegisteredBody>), ApiError> {
    let command = RegisterCommand {
        username: body.username,
        email: body.email,
        password: body.password,
    };
    let registered = register
        .execute(command, None, OffsetDateTime::now_utc())
        .await
        .map_err(|e| match e {
            AuthError::MissingField => {
                ApiError::bad_request("username, email, and password are required")
            }
            AuthError::BadUsername(rule) | AuthError::BadEmail(rule) => ApiError::from(rule),
            AuthError::PasswordTooShort => {
                ApiError::bad_request("password must be at least 8 characters")
            }
            AuthError::EmailTaken => ApiError::bad_request("Email already registered"),
            other => internal(other),
        })?;
    Ok((
        StatusCode::CREATED,
        Json(RegisteredBody {
            id: registered.user.to_string(),
            pending_user_id: registered.user.to_string(),
            address: format!("{}@{}", registered.username, origin.domain()),
            username: registered.username,
            display_name: registered.display_name,
            email: registered.email,
            email_verified: false,
        }),
    ))
}

/// The sign-in request a sign-up form carries, as it came.
#[derive(Debug, Deserialize)]
pub struct CarriedRequest {
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
    nonce: Option<String>,
}

impl CarriedRequest {
    fn parse(&self) -> Result<AuthorizationRequest, AuthError> {
        Ok(AuthorizationRequest {
            client: ClientId::parse(&self.client_id).map_err(|_| AuthError::UnknownClient)?,
            redirect_uri: self.redirect_uri.clone(),
            scope: self.scope.clone(),
            state: self.state.clone(),
            challenge: CodeChallenge::parse(&self.code_challenge, &self.code_challenge_method)?,
            nonce: self.nonce.clone(),
        })
    }

    /// Its parameters as they came, `before` them and `error` after, then the nonce.
    fn back_to(&self, page: &str, before: &[(&str, &str)], error: &str) -> Response {
        let mut pairs = before.to_vec();
        pairs.extend([
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("scope", self.scope.as_str()),
            ("state", self.state.as_str()),
            ("code_challenge", self.code_challenge.as_str()),
            ("code_challenge_method", self.code_challenge_method.as_str()),
            ("error", error),
        ]);
        if let Some(nonce) = &self.nonce {
            pairs.push(("nonce", nonce));
        }
        Redirect::to(&url_with(page, &pairs)).into_response()
    }
}

/// A request not from a registered client is answered here, never sent anywhere.
fn misdirected(error: AuthError) -> ApiError {
    match error {
        AuthError::UnknownClient => ApiError::invalid_client("Unknown client_id"),
        AuthError::UnregisteredRedirect => ApiError::bad_request("redirect_uri is not registered"),
        other => internal(other),
    }
}

#[derive(Debug, Deserialize)]
pub struct RegisterForm {
    username: String,
    email: String,
    password: String,
    #[serde(flatten)]
    request: CarriedRequest,
}

/// `POST /register-and-login` — the sign-up form: an account, then on to confirming its address
/// with the sign-in carried along.
pub async fn register_and_log_in(
    State(register): State<Arc<Register>>,
    State(pages): State<SignInPages>,
    Form(form): Form<RegisterForm>,
) -> Result<Response, ApiError> {
    let login_page = format!("{}/login", pages.frontend_url);
    let refused = |error: &str| {
        form.request
            .back_to(&login_page, &[("tab", "register")], error)
    };
    let Ok(request) = form.request.parse() else {
        return Ok(refused("Invalid request"));
    };
    let command = RegisterCommand {
        username: form.username.clone(),
        email: form.email.clone(),
        password: form.password.clone(),
    };
    let registered = match register
        .execute(command, Some(&request), OffsetDateTime::now_utc())
        .await
    {
        Ok(registered) => registered,
        Err(AuthError::BadUsername(rule) | AuthError::BadEmail(rule)) => {
            return Ok(refused(&sentence(&rule)));
        }
        Err(AuthError::PasswordTooShort) => {
            return Ok(refused("Password must be at least 8 characters"));
        }
        Err(AuthError::EmailTaken) => return Ok(refused("Email already registered")),
        Err(other) => return Err(misdirected(other)),
    };
    let user = registered.user.to_string();
    let mut pairs = vec![
        ("pending_user_id", user.as_str()),
        ("pending_email", registered.email.as_str()),
    ];
    pairs.extend(carrying(&request, &[]));
    Ok(Redirect::to(&url_with(
        &format!("{}/verify-email", pages.frontend_url),
        &pairs,
    ))
    .into_response())
}

#[derive(Debug, Deserialize)]
pub struct VerifyForm {
    pending_user_id: uuid::Uuid,
    /// Only shown back on the page.
    #[serde(default)]
    pending_email: String,
    code: String,
    #[serde(flatten)]
    request: CarriedRequest,
}

fn attempt_refused(attempt: CodeAttempt) -> String {
    match attempt {
        CodeAttempt::NoCode => "Code expired — request a new one".to_owned(),
        CodeAttempt::Exhausted | CodeAttempt::Wrong { left: 0 } => {
            "Too many attempts — request a new code".to_owned()
        }
        CodeAttempt::Wrong { left } => format!("Incorrect code — {left} attempt(s) left"),
        CodeAttempt::AlreadyUsed | CodeAttempt::Confirmed => {
            "Code already used — try logging in".to_owned()
        }
    }
}

/// `POST /verify-email-and-login` — the code mailed to the address: confirmed, then back to the
/// client with a code and a session.
pub async fn verify_email(
    State(verify): State<Arc<VerifyEmail>>,
    State(pages): State<SignInPages>,
    jar: SignedCookieJar,
    Form(form): Form<VerifyForm>,
) -> Result<Response, ApiError> {
    let request = form.request.parse().map_err(|e| match e {
        AuthError::BadChallengeMethod => {
            ApiError::bad_request("code_challenge_method must be S256")
        }
        other => misdirected(other),
    })?;
    let user = form.pending_user_id.to_string();
    let verify_page = format!("{}/verify-email", pages.frontend_url);
    let refused = |error: &str| {
        form.request.back_to(
            &verify_page,
            &[
                ("pending_user_id", user.as_str()),
                ("pending_email", form.pending_email.as_str()),
            ],
            error,
        )
    };
    let verification = verify
        .execute(
            UserId::from(form.pending_user_id),
            &form.code,
            &request,
            OffsetDateTime::now_utc(),
        )
        .await
        .map_err(|e| match e {
            AuthError::UnknownUser => ApiError::bad_request("Unknown user"),
            other => misdirected(other),
        })?;
    Ok(match verification {
        Verification::SignedIn { user, code } => (
            jar.add(session_cookie(user, pages.secure_cookies)),
            back_with_code(&request, code.as_str()),
        )
            .into_response(),
        // Confirmed before: signing in again will go through.
        Verification::AlreadyConfirmed => {
            Redirect::to(&format!("{}/login", pages.frontend_url)).into_response()
        }
        Verification::Malformed => refused("Enter the 6-digit code"),
        Verification::Refused(attempt) => refused(&attempt_refused(attempt)),
    })
}

#[derive(Debug, Deserialize)]
pub struct ResendForm {
    pending_user_id: uuid::Uuid,
}

/// `POST /verify-email/resend` — another code: `204`, `410` once confirmed, `429` past the limit.
pub async fn resend(
    State(resend): State<Arc<ResendCode>>,
    Form(form): Form<ResendForm>,
) -> Result<StatusCode, ApiError> {
    match resend
        .execute(
            UserId::from(form.pending_user_id),
            OffsetDateTime::now_utc(),
        )
        .await
    {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(AuthError::AlreadyVerified) => Ok(StatusCode::GONE),
        Err(AuthError::TooManyCodes) => Ok(StatusCode::TOO_MANY_REQUESTS),
        Err(AuthError::UnknownUser) => Err(ApiError::not_found("Unknown user")),
        Err(other) => Err(internal(other)),
    }
}

#[derive(Debug, Deserialize)]
pub struct TestMailBody {
    to: String,
    #[serde(default = "tester")]
    display_name: String,
}

fn tester() -> String {
    "Tester".to_owned()
}

/// `POST /dev/send-test-email` — development instances only: a signup mail with a fixed code.
pub async fn send_test_mail(
    State(send): State<Arc<SendTestMail>>,
    Json(body): Json<TestMailBody>,
) -> Result<StatusCode, ApiError> {
    send.execute(&body.to, &body.display_name)
        .await
        .map_err(internal)?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
