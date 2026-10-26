//! Registering and confirming an address: `/register`, `/register-and-login`, the code page
//! `/verify-email`, `/verify-email-and-login`, `/verify-email/resend` — see
//! identity-provider/specs/auth.md § 2.

use std::sync::Arc;

use application::auth::{
    Register, RegisterCommand, ResendCode, SendTestMail, Verification, VerifyEmail,
};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use axum_extra::extract::SignedCookieJar;
use domain::UserId;
use domain::auth::{AuthError, AuthorizationRequest, CodeAttempt, Email};
use domain::identity::InstanceOrigin;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::ApiError;
use crate::pages::{
    Appearance, Carried, SameOrigin, SignInPages, VerifyEmailPage, cancel, carried, expired,
    render, to, verify_status,
};
use crate::sign_in::{back_with_code, session_cookie, session_of};

fn internal(error: AuthError) -> ApiError {
    ApiError::internal(anyhow::Error::from(error))
}

#[derive(Debug, Deserialize)]
pub struct RegisterBody {
    display_name: String,
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
        display_name: body.display_name,
        email: body.email,
        password: body.password,
    };
    let registered = register
        .execute(command, None, OffsetDateTime::now_utc())
        .await
        .map_err(|e| match e {
            AuthError::MissingField => {
                ApiError::bad_request("display_name, email, and password are required")
            }
            AuthError::BadDisplayName(rule) | AuthError::BadEmail(rule) => ApiError::from(rule),
            AuthError::PasswordTooShort => {
                ApiError::bad_request("password must be at least 8 characters")
            }
            AuthError::EmailTaken => ApiError::bad_request("Email already registered"),
            AuthError::InvitationRequired => ApiError::new(
                StatusCode::FORBIDDEN,
                "invitation_required",
                format!("Accounts on {} are by invitation only", origin.domain()),
            ),
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

#[derive(Debug, Deserialize)]
pub struct RegisterForm {
    display_name: String,
    email: String,
    password: String,
    #[serde(flatten)]
    carried: Carried,
}

/// `POST /register-and-login` — the sign-up form: an account, then on to confirming its address
/// with the sign-in carried along.
pub async fn register_and_log_in(
    _: SameOrigin,
    State(register): State<Arc<Register>>,
    State(pages): State<SignInPages>,
    Form(form): Form<RegisterForm>,
) -> Result<Response, ApiError> {
    let appearance = form.carried.appearance();
    let Some(request) = form.carried.request() else {
        return Ok(to("/login", &appearance.pairs()));
    };
    let refused = |error: &str| {
        to(
            "/login",
            &carried(
                &request,
                appearance,
                &[("tab", "register"), ("error", error)],
            ),
        )
    };
    let command = RegisterCommand {
        display_name: form.display_name.clone(),
        email: form.email.clone(),
        password: form.password.clone(),
    };
    let registered = match register
        .execute(command, Some(&request), OffsetDateTime::now_utc())
        .await
    {
        Ok(registered) => registered,
        Err(AuthError::MissingField) => return Ok(refused("missing_field")),
        Err(AuthError::BadDisplayName(_)) => return Ok(refused("invalid_display_name")),
        Err(AuthError::BadEmail(_)) => return Ok(refused("invalid_email")),
        Err(AuthError::PasswordTooShort) => return Ok(refused("weak_password")),
        Err(AuthError::EmailTaken) => return Ok(refused("email_taken")),
        Err(AuthError::InvitationRequired) => {
            let pairs = [("error", "invitation_required")];
            return Ok(to("/login", &carried(&request, appearance, &pairs)));
        }
        Err(error @ (AuthError::UnknownClient | AuthError::UnregisteredRedirect)) => {
            return pages.misdirected(error, appearance).await;
        }
        Err(other) => return Err(internal(other)),
    };
    let user = registered.user.to_string();
    let pending = [
        ("pending_user_id", user.as_str()),
        ("pending_email", registered.email.as_str()),
    ];
    Ok(to(
        "/verify-email",
        &carried(&request, appearance, &pending),
    ))
}

#[derive(Debug, Deserialize)]
pub struct VerifyQuery {
    pending_user_id: Option<String>,
    pending_email: Option<String>,
    error: Option<String>,
    notice: Option<String>,
    /// The guesses left, with `error=code_incorrect`.
    left: Option<String>,
    #[serde(flatten)]
    carried: Carried,
}

/// `GET /verify-email` — the page asking for the code mailed to the address.
pub async fn verify_page(
    State(pages): State<SignInPages>,
    Query(query): Query<VerifyQuery>,
) -> Result<Response, ApiError> {
    let appearance = query.carried.appearance();
    let pending = query
        .pending_user_id
        .as_deref()
        .and_then(|user| uuid::Uuid::parse_str(user).ok());
    let (Some(request), Some(pending)) = (query.carried.request(), pending) else {
        return pages
            .notice(StatusCode::BAD_REQUEST, expired(None), appearance)
            .await;
    };
    if let Err(error) = pages.show.request(&request).await {
        return pages.misdirected(error, appearance).await;
    }
    // Shown on the page: an address, never any text a link wants printed there.
    let email = query
        .pending_email
        .filter(|email| Email::parse(email).is_ok());
    let (status, failed) = verify_status(
        query.error.as_deref(),
        query.notice.as_deref(),
        query.left.as_deref(),
    );
    let user = pending.to_string();
    let mut extra = vec![("pending_user_id", user.as_str())];
    if let Some(email) = &email {
        extra.push(("pending_email", email.as_str()));
    }
    let page = VerifyEmailPage {
        frame: pages.frame(appearance).await?,
        back: cancel(&request),
        resent: !failed && query.notice.as_deref() == Some("code_resent"),
        email: email.clone(),
        status,
        failed,
        carried: carried(&request, appearance, &extra),
    };
    Ok(render(StatusCode::OK, &page, Some(&request.redirect_uri)))
}

#[derive(Debug, Deserialize)]
pub struct VerifyForm {
    pending_user_id: uuid::Uuid,
    /// Only shown back on the page.
    #[serde(default)]
    pending_email: String,
    code: String,
    #[serde(flatten)]
    carried: Carried,
}

/// Back to the code page, still carrying everything, with `extra` said.
fn code_page(
    request: &AuthorizationRequest,
    appearance: Appearance,
    user: &str,
    email: &str,
    extra: &[(&str, &str)],
) -> Response {
    let mut pairs = vec![("pending_user_id", user), ("pending_email", email)];
    pairs.extend_from_slice(extra);
    to("/verify-email", &carried(request, appearance, &pairs))
}

/// `POST /verify-email-and-login` — the code mailed to the address: confirmed, then back to the
/// client with a code and a session.
pub async fn verify_email(
    _: SameOrigin,
    State(verify): State<Arc<VerifyEmail>>,
    State(pages): State<SignInPages>,
    jar: SignedCookieJar,
    Form(form): Form<VerifyForm>,
) -> Result<Response, ApiError> {
    let appearance = form.carried.appearance();
    let Some(request) = form.carried.request() else {
        return Ok(to("/login", &appearance.pairs()));
    };
    let user = form.pending_user_id.to_string();
    let again =
        |extra: &[(&str, &str)]| code_page(&request, appearance, &user, &form.pending_email, extra);
    let verification = match verify
        .execute(
            UserId::from(form.pending_user_id),
            &form.code,
            &request,
            session_of(&jar),
            OffsetDateTime::now_utc(),
        )
        .await
    {
        Ok(verification) => verification,
        Err(AuthError::UnknownUser) => {
            let expired = [("tab", "register"), ("error", "signup_expired")];
            return Ok(to("/login", &carried(&request, appearance, &expired)));
        }
        Err(error @ (AuthError::UnknownClient | AuthError::UnregisteredRedirect)) => {
            return pages.misdirected(error, appearance).await;
        }
        Err(other) => return Err(internal(other)),
    };
    Ok(match verification {
        Verification::SignedIn { session, code, .. } => (
            jar.add(session_cookie(session, pages.secure_cookies)),
            back_with_code(&request, code.as_str()),
        )
            .into_response(),
        // Confirmed before: signing in again will go through.
        Verification::AlreadyConfirmed => to(
            "/login",
            &carried(&request, appearance, &[("notice", "already_verified")]),
        ),
        Verification::NoCodeNeeded => to(
            "/login",
            &carried(&request, appearance, &[("notice", "no_code_needed")]),
        ),
        Verification::Malformed => again(&[("error", "code_format")]),
        Verification::Refused(attempt) => match attempt {
            CodeAttempt::NoCode => again(&[("error", "code_expired")]),
            CodeAttempt::Exhausted | CodeAttempt::Wrong { left: 0 } => {
                again(&[("error", "code_exhausted")])
            }
            CodeAttempt::Wrong { left } => {
                again(&[("error", "code_incorrect"), ("left", &left.to_string())])
            }
            CodeAttempt::AlreadyUsed | CodeAttempt::Confirmed => again(&[("error", "code_used")]),
        },
    })
}

#[derive(Debug, Deserialize)]
pub struct ResendForm {
    pending_user_id: uuid::Uuid,
    #[serde(default)]
    pending_email: String,
    #[serde(flatten)]
    carried: Carried,
}

/// `POST /verify-email/resend` — another code, then the code page again saying so: sent, wait,
/// or on to sign in when the address is confirmed already.
pub async fn resend(
    _: SameOrigin,
    State(resend): State<Arc<ResendCode>>,
    Form(form): Form<ResendForm>,
) -> Result<Response, ApiError> {
    let appearance = form.carried.appearance();
    let Some(request) = form.carried.request() else {
        return Ok(to("/login", &appearance.pairs()));
    };
    let user = form.pending_user_id.to_string();
    let again =
        |extra: &[(&str, &str)]| code_page(&request, appearance, &user, &form.pending_email, extra);
    Ok(
        match resend
            .execute(
                UserId::from(form.pending_user_id),
                OffsetDateTime::now_utc(),
            )
            .await
        {
            Ok(()) => again(&[("notice", "code_resent")]),
            Err(AuthError::TooManyCodes) => again(&[("error", "too_many_codes")]),
            Err(AuthError::AlreadyVerified) => to(
                "/login",
                &carried(&request, appearance, &[("notice", "already_verified")]),
            ),
            Err(AuthError::NoCodeNeeded) => to(
                "/login",
                &carried(&request, appearance, &[("notice", "no_code_needed")]),
            ),
            Err(AuthError::UnknownUser) => to(
                "/login",
                &carried(
                    &request,
                    appearance,
                    &[("tab", "register"), ("error", "signup_expired")],
                ),
            ),
            Err(other) => return Err(internal(other)),
        },
    )
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
