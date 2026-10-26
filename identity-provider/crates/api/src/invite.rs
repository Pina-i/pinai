//! Joining by invitation, on this instance's own pages: `/i/{token}` and its sign-up form —
//! see identity-provider/specs/auth.md § 5.

use std::sync::Arc;

use application::auth::{Joined, RegisterCommand, RegisterInvited};
use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::SignedCookieJar;
use domain::auth::{AuthError, InvitationToken, OpenInvitation};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::ApiError;
use crate::pages::{
    AccountReadyPage, Appearance, INVITATION_UNUSABLE, InvitationPage, InvitedSignUpPage,
    SameOrigin, SignInPages, initial_of, login_alert, render, time_left, unreferred,
};
use crate::sign_in::{session_cookie, session_of};

pub(crate) fn invitation_path(token: &InvitationToken) -> String {
    format!("/i/{}", token.as_str())
}

fn sign_up_path(token: &InvitationToken) -> String {
    format!("{}/sign-up", invitation_path(token))
}

/// The same page whatever made the invitation unusable.
async fn unusable(pages: &SignInPages) -> Result<Response, ApiError> {
    Ok(unreferred(
        pages
            .notice(
                StatusCode::NOT_FOUND,
                INVITATION_UNUSABLE,
                Appearance::default(),
            )
            .await?,
    ))
}

/// The open invitation `raw` names.
async fn open(
    pages: &SignInPages,
    raw: &str,
) -> Result<Option<(InvitationToken, OpenInvitation)>, ApiError> {
    let Ok(token) = InvitationToken::parse(raw) else {
        return Ok(None);
    };
    let invitation = pages
        .show
        .invitation(&token, OffsetDateTime::now_utc())
        .await
        .map_err(|e| ApiError::internal(anyhow::Error::from(e)))?;
    Ok(invitation.map(|invitation| (token, invitation)))
}

/// `GET /i/{token}` — who invited, to which instance, until when, and on to the sign-up
/// form.
pub async fn page(
    State(pages): State<SignInPages>,
    Path(raw): Path<String>,
) -> Result<Response, ApiError> {
    let Some((token, invitation)) = open(&pages, &raw).await? else {
        return unusable(&pages).await;
    };
    let page = InvitationPage {
        frame: pages.frame(Appearance::default()).await?,
        inviter: invitation.inviter,
        expires_in: time_left(invitation.expires_at - OffsetDateTime::now_utc()),
        sign_up_href: sign_up_path(&token),
    };
    Ok(unreferred(render(StatusCode::OK, &page, None)))
}

#[derive(Debug, Deserialize)]
pub struct SignUpForm {
    display_name: String,
    email: String,
    password: String,
}

/// What was typed, the password aside, and the code of what was wrong with it.
struct Refused<'a> {
    display_name: &'a str,
    email: &'a str,
    code: &'static str,
}

/// The sign-up form for `token`'s invitation, refused or not yet sent.
async fn form_page(
    pages: &SignInPages,
    register: &RegisterInvited,
    status: StatusCode,
    (token, invitation): (InvitationToken, OpenInvitation),
    refused: Option<Refused<'_>>,
) -> Result<Response, ApiError> {
    let (alert, bad) = match refused
        .as_ref()
        .and_then(|refused| login_alert(refused.code, &pages.host()))
    {
        Some((alert, field)) => (Some(alert), field),
        None => (None, ""),
    };
    let web_app = register.web_app_entry();
    let page = InvitedSignUpPage {
        frame: pages.frame(Appearance::default()).await?,
        inviter_initial: invitation
            .inviter
            .as_deref()
            .map(initial_of)
            .unwrap_or_default(),
        inviter: invitation.inviter,
        back_href: invitation_path(&token),
        action: sign_up_path(&token),
        web_app: web_app.clone(),
        alert,
        bad,
        display_name: refused
            .as_ref()
            .map_or_else(String::new, |refused| refused.display_name.to_owned()),
        email: refused
            .as_ref()
            .map_or_else(String::new, |refused| refused.email.to_owned()),
        email_host: pages.email_host(),
    };
    // Not `no-referrer`, under which the form posts `Origin: null`; `same-origin` keeps the token
    // here too. Chrome holds a redirect `form-action` refuses: the answer goes to the web app.
    Ok(render(status, &page, web_app.as_deref()))
}

/// `GET /i/{token}/sign-up` — the form the invitation lets someone in with.
pub async fn sign_up_page(
    State(pages): State<SignInPages>,
    State(register): State<Arc<RegisterInvited>>,
    Path(raw): Path<String>,
) -> Result<Response, ApiError> {
    let Some(open) = open(&pages, &raw).await? else {
        return unusable(&pages).await;
    };
    form_page(&pages, &register, StatusCode::OK, open, None).await
}

/// `POST /i/{token}/sign-up` — the account, admitted. Then the browser lands in the web app
/// signed in, or, with no web app known, is told to sign in from the app.
pub async fn sign_up(
    _: SameOrigin,
    State(pages): State<SignInPages>,
    State(register): State<Arc<RegisterInvited>>,
    jar: SignedCookieJar,
    Path(raw): Path<String>,
    Form(form): Form<SignUpForm>,
) -> Result<Response, ApiError> {
    let Ok(token) = InvitationToken::parse(&raw) else {
        return unusable(&pages).await;
    };
    let SignUpForm {
        display_name,
        email,
        password,
    } = form;
    let command = RegisterCommand {
        display_name: display_name.clone(),
        email: email.clone(),
        password,
    };
    let joined = register
        .execute(&token, command, session_of(&jar), OffsetDateTime::now_utc())
        .await;
    let code = match joined {
        Ok(Joined::InWebApp { session, entry, .. }) => {
            let cookie = session_cookie(session, pages.secure_cookies);
            return Ok(unreferred(
                (jar.add(cookie), Redirect::to(&entry)).into_response(),
            ));
        }
        Ok(Joined::Ready(registered)) => {
            let page = AccountReadyPage {
                frame: pages.frame(Appearance::default()).await?,
                email: registered.email,
            };
            return Ok(unreferred(render(StatusCode::OK, &page, None)));
        }
        Err(AuthError::InvitationUnusable) => return unusable(&pages).await,
        Err(AuthError::BadDisplayName(_)) => "invalid_display_name",
        Err(AuthError::BadEmail(_)) => "invalid_email",
        Err(AuthError::PasswordTooShort) => "weak_password",
        Err(AuthError::EmailTaken) => "email_taken",
        Err(other) => return Err(ApiError::internal(anyhow::Error::from(other))),
    };
    let Some(open) = open(&pages, &raw).await? else {
        return unusable(&pages).await;
    };
    let refused = Refused {
        display_name: &display_name,
        email: &email,
        code,
    };
    form_page(
        &pages,
        &register,
        StatusCode::BAD_REQUEST,
        open,
        Some(refused),
    )
    .await
}

#[cfg(test)]
mod tests;
