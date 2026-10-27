//! Setting a new password with an admin's reset link, on this instance's own page: `/r/{token}` —
//! see identity-provider/specs/auth.md § 7.

use std::sync::Arc;

use application::auth::ResetPassword;
use axum::Form;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use domain::auth::{AuthError, OpenReset, ResetToken};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::ApiError;
use crate::pages::{
    Appearance, NoticePage, PasswordChangedPage, PasswordResetPage, SameOrigin, SignInPages,
    login_alert, render, unreferred,
};

pub(crate) fn reset_path(token: &ResetToken) -> String {
    format!("/r/{}", token.as_str())
}

/// The same page whatever made the link unusable.
async fn unusable(pages: &SignInPages) -> Result<Response, ApiError> {
    let page = NoticePage {
        frame: pages.frame(Appearance::default()).await?,
        title: "This link can no longer be used",
        text: format!("Ask an admin of {} for a new one.", pages.host()).into(),
        back: None,
    };
    Ok(unreferred(render(StatusCode::NOT_FOUND, &page, None)))
}

/// The open link `raw` names.
async fn open(pages: &SignInPages, raw: &str) -> Result<Option<(ResetToken, OpenReset)>, ApiError> {
    let Ok(token) = ResetToken::parse(raw) else {
        return Ok(None);
    };
    let reset = pages
        .show
        .password_reset(&token, OffsetDateTime::now_utc())
        .await
        .map_err(|e| ApiError::internal(anyhow::Error::from(e)))?;
    Ok(reset.map(|reset| (token, reset)))
}

/// The form for `token`'s member, refused — with the code of what was wrong — or not yet sent.
/// The passwords typed are never shown again.
async fn form_page(
    pages: &SignInPages,
    status: StatusCode,
    (token, reset): (ResetToken, OpenReset),
    refused: Option<&'static str>,
) -> Result<Response, ApiError> {
    let (alert, bad) = match refused.and_then(|code| login_alert(code, &pages.host())) {
        Some((alert, field)) => (Some(alert), field),
        None => (None, ""),
    };
    let page = PasswordResetPage {
        frame: pages.frame(Appearance::default()).await?,
        display_name: reset.display_name,
        action: reset_path(&token),
        alert,
        bad,
    };
    // Not `no-referrer`, under which the form posts `Origin: null`; `same-origin` keeps the token
    // here too.
    Ok(render(status, &page, None))
}

/// `GET /r/{token}` — the form a reset link opens, for its member.
pub async fn page(
    State(pages): State<SignInPages>,
    Path(raw): Path<String>,
) -> Result<Response, ApiError> {
    let Some(open) = open(&pages, &raw).await? else {
        return unusable(&pages).await;
    };
    form_page(&pages, StatusCode::OK, open, None).await
}

#[derive(Deserialize)]
pub struct ResetForm {
    password: String,
    confirmation: String,
}

/// `POST /r/{token}` — the new password, then a page saying to sign in again.
pub async fn reset(
    _: SameOrigin,
    State(pages): State<SignInPages>,
    State(reset): State<Arc<ResetPassword>>,
    Path(raw): Path<String>,
    Form(form): Form<ResetForm>,
) -> Result<Response, ApiError> {
    let Ok(token) = ResetToken::parse(&raw) else {
        return unusable(&pages).await;
    };
    let changed = reset
        .execute(
            &token,
            &form.password,
            &form.confirmation,
            OffsetDateTime::now_utc(),
        )
        .await;
    let code = match changed {
        Ok(member) => {
            tracing::info!(user_id = %member, "set a password with a reset link");
            let page = PasswordChangedPage {
                frame: pages.frame(Appearance::default()).await?,
                web_app: reset.web_app_entry(),
            };
            return Ok(unreferred(render(StatusCode::OK, &page, None)));
        }
        Err(AuthError::ResetUnusable) => return unusable(&pages).await,
        Err(AuthError::PasswordTooShort) => "weak_password",
        Err(AuthError::PasswordMismatch) => "password_mismatch",
        Err(other) => return Err(ApiError::internal(anyhow::Error::from(other))),
    };
    let Some(open) = open(&pages, &raw).await? else {
        return unusable(&pages).await;
    };
    form_page(&pages, StatusCode::BAD_REQUEST, open, Some(code)).await
}

#[cfg(test)]
mod tests;
