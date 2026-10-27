//! "Forgot your password?" on an open instance's login page: `/forgot-password`, the reset
//! request the Sign in tab folds into, and the answer that a link is on its way — see
//! identity-provider/specs/auth.md § 7.

use std::sync::Arc;

use application::auth::RequestPasswordReset;
use axum::Form;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use domain::auth::{AuthError, REQUESTED_RESET_TTL};
use serde::Deserialize;

use crate::ApiError;
use crate::background::ResetRequests;
use crate::pages::{
    Appearance, Carried, ForgotSentPage, NoticePage, SameOrigin, SignInPages, carried, render, to,
};
use crate::sign_in::{LoginAnswer, LoginView, login_view, url_with};

/// What an invite-only instance answers at `/forgot-password`: its admins give the links.
async fn not_here(pages: &SignInPages, appearance: Appearance) -> Result<Response, ApiError> {
    let page = NoticePage {
        frame: pages.frame(appearance).await?,
        title: "No password reset by mail here",
        text: format!("Ask an admin of {} for a reset link.", pages.host()).into(),
        back: None,
        sign_in: None,
    };
    Ok(render(StatusCode::NOT_FOUND, &page, None))
}

#[derive(Deserialize)]
pub struct ForgotQuery {
    #[serde(flatten)]
    carried: Carried,
}

/// `GET /forgot-password` — the login page opened on the reset request, as "Forgot password?"
/// folds it without script.
pub async fn page(
    State(pages): State<SignInPages>,
    Query(query): Query<ForgotQuery>,
) -> Result<Response, ApiError> {
    if !pages.reset_by_mail() {
        return not_here(&pages, query.carried.appearance()).await;
    }
    login_view(
        &pages,
        StatusCode::OK,
        &query.carried,
        LoginView::Forgot,
        LoginAnswer::default(),
    )
    .await
}

/// No `Debug`: it holds an address.
#[derive(Deserialize)]
pub struct ForgotForm {
    #[serde(default)]
    email: String,
    /// "Send it again": the request once more, the address in its field, nothing sent yet.
    again: Option<String>,
    #[serde(flatten)]
    carried: Carried,
}

/// `POST /forgot-password` — "Check your email", the same whatever the address: whether it has an
/// account, and whether a link is mailed, is found out once the answer is gone.
pub async fn request(
    _: SameOrigin,
    State(pages): State<SignInPages>,
    State(request_reset): State<Arc<RequestPasswordReset>>,
    State(requests): State<ResetRequests>,
    Form(form): Form<ForgotForm>,
) -> Result<Response, ApiError> {
    let appearance = form.carried.appearance();
    let accepted = request_reset.accept(&form.email);
    if let Err(AuthError::NoResetByMail) = accepted {
        return not_here(&pages, appearance).await;
    }
    let Some(request) = form.carried.request() else {
        return Ok(to("/login", &appearance.pairs()));
    };
    if let Err(error) = pages.show.request(&request).await {
        return pages.misdirected(error, appearance).await;
    }
    let again = form.again.is_some();
    let address = match accepted {
        Ok(address) if !again => address,
        Ok(_) | Err(AuthError::BadEmail(_)) => {
            let (status, error) = if again {
                (StatusCode::OK, None)
            } else {
                (StatusCode::BAD_REQUEST, Some("invalid_email"))
            };
            let answer = LoginAnswer {
                error,
                email: &form.email,
                ..LoginAnswer::default()
            };
            return login_view(&pages, status, &form.carried, LoginView::Forgot, answer).await;
        }
        Err(other) => return Err(ApiError::internal(anyhow::Error::from(other))),
    };
    let pairs = carried(&request, appearance, &[]);
    let page = ForgotSentPage {
        frame: pages.frame(appearance).await?,
        email: address.as_str().to_owned(),
        reset_minutes: REQUESTED_RESET_TTL.whole_minutes(),
        sign_in_href: url_with("/login", &pairs),
        carried: pairs,
    };
    requests.submit(address);
    Ok(render(StatusCode::OK, &page, None))
}

#[cfg(test)]
mod tests;
