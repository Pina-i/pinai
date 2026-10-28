//! How the instance introduces itself, as its admins see and change it in Settings → Instance —
//! see identity-provider/specs/identity.md § 6.

use std::sync::Arc;

use application::identity::{EditIntro, IntroDraft, ShowIntro};
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use domain::ValidationError;
use domain::identity::{IntroError, IntroText};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::ApiError;
use crate::auth::{Authenticated, not_admin};

/// The text as written: `null` for a default, the domain for the name, none for the description.
/// Both keys are required in a `PUT`, so a body missing one never resets it.
#[derive(Serialize, Deserialize)]
pub struct IntroBody {
    #[serde(deserialize_with = "Option::deserialize")]
    name: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    description: Option<String>,
}

impl From<IntroText> for IntroBody {
    fn from(text: IntroText) -> Self {
        Self {
            name: text.name().map(str::to_owned),
            description: text.description().map(str::to_owned),
        }
    }
}

impl From<IntroError> for ApiError {
    fn from(error: IntroError) -> Self {
        match error {
            IntroError::NotAdmin => not_admin(),
            IntroError::Invalid(broken) => broken.into(),
            IntroError::Unexpected(e) => ApiError::internal(e),
        }
    }
}

/// `GET /api/admin/intro`
pub async fn show(
    State(show): State<Arc<ShowIntro>>,
    Authenticated(user): Authenticated,
) -> Result<Json<IntroBody>, ApiError> {
    Ok(Json(show.execute(user).await?.into()))
}

/// `PUT /api/admin/intro` — answers the text saved, as `GET` would.
pub async fn edit(
    State(edit): State<Arc<EditIntro>>,
    Authenticated(user): Authenticated,
    body: Result<Json<IntroBody>, JsonRejection>,
) -> Result<Json<IntroBody>, ApiError> {
    // A body that is no draft: the use case still asks for an admin first.
    let draft = match body {
        Ok(Json(body)) => Ok(IntroDraft {
            name: body.name,
            description: body.description,
        }),
        Err(_) => Err(ValidationError::new(
            "instance intro",
            "a name and a description, each a string or null",
        )),
    };
    let saved = edit.execute(user, draft, OffsetDateTime::now_utc()).await?;
    tracing::info!(user_id = %user, "changed the instance's intro");
    Ok(Json(saved.into()))
}

#[cfg(test)]
mod tests;
