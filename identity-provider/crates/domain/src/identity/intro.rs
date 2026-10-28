use crate::ValidationError;
use crate::auth::AuthError;

use super::{InstanceOrigin, SavedIntroError};

/// How this instance introduces itself: on its sign-in pages, and to whoever reads its NodeInfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceIntro {
    name: String,
    description: Option<String>,
}

impl InstanceIntro {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// The name and the description as written, by `.env` or by an admin: `None` is the default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntroText {
    name: Option<String>,
    description: Option<String>,
}

impl IntroText {
    pub const MAX_NAME: usize = 40;
    pub const MAX_DESCRIPTION: usize = 90;

    /// Each trimmed, a blank one the default; within [`Self::MAX_NAME`] and
    /// [`Self::MAX_DESCRIPTION`] characters.
    pub fn parse(name: Option<&str>, description: Option<&str>) -> Result<Self, ValidationError> {
        let within = |field: &'static str, value: &str, max: usize| {
            if value.chars().count() > max {
                Err(ValidationError::new(
                    field,
                    format!("{max} characters at most"),
                ))
            } else {
                Ok(value.to_owned())
            }
        };
        Ok(Self {
            name: given(name)
                .map(|name| within("instance name", name, Self::MAX_NAME))
                .transpose()?,
            description: given(description)
                .map(|description| {
                    within("instance description", description, Self::MAX_DESCRIPTION)
                })
                .transpose()?,
        })
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// As the pages show it: the instance's host for no name.
    pub fn shown(&self, origin: &InstanceOrigin) -> InstanceIntro {
        InstanceIntro {
            name: self
                .name
                .clone()
                .unwrap_or_else(|| origin.domain().to_string()),
            description: self.description.clone(),
        }
    }
}

fn given(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim).filter(|value| !value.is_empty())
}

/// What an admin saved, whole, once they have; until then what `.env` sets.
pub fn intro_in_force(saved: Option<IntroText>, configured: IntroText) -> IntroText {
    saved.unwrap_or(configured)
}

/// The fields `.env` sets that the saved text replaces with something else.
pub fn overridden_settings(saved: &IntroText, configured: &IntroText) -> Vec<IntroField> {
    let mut overridden = Vec::new();
    if configured.name.is_some() && configured.name != saved.name {
        overridden.push(IntroField::Name);
    }
    if configured.description.is_some() && configured.description != saved.description {
        overridden.push(IntroField::Description);
    }
    overridden
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntroField {
    Name,
    Description,
}

impl IntroField {
    /// The variable that sets it in `.env`.
    pub fn env_var(self) -> &'static str {
        match self {
            Self::Name => "INSTANCE_NAME",
            Self::Description => "INSTANCE_DESCRIPTION",
        }
    }

    pub fn noun(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Description => "description",
        }
    }
}

/// Showing or changing the intro, which only admins do.
#[derive(Debug, thiserror::Error)]
pub enum IntroError {
    #[error("only an admin may do this")]
    NotAdmin,
    #[error(transparent)]
    Invalid(#[from] ValidationError),
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

impl From<AuthError> for IntroError {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::NotAdmin => Self::NotAdmin,
            other => Self::Unexpected(other.into()),
        }
    }
}

impl From<SavedIntroError> for IntroError {
    fn from(error: SavedIntroError) -> Self {
        match error {
            SavedIntroError::Unexpected(e) => Self::Unexpected(e),
        }
    }
}

#[cfg(test)]
mod tests;
