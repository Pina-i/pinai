use crate::ValidationError;

use super::InstanceOrigin;

/// How this instance introduces itself: on its sign-in pages, and to whoever reads its NodeInfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceIntro {
    name: String,
    description: Option<String>,
}

impl InstanceIntro {
    pub const MAX_NAME: usize = 60;
    pub const MAX_DESCRIPTION: usize = 280;

    /// Each trimmed; a blank or absent name is the instance's host, a blank description none.
    pub fn new(
        origin: &InstanceOrigin,
        name: Option<&str>,
        description: Option<&str>,
    ) -> Result<Self, ValidationError> {
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
        let name = match given(name) {
            Some(name) => within("instance name", name, Self::MAX_NAME)?,
            None => origin.domain().to_string(),
        };
        let description = given(description)
            .map(|description| within("instance description", description, Self::MAX_DESCRIPTION))
            .transpose()?;
        Ok(Self { name, description })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

fn given(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim).filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests;
