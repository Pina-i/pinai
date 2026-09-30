use crate::ValidationError;

/// The name an account shows, trimmed: 1–50 characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayName(String);

impl DisplayName {
    pub const MAX_CHARS: usize = 50;

    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let name = raw.trim();
        if name.is_empty() {
            return Err(ValidationError::new(
                "display_name",
                "display_name cannot be blank",
            ));
        }
        if name.chars().count() > Self::MAX_CHARS {
            return Err(ValidationError::new(
                "display_name",
                format!("display_name must be ≤ {} characters", Self::MAX_CHARS),
            ));
        }
        Ok(Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The pronouns an account may show: a closed set, which the `users` table checks too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pronouns {
    He,
    She,
    NonBinary,
}

impl Pronouns {
    pub const ALL: [Self; 3] = [Self::He, Self::She, Self::NonBinary];

    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        Self::ALL
            .into_iter()
            .find(|pronouns| pronouns.as_str() == raw)
            .ok_or_else(|| {
                let allowed: Vec<&str> = Self::ALL.iter().map(|p| p.as_str()).collect();
                ValidationError::new(
                    "pronouns",
                    format!("pronouns must be one of: {}", allowed.join(", ")),
                )
            })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::He => "he",
            Self::She => "she",
            Self::NonBinary => "non-binary",
        }
    }
}

/// A few words about the account: at most 190 characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bio(String);

impl Bio {
    pub const MAX_CHARS: usize = 190;

    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        if raw.chars().count() > Self::MAX_CHARS {
            return Err(ValidationError::new(
                "bio",
                format!("bio must be ≤ {} characters", Self::MAX_CHARS),
            ));
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A save of the profile form: every field is sent, and pronouns or a bio left empty clear it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileEdit {
    pub display_name: DisplayName,
    pub pronouns: Option<Pronouns>,
    pub bio: Option<Bio>,
}

impl ProfileEdit {
    pub fn parse(
        display_name: Option<&str>,
        pronouns: Option<&str>,
        bio: Option<&str>,
    ) -> Result<Self, ValidationError> {
        let display_name = display_name
            .ok_or_else(|| ValidationError::new("display_name", "display_name is required"))?;
        let display_name = DisplayName::parse(display_name)?;
        let pronouns = match pronouns.map(str::trim) {
            None | Some("") => None,
            Some(raw) => Some(Pronouns::parse(raw)?),
        };
        let bio = match bio {
            None | Some("") => None,
            Some(raw) => Some(Bio::parse(raw)?),
        };
        Ok(Self {
            display_name,
            pronouns,
            bio,
        })
    }
}

#[cfg(test)]
mod tests;
