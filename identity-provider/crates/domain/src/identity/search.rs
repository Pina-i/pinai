use crate::ValidationError;

/// What an account search looks for, trimmed: at least 2 characters, each only itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchQuery(String);

impl SearchQuery {
    pub const MIN_CHARS: usize = 2;

    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let query = raw.trim();
        if query.chars().count() < Self::MIN_CHARS {
            return Err(ValidationError::new(
                "q",
                format!("at least {} characters", Self::MIN_CHARS),
            ));
        }
        Ok(Self(query.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests;
