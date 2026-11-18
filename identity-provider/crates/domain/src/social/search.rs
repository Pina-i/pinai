use unicode_normalization::char::is_combining_mark;

use crate::ValidationError;

/// What a search for people by name looks for, trimmed, each character only itself: 2 characters
/// besides combining marks, which fold away, 100 in all at most, none a control character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchQuery(String);

impl SearchQuery {
    pub const MIN_CHARS: usize = 2;
    /// Names hold 50 at most; one typed with its accents apart takes more.
    pub const MAX_CHARS: usize = 100;

    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let query = raw.trim();
        if query.chars().any(char::is_control) {
            return Err(ValidationError::new("q", "no control characters"));
        }
        if query.chars().filter(|c| !is_combining_mark(*c)).count() < Self::MIN_CHARS {
            return Err(ValidationError::new(
                "q",
                format!(
                    "at least {} characters besides combining marks",
                    Self::MIN_CHARS
                ),
            ));
        }
        // Every character counts here, so combining marks can't be stacked past the bound.
        if query.chars().count() > Self::MAX_CHARS {
            return Err(ValidationError::new(
                "q",
                format!("at most {} characters", Self::MAX_CHARS),
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
