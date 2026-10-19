use crate::ValidationError;

/// The part of a username its owner chooses; the instance appends `_` and a suffix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsernameChoice(String);

impl UsernameChoice {
    /// 2–32 characters of `a–z`, `0–9`, `_` and `.`, with no dot at either end or next to another.
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let refuse = || {
            ValidationError::new(
                "username",
                "2–32 characters: lowercase letters, digits, _ and . (no dot at the ends or twice in a row)",
            )
        };
        let allowed =
            |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.';
        if !(2..=32).contains(&raw.len())
            || !raw.chars().all(allowed)
            || raw.starts_with('.')
            || raw.ends_with('.')
            || raw.contains("..")
        {
            return Err(refuse());
        }
        Ok(Self(raw.to_owned()))
    }

    /// The chosen part an account signing up by display name gets: the name in ASCII
    /// ("Hōkū" → `hoku`), lowercase, every run of anything else one `_`, at most 32 characters.
    /// A name with less than 2 characters left is `user`; the suffix keeps it unique anyway.
    pub fn derived_from(display_name: &str) -> Self {
        let ascii = deunicode::deunicode(display_name).to_ascii_lowercase();
        let mut derived = String::with_capacity(ascii.len());
        for c in ascii.chars() {
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                derived.push(c);
            } else if !derived.is_empty() && !derived.ends_with('_') {
                derived.push('_');
            }
        }
        derived.truncate(32);
        let derived = derived.trim_end_matches('_');
        Self::parse(derived).unwrap_or_else(|_| Self("user".to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The random part the instance appends to a chosen name: 5 characters of `a–z0–9`. It holds no
/// `_`, so a handle always splits back at its last underscore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleSuffix(String);

impl HandleSuffix {
    pub const ALPHABET: &'static str = "abcdefghijklmnopqrstuvwxyz0123456789";
    pub const LEN: usize = 5;

    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        if raw.len() == Self::LEN && raw.chars().all(|c| Self::ALPHABET.contains(c)) {
            Ok(Self(raw.to_owned()))
        } else {
            Err(ValidationError::new(
                "handle suffix",
                "5 characters: a–z, 0–9",
            ))
        }
    }
}

/// A local account's handle — `{chosen name}_{suffix}`, the last segment of its actor URI.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(transparent)]
pub struct Handle(String);

impl Handle {
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let (choice, suffix) = raw
            .rsplit_once('_')
            .ok_or_else(|| ValidationError::new("handle", "a chosen name, `_` and a suffix"))?;
        Ok(Self::compose(
            &UsernameChoice::parse(choice)?,
            &HandleSuffix::parse(suffix)?,
        ))
    }

    pub fn compose(choice: &UsernameChoice, suffix: &HandleSuffix) -> Self {
        Self(format!("{}_{}", choice.0, suffix.0))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests;
