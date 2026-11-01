use crate::ValidationError;

/// The instance's Klipy API key: `KLIPY_API_KEY`, what turns on its members' GIF picker. Not a
/// secret — Klipy expects every client to hold a copy, and NodeInfo hands it to anyone — but each
/// instance has its own, so its quota and its standing with Klipy are its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KlipyKey(String);

impl KlipyKey {
    pub const MAX_LEN: usize = 256;

    /// ASCII letters, digits, `-` and `_`, at most [`Self::MAX_LEN`]: the client writes it into
    /// a URL path, so nothing that would need escaping there.
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let key = raw.trim();
        let fine = !key.is_empty()
            && key.len() <= Self::MAX_LEN
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !fine {
            return Err(ValidationError::new(
                "Klipy API key",
                "letters, digits, - and _, as the Partner Panel gives it",
            ));
        }
        Ok(Self(key.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests;
