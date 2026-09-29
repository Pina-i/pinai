use std::fmt;

use crate::ValidationError;

/// An MLSMessage: opaque to the server, never empty, at most 64 KiB — ample for application
/// messages (a text DM is ~200 bytes), and a bound on what a sender or a peer can make us store.
#[derive(Clone, PartialEq, Eq)]
pub struct MlsCiphertext(Vec<u8>);

impl MlsCiphertext {
    pub const MAX_BYTES: usize = 64 * 1024;

    pub fn parse(bytes: Vec<u8>) -> Result<Self, ValidationError> {
        if bytes.is_empty() {
            return Err(ValidationError::new("mls_ciphertext", "is empty"));
        }
        if bytes.len() > Self::MAX_BYTES {
            return Err(ValidationError::new(
                "mls_ciphertext",
                format!("exceeds {} bytes", Self::MAX_BYTES),
            ));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for MlsCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MlsCiphertext({} bytes)", self.0.len())
    }
}

#[cfg(test)]
mod tests;
