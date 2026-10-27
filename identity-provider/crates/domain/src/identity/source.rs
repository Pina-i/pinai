use url::Url;

use crate::ValidationError;

/// Where Pīna'i's own code is published: what an instance links unless `SOURCE_URL` says otherwise.
pub const PINAI_SOURCE_URL: &str = "https://github.com/Pina-i/pinai";

/// Where the code this instance runs can be had: AGPL-3.0 § 13 owes it to everyone who uses the
/// instance over the network, so its NodeInfo and its sign-in pages link it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceUrl(String);

impl SourceUrl {
    /// An absolute `http(s)` URL with a host and no credentials, kept normalised.
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let refuse = || {
            ValidationError::new(
                "source URL",
                "an http(s) URL, like https://git.example.org/pinai",
            )
        };
        let url = Url::parse(raw.trim()).map_err(|_| refuse())?;
        let fine = matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none();
        if !fine {
            return Err(refuse());
        }
        Ok(Self(url.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests;
