use std::fmt;

use url::Url;

use crate::ValidationError;

use super::{Domain, FederatedAddress};

/// The canonical ActivityPub id of an account, local or remote.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActorUri {
    url: Url,
    domain: Domain,
}

impl ActorUri {
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let refuse = || ValidationError::new("actor URI", "an http(s) URL with a host");
        let url = Url::parse(raw).map_err(|_| refuse())?;
        // The URL standard reads `http:///x` as host `x`; an empty authority is malformed here.
        let has_authority = raw
            .split_once("://")
            .is_some_and(|(_, rest)| !rest.starts_with('/'));
        let plain = has_authority
            && matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some_and(|host| !host.is_empty())
            && url.query().is_none()
            && url.fragment().is_none();
        if !plain {
            return Err(refuse());
        }
        let host = url.host_str().unwrap_or_default();
        let domain = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        };
        // Only hosts an address can name (no IP-literal brackets), so `domain()` never fails.
        let domain = Domain::parse(&domain).map_err(|_| refuse())?;
        Ok(Self { url, domain })
    }

    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// The address a Pina'i-style URI (`…/users/{name}`) stands for; `None` for other shapes.
    pub fn federated_address(&self) -> Option<FederatedAddress> {
        let name = self.path().strip_prefix("/users/")?;
        if name.contains('/') {
            return None;
        }
        FederatedAddress::parse(&format!("{name}@{}", self.domain)).ok()
    }

    pub fn path(&self) -> &str {
        self.url.path()
    }

    pub fn scheme(&self) -> &str {
        self.url.scheme()
    }

    /// `host[:port]` — the port only when the URI names a non-default one.
    pub fn domain(&self) -> &Domain {
        &self.domain
    }
}

impl fmt::Display for ActorUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests;
