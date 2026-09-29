use std::fmt;

use crate::ValidationError;

/// The host part of an address or an actor URI: `host[:port]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Domain(String);

impl Domain {
    /// Lowercased: hosts are case-insensitive, and a mixed-case copy of our own domain must
    /// still read as ours.
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let refuse = || ValidationError::new("domain", "a host name, optionally :port");
        let domain = raw.to_ascii_lowercase();
        let (host, port) = match domain.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (domain.as_str(), None),
        };
        let host_ok = !host.is_empty()
            && host
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
            && !host.starts_with(['.', '-'])
            && !host.ends_with(['.', '-']);
        let port_ok = port.is_none_or(|p| p.parse::<u16>().is_ok_and(|p| p > 0));
        if host_ok && port_ok {
            Ok(Self(domain))
        } else {
            Err(refuse())
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `user@domain` — how an account on any instance is named.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FederatedAddress {
    user: String,
    domain: Domain,
}

impl FederatedAddress {
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let (user, domain) = raw
            .strip_prefix('@')
            .unwrap_or(raw)
            .split_once('@')
            .ok_or_else(|| ValidationError::new("address", "user@domain"))?;
        let user_ok = !user.is_empty()
            && !user
                .chars()
                .any(|c| c == '@' || c == '/' || c.is_whitespace() || c.is_control());
        if !user_ok {
            return Err(ValidationError::new("address", "user@domain"));
        }
        Ok(Self {
            user: user.to_owned(),
            domain: Domain::parse(domain)?,
        })
    }

    pub fn user(&self) -> &str {
        &self.user
    }

    pub fn domain(&self) -> &Domain {
        &self.domain
    }
}

impl fmt::Display for FederatedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.user, self.domain)
    }
}

#[cfg(test)]
mod tests;
