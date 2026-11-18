use std::fmt;

use crate::ValidationError;

/// The host part of an address or an actor URI: `host[:port]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Domain(String);

impl Domain {
    /// Lowercased, the port without leading zeros: hosts are case-insensitive, and a copy of our
    /// own domain written otherwise must still read as ours.
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let refuse = || ValidationError::new("domain", "a host name, optionally :port");
        let domain = raw.to_ascii_lowercase();
        let (host, port) = match domain.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (domain.as_str(), None),
        };
        if !is_host_name(host) {
            return Err(refuse());
        }
        let Some(port) = port else {
            return Ok(Self(domain));
        };
        match port
            .bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| port.parse::<u16>())
        {
            Some(Ok(port)) if port > 0 => Ok(Self(format!("{host}:{port}"))),
            _ => Err(refuse()),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Without its port: the host an address on this instance is mailed at.
    pub fn host(&self) -> &str {
        host_of(&self.0)
    }
}

/// A name DNS can answer, at most 253 characters of labels; one ending in a label of digits
/// only is an IPv4 address or nothing, as a URL reads it.
fn is_host_name(host: &str) -> bool {
    let last_is_numeric = host
        .rsplit('.')
        .next()
        .is_some_and(|label| label.bytes().all(|b| b.is_ascii_digit()));
    host.len() <= 253
        && host.split('.').all(is_dns_label)
        && (!last_is_numeric || host.parse::<std::net::Ipv4Addr>().is_ok())
}

/// 1–63 of `a–z0–9-`, neither starting nor ending with `-`: any other name never resolves.
fn is_dns_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// An authority's host, `host[:port]` or `[v6][:port]`, without a numeric port.
pub fn host_of(authority: &str) -> &str {
    let split = if authority.starts_with('[') {
        authority.find(']').map(|end| authority.split_at(end + 1))
    } else {
        authority
            .rfind(':')
            .filter(|&colon| !authority[..colon].contains(':'))
            .map(|colon| authority.split_at(colon))
    };
    match split {
        Some((host, port)) if port.is_empty() || is_numeric_port(port) => host,
        _ => authority,
    }
}

/// `:` and one digit or more.
fn is_numeric_port(suffix: &str) -> bool {
    suffix
        .strip_prefix(':')
        .is_some_and(|port| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
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
