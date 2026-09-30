use crate::ValidationError;

use super::{ActorUri, Domain, FederatedAddress, Handle};

/// Where an address points: one of our accounts, or an account on another instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    Local(Handle),
    Remote(FederatedAddress),
}

/// This instance: the scheme and domain every local actor URI starts with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceOrigin {
    scheme: String,
    domain: Domain,
}

impl InstanceOrigin {
    /// From the issuer URL, e.g. `https://idp.alice.com` or `http://localhost:8080`.
    pub fn parse(issuer: &str) -> Result<Self, ValidationError> {
        let root = ActorUri::parse(issuer)?;
        Ok(Self {
            scheme: root.scheme().to_owned(),
            domain: root.domain().clone(),
        })
    }

    pub fn actor_uri(&self, handle: &Handle) -> ActorUri {
        ActorUri::parse(&format!(
            "{}://{}/users/{}",
            self.scheme,
            self.domain,
            handle.as_str()
        ))
        .expect("a handle is a valid path segment")
    }

    /// Where a remote account is expected to live, before WebFinger says: peers are assumed to
    /// speak our scheme.
    pub fn conventional_uri(&self, address: &FederatedAddress) -> Option<ActorUri> {
        ActorUri::parse(&format!(
            "{}://{}/users/{}",
            self.scheme,
            address.domain(),
            address.user()
        ))
        .ok()
    }

    pub fn address_of(&self, handle: &Handle) -> FederatedAddress {
        FederatedAddress::parse(&format!("{}@{}", handle.as_str(), self.domain))
            .expect("a handle is a valid address user")
    }

    /// What a user typed to name someone: a bare name is one of our accounts, anything else
    /// must be a full address.
    pub fn resolve(&self, raw: &str) -> Result<Recipient, ValidationError> {
        let named = raw.strip_prefix('@').unwrap_or(raw);
        if named.contains('@') {
            self.recipient(&FederatedAddress::parse(named)?)
        } else {
            Ok(Recipient::Local(Handle::parse(named)?))
        }
    }

    pub fn recipient(&self, address: &FederatedAddress) -> Result<Recipient, ValidationError> {
        if *address.domain() == self.domain {
            Ok(Recipient::Local(Handle::parse(address.user())?))
        } else {
            Ok(Recipient::Remote(address.clone()))
        }
    }

    /// The handle a URI of ours names — exactly `/users/{handle}`, nothing below it.
    pub fn local_handle(&self, uri: &ActorUri) -> Option<Handle> {
        if !self.owns(uri) {
            return None;
        }
        let segment = uri.path().strip_prefix("/users/")?;
        if segment.contains('/') {
            return None;
        }
        Handle::parse(segment).ok()
    }

    /// Where this instance is reached: `{scheme}://{domain}`.
    pub fn base_url(&self) -> String {
        format!("{}://{}", self.scheme, self.domain)
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    pub fn owns(&self, uri: &ActorUri) -> bool {
        uri.scheme() == self.scheme && *uri.domain() == self.domain
    }
}

#[cfg(test)]
mod tests;
