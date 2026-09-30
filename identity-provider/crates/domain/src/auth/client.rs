use crate::ValidationError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientId(String);

impl ClientId {
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        if raw.is_empty() {
            return Err(ValidationError::new("client_id", "required"));
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An application users sign in to through this instance, and where it may send them back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub id: ClientId,
    pub redirect_uris: Vec<String>,
}

impl Client {
    /// An exact match, case included — RFC 6749 § 3.1.2.
    pub fn allows(&self, redirect_uri: &str) -> bool {
        self.redirect_uris.iter().any(|uri| uri == redirect_uri)
    }
}

/// Where a browser may be sent after signing out: back to where a client lives — the origin of
/// one of its redirect URIs. Anywhere else would make `/logout` an open redirect.
pub fn may_return_after_logout(uri: &str, clients: &[Client]) -> bool {
    let Some(target) = web_origin(uri) else {
        return false;
    };
    clients
        .iter()
        .flat_map(|client| &client.redirect_uris)
        .any(|registered| web_origin(registered).as_ref() == Some(&target))
}

fn web_origin(uri: &str) -> Option<url::Origin> {
    let url = url::Url::parse(uri).ok()?;
    matches!(url.scheme(), "http" | "https").then(|| url.origin())
}

#[cfg(test)]
mod tests;
