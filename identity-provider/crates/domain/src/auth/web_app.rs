use url::Url;

use crate::ValidationError;
use crate::identity::InstanceOrigin;

use super::ClientId;

/// Where the official web app lives once it is published. `WEB_APP_ORIGIN` overrides it in any
/// environment, and development defaults to the web client of a checkout.
pub const OFFICIAL_WEB_APP_ORIGIN: Option<&str> = None;

/// The official web app, by its origin: someone who joins by invitation lands in it, signed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebApp {
    origin: String,
    client_id: ClientId,
}

impl WebApp {
    /// An `http(s)` origin: a scheme, a host and maybe a port, nothing after.
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let refuse =
            || ValidationError::new("web app", "an http(s) origin, like https://app.example");
        let url = Url::parse(raw.trim()).map_err(|_| refuse())?;
        let fine = matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none();
        if !fine {
            return Err(refuse());
        }
        let origin = url.origin().ascii_serialization();
        let client_id =
            ClientId::parse(&format!("{origin}/oauth-client.json")).map_err(|_| refuse())?;
        Ok(Self { origin, client_id })
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// What it presents itself as: the document it serves at `/oauth-client.json`.
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// Where it opens on `instance`: `{origin}/?instance={domain}`.
    pub fn entry(&self, instance: &InstanceOrigin) -> String {
        let domain: String =
            url::form_urlencoded::byte_serialize(instance.domain().to_string().as_bytes())
                .collect();
        format!("{}/?instance={domain}", self.origin)
    }
}

#[cfg(test)]
mod tests;
