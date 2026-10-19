use serde::{Deserialize, Serialize};
use url::Url;

use crate::ValidationError;
use crate::identity::InstanceOrigin;

/// A client is the URL of the document it publishes about itself — the OAuth Client ID Metadata
/// Document draft — so an instance signs in clients it has never heard of.
// Kept as the string it was parsed from: it travels inside every request and ticket.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientId(String);

impl ClientId {
    pub const MAX_LEN: usize = 2048;

    /// An `http(s)` URL with a path, in normalised form: the id is compared as a string, so
    /// `/./`, `..`, an upper-case host or a default port would make two ids of one document.
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let refuse = || {
            ValidationError::new(
                "client_id",
                "a normalised http(s) URL with a path, of 2 KiB at most",
            )
        };
        if raw.len() > Self::MAX_LEN {
            return Err(refuse());
        }
        let url = Url::parse(raw).map_err(|_| refuse())?;
        let fine = matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.path() != "/"
            && url.as_str() == raw;
        if fine {
            Ok(Self(url.into()))
        } else {
            Err(refuse())
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn url(&self) -> Url {
        Url::parse(&self.0).expect("checked at parse")
    }

    pub fn host(&self) -> String {
        self.url().host_str().expect("checked at parse").to_owned()
    }

    /// Where it lives, as an address bar shows it: the host, and a port other than the scheme's.
    pub fn authority(&self) -> String {
        match self.url().port() {
            Some(port) => format!("{}:{port}", self.host()),
            None => self.host(),
        }
    }

    fn is_https(&self) -> bool {
        self.url().scheme() == "https"
    }

    fn origin(&self) -> url::Origin {
        self.url().origin()
    }

    /// The private-use scheme a native client may claim: its host, reversed — RFC 8252 § 7.1.
    fn reversed_host(&self) -> Option<String> {
        match self.url().host()? {
            url::Host::Domain(domain) => {
                Some(domain.split('.').rev().collect::<Vec<_>>().join("."))
            }
            _ => None,
        }
    }
}

/// What this instance takes from a client document. A development instance's clients live on
/// `localhost` over plain `http`, and its native clients have no domain of their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientPolicy {
    pub allow_http: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientKind {
    /// Served from its own origin, where its redirect URIs live.
    Web,
    /// Installed on a device, called back through a scheme or the loopback interface.
    Native,
}

/// A client's document as published: untrusted until [`Client::from_document`] took it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientDocument {
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_type: Option<String>,
    pub redirect_uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
}

/// An application users sign in to through this instance, as its document describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub id: ClientId,
    pub name: String,
    pub kind: ClientKind,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    /// Asks to stay signed in on its device: only a native client may.
    pub offline_access: bool,
}

/// Never a native client's own scheme: each would hand the code to something else.
const RESERVED_SCHEMES: [&str; 10] = [
    "http",
    "https",
    "javascript",
    "data",
    "file",
    "blob",
    "about",
    "vbscript",
    "ws",
    "wss",
];

impl Client {
    pub const MAX_NAME: usize = 80;
    pub const MAX_URIS: usize = 10;

    pub fn from_document(
        id: ClientId,
        document: ClientDocument,
        policy: ClientPolicy,
    ) -> Result<Self, ValidationError> {
        if document.client_id != id.as_str() {
            return Err(ValidationError::new(
                "client_id",
                "the document's own URL, exactly",
            ));
        }
        if !id.is_https() && !policy.allow_http {
            return Err(ValidationError::new("client_id", "https"));
        }
        if !matches!(
            document.token_endpoint_auth_method.as_deref(),
            None | Some("none")
        ) {
            return Err(ValidationError::new(
                "token_endpoint_auth_method",
                "none: confidential clients aren't supported",
            ));
        }
        let kind = match document.application_type.as_deref() {
            None | Some("web") => ClientKind::Web,
            Some("native") => ClientKind::Native,
            Some(_) => return Err(ValidationError::new("application_type", "web or native")),
        };
        let name = match document.client_name.as_deref().map(str::trim) {
            None | Some("") => id.host(),
            Some(name) if name.chars().count() <= Self::MAX_NAME => name.to_owned(),
            Some(_) => return Err(ValidationError::new("client_name", "80 characters at most")),
        };
        let fits = |uri: &String| redirect_fits(uri, &id, kind, policy);
        if document.redirect_uris.is_empty()
            || document.redirect_uris.len() > Self::MAX_URIS
            || !document.redirect_uris.iter().all(fits)
        {
            return Err(ValidationError::new(
                "redirect_uris",
                "1 to 10, each where this kind of client lives",
            ));
        }
        if document.post_logout_redirect_uris.len() > Self::MAX_URIS
            || !document.post_logout_redirect_uris.iter().all(fits)
        {
            return Err(ValidationError::new(
                "post_logout_redirect_uris",
                "10 at most, each where this kind of client lives",
            ));
        }
        let offline_access = kind == ClientKind::Native
            && document
                .scope
                .as_deref()
                .is_some_and(|scope| scope.split_whitespace().any(|s| s == "offline_access"));
        Ok(Self {
            id,
            name,
            kind,
            redirect_uris: document.redirect_uris,
            post_logout_redirect_uris: document.post_logout_redirect_uris,
            offline_access,
        })
    }

    /// An exact match, case included — RFC 6749 § 3.1.2.
    pub fn allows(&self, redirect_uri: &str) -> bool {
        self.redirect_uris.iter().any(|uri| uri == redirect_uri)
    }

    /// Where `/logout` may send a browser back to: a URI the client listed, exactly — anything
    /// else would make the endpoint an open redirect.
    pub fn may_return_to(&self, uri: &str) -> bool {
        self.post_logout_redirect_uris
            .iter()
            .any(|listed| listed == uri)
    }

    /// The document this client would publish.
    pub fn document(&self) -> ClientDocument {
        ClientDocument {
            client_id: self.id.as_str().to_owned(),
            client_name: Some(self.name.clone()),
            application_type: Some(
                match self.kind {
                    ClientKind::Web => "web",
                    ClientKind::Native => "native",
                }
                .to_owned(),
            ),
            redirect_uris: self.redirect_uris.clone(),
            post_logout_redirect_uris: self.post_logout_redirect_uris.clone(),
            scope: Some(
                if self.offline_access {
                    "openid profile email offline_access"
                } else {
                    "openid profile email"
                }
                .to_owned(),
            ),
            token_endpoint_auth_method: Some("none".to_owned()),
        }
    }
}

/// Where a redirect may point. A web client's lie on its own origin; a native client's on the
/// loopback interface (RFC 8252 § 7.3) or under a scheme named after its own domain (§ 7.1), so no
/// document can claim another app's scheme.
fn redirect_fits(uri: &str, id: &ClientId, kind: ClientKind, policy: ClientPolicy) -> bool {
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    if url.as_str() != uri || url.fragment().is_some() || !url.username().is_empty() {
        return false;
    }
    match (kind, url.scheme()) {
        (ClientKind::Web, "https") => url.origin() == id.origin(),
        (ClientKind::Web, "http") => policy.allow_http && url.origin() == id.origin(),
        (ClientKind::Web, _) => false,
        (ClientKind::Native, "http") => {
            matches!(
                url.host(),
                Some(url::Host::Ipv4(ip)) if ip.is_loopback()
            ) || matches!(url.host(), Some(url::Host::Ipv6(ip)) if ip.is_loopback())
        }
        (ClientKind::Native, scheme) => {
            !RESERVED_SCHEMES.contains(&scheme)
                && (policy.allow_http || id.reversed_host().as_deref() == Some(scheme))
        }
    }
}

/// Where every instance publishes the official desktop app's document.
pub const DESKTOP_DOCUMENT_PATH: &str = "/clients/desktop.json";
/// The desktop app's callback: the Pina-i organisation's GitHub Pages domain, reversed.
pub const DESKTOP_REDIRECT_URI: &str = "io.github.pina-i:/callback";

/// The official desktop app, as every instance describes it: its document is served here, so a
/// desktop sign-in depends on nothing but the user's own instance.
pub fn desktop_client(origin: &InstanceOrigin) -> Client {
    Client {
        id: ClientId::parse(&format!("{}{DESKTOP_DOCUMENT_PATH}", origin.base_url()))
            .expect("an instance's base URL and a fixed path"),
        name: "Pīna'i desktop".to_owned(),
        kind: ClientKind::Native,
        redirect_uris: vec![DESKTOP_REDIRECT_URI.to_owned()],
        post_logout_redirect_uris: Vec::new(),
        offline_access: true,
    }
}

#[cfg(test)]
mod tests;
