use axum_extra::extract::cookie::Key;
use hkdf::Hkdf;
use sha2::Sha256;

/// The keys `SESSION_SECRET` makes: the session cookie's, and the attachment links'. Each is
/// derived from the whole secret (HKDF-SHA256) under a label of its own, so no two purposes
/// share a key and no byte of the secret is left out.
pub struct SessionKeys {
    pub cookies: Key,
    pub attachment_links: Vec<u8>,
}

impl SessionKeys {
    pub fn from_secret(secret: &str) -> Self {
        let derive = Hkdf::<Sha256>::new(None, secret.as_bytes());
        let mut cookies = [0u8; 64];
        let mut attachment_links = [0u8; 32];
        derive
            .expand(b"pinai idp: session cookies", &mut cookies)
            .expect("64 bytes is within HKDF-SHA256's output");
        derive
            .expand(b"pinai idp: attachment links", &mut attachment_links)
            .expect("32 bytes is within HKDF-SHA256's output");
        Self {
            cookies: Key::from(&cookies),
            attachment_links: attachment_links.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests;
