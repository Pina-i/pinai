//! Blob tokens: `<user>.<attachment>.<expires_unix>.<hmac_hex>`, HMAC-SHA256 over the first three
//! parts. The format is unchanged from the legacy handler, so tokens outlive a deploy.

use std::time::Duration;

use domain::messaging::{BlobTokenError, BlobTokens};
use domain::{AttachmentId, UserId};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use time::OffsetDateTime;

type HmacSha256 = Hmac<Sha256>;

pub struct HmacBlobTokens {
    secret: Vec<u8>,
    ttl: Duration,
}

impl HmacBlobTokens {
    pub fn new(secret: Vec<u8>, ttl: Duration) -> Self {
        Self { secret, ttl }
    }

    fn mac(&self, payload: &str) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC takes any key length");
        mac.update(payload.as_bytes());
        mac
    }
}

impl BlobTokens for HmacBlobTokens {
    fn mint(&self, user: UserId, attachment: AttachmentId) -> (String, OffsetDateTime) {
        let expires_at = OffsetDateTime::now_utc() + self.ttl;
        let payload = format!(
            "{}.{}.{}",
            user.as_uuid().simple(),
            attachment.as_uuid().simple(),
            expires_at.unix_timestamp()
        );
        let mac = self.mac(&payload).finalize().into_bytes();
        (format!("{payload}.{}", encode_hex(&mac)), expires_at)
    }

    fn verify(&self, token: &str) -> Result<(UserId, AttachmentId), BlobTokenError> {
        let (payload, mac_hex) = token.rsplit_once('.').ok_or(BlobTokenError::Invalid)?;
        let mac = decode_hex(mac_hex).ok_or(BlobTokenError::Invalid)?;
        // Constant-time: `verify_slice` never short-circuits on the first differing byte.
        self.mac(payload)
            .verify_slice(&mac)
            .map_err(|_| BlobTokenError::Invalid)?;
        let mut parts = payload.split('.');
        let mut next = || parts.next().ok_or(BlobTokenError::Invalid);
        let user = uuid::Uuid::parse_str(next()?).map_err(|_| BlobTokenError::Invalid)?;
        let attachment = uuid::Uuid::parse_str(next()?).map_err(|_| BlobTokenError::Invalid)?;
        let expires: i64 = next()?.parse().map_err(|_| BlobTokenError::Invalid)?;
        if parts.next().is_some() {
            return Err(BlobTokenError::Invalid);
        }
        if OffsetDateTime::now_utc().unix_timestamp() > expires {
            return Err(BlobTokenError::Expired);
        }
        Ok((user.into(), attachment.into()))
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}
