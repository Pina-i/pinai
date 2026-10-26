use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use time::{Duration, OffsetDateTime};

use crate::{InvitationId, UserId, ValidationError};

/// How long an invitation lets someone in.
pub const INVITATION_TTL: Duration = Duration::days(7);
/// How long an invitation used, revoked or expired is kept before it is swept.
pub const INVITATION_RETENTION: Duration = Duration::days(30);

/// The secret an invitation link carries: 256 random bits, URL-safe base64 without padding. Only
/// its SHA-256 is kept.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct InvitationToken(String);

impl InvitationToken {
    /// 32 bytes, base64url without padding.
    pub const LEN: usize = 43;

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// A token as a link brings it back. Anything else names no invitation.
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let refuse = || ValidationError::new("invitation", "43 characters of URL-safe base64");
        if raw.len() != Self::LEN {
            return Err(refuse());
        }
        match URL_SAFE_NO_PAD.decode(raw) {
            Ok(bytes) if bytes.len() == 32 => Ok(Self(raw.to_owned())),
            _ => Err(refuse()),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for InvitationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InvitationToken(..)")
    }
}

/// An invitation as the store keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    pub id: InvitationId,
    pub created_by: UserId,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub used_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
}

impl Invitation {
    /// It lets someone in: unused, unrevoked and unexpired.
    pub fn is_open(&self, now: OffsetDateTime) -> bool {
        self.used_at.is_none() && self.revoked_at.is_none() && now < self.expires_at
    }

    /// When it stopped letting anyone in: used, revoked or expired, whichever came first.
    pub fn ended_at(&self) -> OffsetDateTime {
        [self.used_at, self.revoked_at]
            .into_iter()
            .flatten()
            .fold(self.expires_at, OffsetDateTime::min)
    }
}

/// An open invitation, as its link shows it and its admins list it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenInvitation {
    pub id: InvitationId,
    /// Its creator's display name.
    pub inviter: Option<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[cfg(test)]
mod tests;
