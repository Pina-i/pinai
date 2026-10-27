use time::{Duration, OffsetDateTime};

use crate::{InvitationId, UserId};

/// How long an invitation lets someone in.
pub const INVITATION_TTL: Duration = Duration::days(7);
/// How long an invitation used, revoked or expired is kept before it is swept.
pub const INVITATION_RETENTION: Duration = Duration::days(30);

link_token!(
    /// The secret an invitation link carries. Only its SHA-256 is kept.
    InvitationToken,
    "invitation"
);

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
