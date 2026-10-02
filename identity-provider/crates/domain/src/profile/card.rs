use time::{Duration, OffsetDateTime};

use super::PublicProfile;

/// What this instance holds of an account for one viewer's profile card, read in one go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardFacts {
    pub profile: PublicProfile,
    /// The account is one of this instance's.
    pub local: bool,
    /// The viewer counts the account among their friends, or shares a conversation with it.
    pub known: bool,
    /// When the two became friends; `None` unless they are.
    pub friends_since: Option<OffsetDateTime>,
    /// When this instance last asked the account's instance; an account here has none.
    pub fetched_at: Option<OffsetDateTime>,
}

/// What a viewer is shown of an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileCard {
    pub profile: PublicProfile,
    pub friends_since: Option<OffsetDateTime>,
}

impl CardFacts {
    /// How long another instance's profile is shown as cached before it is asked for again.
    pub const FRESH_FOR: Duration = Duration::hours(24);

    /// The card the viewer is shown. An account here is public to every account here, like its
    /// actor document; one of another instance only to those who know it, so that the answer
    /// never tells whether anyone here has met someone.
    pub fn card(self) -> Option<ProfileCard> {
        (self.local || self.known).then_some(ProfileCard {
            profile: self.profile,
            friends_since: self.friends_since,
        })
    }

    /// Whether the cached profile is old enough to ask the account's instance for it again.
    pub fn is_stale(&self, now: OffsetDateTime) -> bool {
        self.fetched_at
            .is_some_and(|fetched| now - fetched > Self::FRESH_FOR)
    }
}

#[cfg(test)]
mod tests;
