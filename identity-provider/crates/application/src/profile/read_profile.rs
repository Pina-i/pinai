use std::sync::Arc;

use domain::UserId;
use domain::identity::{Accounts, ActorUri};
use domain::profile::{ProfileCard, ProfileCards, ProfileError, ProfileRefresh};
use time::OffsetDateTime;

/// `GET /api/profiles?actor=`: the profile card one account reads of another — see
/// identity-provider/specs/profile-and-settings.md § 1.
pub struct ReadProfile {
    accounts: Arc<dyn Accounts>,
    cards: Arc<dyn ProfileCards>,
    refresh: Arc<dyn ProfileRefresh>,
}

impl ReadProfile {
    pub fn new(
        accounts: Arc<dyn Accounts>,
        cards: Arc<dyn ProfileCards>,
        refresh: Arc<dyn ProfileRefresh>,
    ) -> Self {
        Self {
            accounts,
            cards,
            refresh,
        }
    }

    /// `None` when the viewer may not be shown the account, or it is not one this instance holds.
    pub async fn execute(
        &self,
        viewer: UserId,
        actor: &ActorUri,
    ) -> Result<Option<ProfileCard>, ProfileError> {
        let viewer = self
            .accounts
            .find(viewer)
            .await
            .map_err(|e| ProfileError::Unexpected(e.into()))?
            .ok_or(ProfileError::UnknownUser)?;
        let Some(facts) = self.cards.facts(&viewer, actor).await? else {
            return Ok(None);
        };
        let stale = facts.is_stale(OffsetDateTime::now_utc());
        let card = facts.card();
        if stale && card.is_some() {
            self.refresh.refresh(actor);
        }
        Ok(card)
    }
}

#[cfg(test)]
mod tests;
