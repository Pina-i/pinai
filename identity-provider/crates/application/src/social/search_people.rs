use std::sync::Arc;

use domain::UserId;
use domain::social::{PeopleFound, PeopleSearch, SearchQuery, SocialError};

/// `GET /api/users/search` — see identity-provider/specs/identity.md § 7.
pub struct SearchPeople {
    people: Arc<dyn PeopleSearch>,
}

impl SearchPeople {
    pub const MAX_PER_SECTION: i64 = 50;

    pub fn new(people: Arc<dyn PeopleSearch>) -> Self {
        Self { people }
    }

    pub async fn execute(
        &self,
        caller: UserId,
        query: &SearchQuery,
        limit: i64,
    ) -> Result<PeopleFound, SocialError> {
        let limit = limit.clamp(1, Self::MAX_PER_SECTION);
        Ok(self.people.search(caller, query, limit).await?)
    }
}

#[cfg(test)]
mod tests;
