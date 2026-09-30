use std::sync::Arc;

use domain::identity::{Account, Accounts, AccountsError, SearchQuery};

/// `GET /api/users/search`.
pub struct SearchAccounts {
    accounts: Arc<dyn Accounts>,
}

impl SearchAccounts {
    pub const MAX_RESULTS: i64 = 50;

    pub fn new(accounts: Arc<dyn Accounts>) -> Self {
        Self { accounts }
    }

    pub async fn execute(
        &self,
        query: &SearchQuery,
        limit: i64,
    ) -> Result<Vec<Account>, AccountsError> {
        self.accounts
            .search(query.as_str(), limit.clamp(1, Self::MAX_RESULTS))
            .await
    }
}

#[cfg(test)]
mod tests;
