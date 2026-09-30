use std::sync::Arc;

use domain::identity::{Account, Accounts, AccountsError, ActorUri, InstanceOrigin};

/// The account at `/users/{slug}` — its actor document, collections and inbox.
pub struct FindAccount {
    origin: InstanceOrigin,
    accounts: Arc<dyn Accounts>,
}

impl FindAccount {
    pub fn new(origin: InstanceOrigin, accounts: Arc<dyn Accounts>) -> Self {
        Self { origin, accounts }
    }

    /// By the URI the slug makes, not by `Handle`: an account named before the handle rules is
    /// still reached.
    pub async fn execute(&self, slug: &str) -> Result<Option<Account>, AccountsError> {
        let Ok(uri) = ActorUri::parse(&format!("{}/users/{slug}", self.origin.base_url())) else {
            return Ok(None);
        };
        self.accounts.find_by_uri(&uri).await
    }
}

#[cfg(test)]
mod tests;
