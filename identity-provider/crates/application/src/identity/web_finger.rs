use std::sync::Arc;

use domain::identity::{Account, Accounts, AccountsError, InstanceOrigin, Recipient};

/// `GET /.well-known/webfinger`: the account an `acct:` resource names, if it is one of ours.
pub struct WebFinger {
    origin: InstanceOrigin,
    accounts: Arc<dyn Accounts>,
}

impl WebFinger {
    pub fn new(origin: InstanceOrigin, accounts: Arc<dyn Accounts>) -> Self {
        Self { origin, accounts }
    }

    /// `acct:alice_xk9mp@idp.alice.com`, `acct:alice_xk9mp`, or either without `acct:`.
    pub async fn execute(&self, resource: &str) -> Result<Option<Account>, AccountsError> {
        let acct = resource.strip_prefix("acct:").unwrap_or(resource);
        match self.origin.resolve(acct) {
            Ok(Recipient::Local(handle)) => self.accounts.find_by_handle(&handle).await,
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests;
