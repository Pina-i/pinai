use std::sync::Arc;

use domain::UserId;
use domain::social::{ContactPolicies, ContactPolicy, SocialError};

/// `PATCH /api/privacy`: who may message the account or add it to a group.
pub struct SetContactPolicy {
    policies: Arc<dyn ContactPolicies>,
}

impl SetContactPolicy {
    pub fn new(policies: Arc<dyn ContactPolicies>) -> Self {
        Self { policies }
    }

    pub async fn execute(
        &self,
        owner: UserId,
        policy: ContactPolicy,
    ) -> Result<ContactPolicy, SocialError> {
        self.policies.set(owner, policy).await?;
        Ok(policy)
    }
}

#[cfg(test)]
mod tests;
