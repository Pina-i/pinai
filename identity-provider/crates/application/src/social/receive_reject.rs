use std::sync::Arc;

use domain::UserId;
use domain::identity::ActorUri;
use domain::social::{SocialError, SocialGraph};

/// An inbound `Reject`: a remote actor declined the inbox owner's request. Never announced — a
/// declined request just stops existing; a redelivered Reject changes nothing.
pub struct ReceiveReject {
    graph: Arc<dyn SocialGraph>,
}

impl ReceiveReject {
    pub fn new(graph: Arc<dyn SocialGraph>) -> Self {
        Self { graph }
    }

    pub async fn execute(&self, owner: UserId, rejecter: ActorUri) -> Result<(), SocialError> {
        self.graph.drop_outgoing(owner, &rejecter).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
