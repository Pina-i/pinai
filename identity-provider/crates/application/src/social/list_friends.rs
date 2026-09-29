use std::sync::Arc;

use domain::UserId;
use domain::social::{FriendView, SocialError, SocialGraph};

/// `GET /api/friends`.
pub struct ListFriends {
    graph: Arc<dyn SocialGraph>,
}

impl ListFriends {
    pub fn new(graph: Arc<dyn SocialGraph>) -> Self {
        Self { graph }
    }

    pub async fn execute(&self, owner: UserId) -> Result<Vec<FriendView>, SocialError> {
        Ok(self.graph.friends(owner).await?)
    }
}
