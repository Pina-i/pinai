use std::sync::Arc;

use domain::identity::Accounts;
use domain::messaging::{MessageNotifier, Messages, MessagingError};
use time::{Duration, OffsetDateTime};

/// A delivery runs in the process that stored the message: if that process dies first, the
/// message stays `pending` for good. Once older than any delivery could take, it is failed, and
/// its sender told, so their client offers to send it again.
pub struct SweepStaleDeliveries {
    grace: Duration,
    accounts: Arc<dyn Accounts>,
    messages: Arc<dyn Messages>,
    notifier: Arc<dyn MessageNotifier>,
}

impl SweepStaleDeliveries {
    pub fn new(
        grace: Duration,
        accounts: Arc<dyn Accounts>,
        messages: Arc<dyn Messages>,
        notifier: Arc<dyn MessageNotifier>,
    ) -> Self {
        Self {
            grace,
            accounts,
            messages,
            notifier,
        }
    }

    /// How many deliveries were failed.
    pub async fn execute(&self, now: OffsetDateTime) -> Result<usize, MessagingError> {
        let failed = self
            .messages
            .fail_stale_deliveries(now - self.grace)
            .await?;
        for message in &failed {
            // A sender whose account is gone has no client to tell.
            if let Some(sender) = self.accounts.find_by_uri(&message.sender).await? {
                self.notifier.delivery_failed(sender.id, message);
            }
        }
        Ok(failed.len())
    }
}

#[cfg(test)]
mod tests;
