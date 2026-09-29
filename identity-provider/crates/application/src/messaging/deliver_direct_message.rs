use std::sync::Arc;

use domain::messaging::{
    DeliveryStatus, DirectDelivery, MessageFederation, MessageNotifier, Messages,
};

/// The second half of a message to another instance, run once the send has been answered: its
/// outcome is recorded on the message, and a failure is pushed to the sender so its client can
/// send the message again.
pub struct DeliverDirectMessage {
    federation: Arc<dyn MessageFederation>,
    messages: Arc<dyn Messages>,
    notifier: Arc<dyn MessageNotifier>,
}

impl DeliverDirectMessage {
    pub fn new(
        federation: Arc<dyn MessageFederation>,
        messages: Arc<dyn Messages>,
        notifier: Arc<dyn MessageNotifier>,
    ) -> Self {
        Self {
            federation,
            messages,
            notifier,
        }
    }

    pub async fn execute(&self, delivery: DirectDelivery) -> DeliveryStatus {
        let message = &delivery.message;
        let status = match self.federation.deliver_direct(&delivery).await {
            Ok(()) => DeliveryStatus::Delivered,
            Err(e) => {
                tracing::warn!(message_id = %message.id, inbox = %delivery.to.inbox, error = %e, "DM delivery failed");
                DeliveryStatus::Failed
            }
        };
        if let Err(e) = self.messages.set_delivery(message.id, status).await {
            tracing::warn!(message_id = %message.id, error = ?e, "failed to record the DM delivery outcome");
        }
        if status == DeliveryStatus::Failed {
            self.notifier.delivery_failed(delivery.from.id, message);
        }
        status
    }
}

#[cfg(test)]
mod tests;
