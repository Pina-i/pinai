use std::sync::Arc;

use domain::identity::testing::{account, remote_actor};
use domain::messaging::testing::{
    InMemoryMessaging, MessageNotice, RecordingMessageFederation, RecordingMessageNotifier,
    contract::new_message,
};
use domain::messaging::{Conversations, Messages};

use super::*;

async fn pending(store: &InMemoryMessaging) -> DirectDelivery {
    let alice = account("alice");
    let carol = remote_actor("carol_k2m9x@idp.carol.test");
    let dm = store
        .open_dm(&alice.actor_uri, &carol.actor_uri, None)
        .await
        .unwrap();
    let message = store
        .record(&new_message(dm, &alice.actor_uri))
        .await
        .unwrap();
    DirectDelivery {
        from: alice,
        to: carol,
        message,
        reply_to: None,
    }
}

#[tokio::test]
async fn a_delivered_message_is_marked_delivered() {
    let store = Arc::new(InMemoryMessaging::default());
    let notifier = Arc::new(RecordingMessageNotifier::default());
    let federation = Arc::new(RecordingMessageFederation::default());
    let delivery = pending(&store).await;
    let deliver = DeliverDirectMessage::new(federation.clone(), store.clone(), notifier.clone());

    let outcome = deliver.execute(delivery.clone()).await;

    assert_eq!(outcome, DeliveryStatus::Delivered);
    let stored = Messages::find(&*store, delivery.message.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.delivery, DeliveryStatus::Delivered);
    assert_eq!(federation.sent().len(), 1);
    assert!(notifier.sent().is_empty());
}

#[tokio::test]
async fn an_undelivered_message_is_marked_failed_and_its_sender_told() {
    let store = Arc::new(InMemoryMessaging::default());
    let notifier = Arc::new(RecordingMessageNotifier::default());
    let delivery = pending(&store).await;
    let deliver = DeliverDirectMessage::new(
        Arc::new(RecordingMessageFederation::unreachable()),
        store.clone(),
        notifier.clone(),
    );

    let outcome = deliver.execute(delivery.clone()).await;

    assert_eq!(outcome, DeliveryStatus::Failed);
    let stored = Messages::find(&*store, delivery.message.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.delivery, DeliveryStatus::Failed);
    assert_eq!(
        notifier.sent(),
        vec![MessageNotice::DeliveryFailed(
            delivery.from.id,
            delivery.message.id
        )]
    );
}
