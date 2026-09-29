use domain::identity::testing::{InMemoryAccounts, account, remote_actor};
use domain::messaging::testing::{
    InMemoryMessaging, MessageNotice, RecordingMessageNotifier, contract::new_message,
};
use domain::messaging::{Conversations, DeliveryStatus};

use super::*;

#[tokio::test]
async fn a_delivery_left_pending_past_the_grace_is_failed_and_its_sender_told() {
    let alice = account("alice");
    let carol = remote_actor("carol_k2m9x@idp.carol.test");
    let store = Arc::new(InMemoryMessaging::default());
    let notifier = Arc::new(RecordingMessageNotifier::default());
    let dm = store
        .open_dm(&alice.actor_uri, &carol.actor_uri, None)
        .await
        .unwrap();
    let sent = store
        .record(&new_message(dm, &alice.actor_uri))
        .await
        .unwrap();
    let sweep = SweepStaleDeliveries::new(
        Duration::minutes(5),
        Arc::new(InMemoryAccounts::with([alice.clone()])),
        store.clone(),
        notifier.clone(),
    );

    let within_grace = sweep
        .execute(sent.created_at + Duration::minutes(4))
        .await
        .unwrap();
    let past_grace = sweep
        .execute(sent.created_at + Duration::minutes(6))
        .await
        .unwrap();

    assert_eq!((within_grace, past_grace), (0, 1));
    let stored = Messages::find(&*store, sent.id).await.unwrap().unwrap();
    assert_eq!(stored.delivery, DeliveryStatus::Failed);
    assert_eq!(
        notifier.sent(),
        vec![MessageNotice::DeliveryFailed(alice.id, sent.id)]
    );
}
