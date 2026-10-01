use std::sync::Arc;

use domain::UserId;
use domain::social::testing::InMemoryContactPolicies;

use super::*;

#[tokio::test]
async fn the_setting_is_saved_and_answered() {
    let policies = Arc::new(InMemoryContactPolicies::default());
    let (alice, bob) = (UserId::generate(), UserId::generate());

    let set = SetContactPolicy::new(policies.clone())
        .execute(alice, ContactPolicy::Everyone)
        .await
        .unwrap();

    assert_eq!(set, ContactPolicy::Everyone);
    assert_eq!(policies.get(alice).await.unwrap(), ContactPolicy::Everyone);
    assert_eq!(
        policies.get(bob).await.unwrap(),
        ContactPolicy::FriendsAndGroups
    );
}
