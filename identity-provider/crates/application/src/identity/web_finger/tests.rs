use domain::identity::testing::{InMemoryAccounts, account};

use super::*;

fn web_finger(accounts: impl IntoIterator<Item = Account>) -> WebFinger {
    WebFinger::new(
        InstanceOrigin::parse("http://localhost:8080").unwrap(),
        Arc::new(InMemoryAccounts::with(accounts)),
    )
}

#[tokio::test]
async fn an_address_of_ours_is_resolved_with_or_without_its_domain() {
    let alice = account("alice");

    for resource in [
        "acct:alice_t3st0@localhost:8080",
        "acct:alice_t3st0@LOCALHOST:8080",
        "acct:alice_t3st0",
        "alice_t3st0",
    ] {
        assert_eq!(
            web_finger([alice.clone()]).execute(resource).await.unwrap(),
            Some(alice.clone()),
            "{resource:?}"
        );
    }
}

#[tokio::test]
async fn an_address_elsewhere_or_of_no_account_resolves_to_none() {
    let alice = account("alice");

    for resource in [
        "acct:alice_t3st0@idp.other.test",
        "acct:bob_t3st0@localhost:8080",
        "acct:not a handle",
    ] {
        assert_eq!(
            web_finger([alice.clone()]).execute(resource).await.unwrap(),
            None,
            "{resource:?}"
        );
    }
}
