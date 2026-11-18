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

#[tokio::test]
async fn our_domain_with_our_schemes_default_port_is_ours() {
    let alice = account("alice");
    let web_finger = WebFinger::new(
        InstanceOrigin::parse("https://idp.alice.test").unwrap(),
        Arc::new(InMemoryAccounts::with([alice.clone()])),
    );

    for resource in [
        "acct:alice_t3st0@idp.alice.test",
        "acct:alice_t3st0@idp.alice.test:443",
    ] {
        assert_eq!(
            web_finger.execute(resource).await.unwrap(),
            Some(alice.clone()),
            "{resource:?}"
        );
    }
    assert_eq!(
        web_finger
            .execute("acct:alice_t3st0@idp.alice.test:8443")
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn a_sign_up_still_to_confirm_is_not_found() {
    let kai = account("kai");
    let accounts = InMemoryAccounts::default();
    accounts.signing_up(kai.clone());
    let web_finger = WebFinger::new(
        InstanceOrigin::parse("http://localhost:8080").unwrap(),
        Arc::new(accounts),
    );

    assert_eq!(
        web_finger
            .execute("acct:kai_t3st0@localhost:8080")
            .await
            .unwrap(),
        None
    );
}
