use domain::identity::testing::{InMemoryAccounts, account};

use super::*;

fn find(accounts: impl IntoIterator<Item = Account>) -> FindAccount {
    FindAccount::new(
        InstanceOrigin::parse("http://localhost:8080").unwrap(),
        Arc::new(InMemoryAccounts::with(accounts)),
    )
}

#[tokio::test]
async fn an_account_is_found_by_the_slug_of_its_uri() {
    let alice = account("alice");

    let found = find([alice.clone()])
        .execute(&alice.username)
        .await
        .unwrap();

    assert_eq!(found, Some(alice));
}

#[tokio::test]
async fn a_slug_naming_no_account_finds_none() {
    let alice = account("alice");

    for slug in ["bob_t3st0", "alice_t3st0/inbox", "%zz", ""] {
        assert_eq!(
            find([alice.clone()]).execute(slug).await.unwrap(),
            None,
            "{slug:?}"
        );
    }
}
