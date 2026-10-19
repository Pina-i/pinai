use super::*;

#[tokio::test]
async fn a_search_finds_the_handles_holding_the_query() {
    let (alice, bob) = (account("alice"), account("bob"));
    contract::a_search_finds_the_handles_holding_the_query(
        &InMemoryAccounts::with([alice.clone(), bob.clone()]),
        &alice,
        &bob,
    )
    .await;
}

#[tokio::test]
async fn a_search_takes_its_query_literally() {
    let alice = account("alice");
    contract::a_search_takes_its_query_literally(&InMemoryAccounts::with([alice.clone()]), &alice)
        .await;
}

#[tokio::test]
async fn every_account_counts() {
    contract::every_account_counts(&InMemoryAccounts::with([account("alice"), account("bob")]))
        .await;
}
