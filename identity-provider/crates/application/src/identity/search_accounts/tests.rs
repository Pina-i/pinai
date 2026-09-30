use domain::identity::testing::{InMemoryAccounts, account};

use super::*;

#[tokio::test]
async fn a_search_answers_at_most_fifty_and_at_least_one() {
    let accounts: Vec<Account> = (0..60).map(|i| account(&format!("user{i:02}"))).collect();
    let search = SearchAccounts::new(Arc::new(InMemoryAccounts::with(accounts)));

    let user = SearchQuery::parse("user").unwrap();

    assert_eq!(search.execute(&user, 500).await.unwrap().len(), 50);
    assert_eq!(search.execute(&user, 0).await.unwrap().len(), 1);
    assert_eq!(search.execute(&user, 20).await.unwrap().len(), 20);
}
