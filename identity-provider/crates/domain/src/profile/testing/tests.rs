use super::*;

#[tokio::test]
async fn an_account_is_found_with_its_profile() {
    let profiles = InMemoryProfiles::default();
    contract::an_account_is_found_with_its_profile(&profiles, &profiles).await;
}

#[tokio::test]
async fn an_edit_writes_every_field() {
    let profiles = InMemoryProfiles::default();
    contract::an_edit_writes_every_field(&profiles, &profiles).await;
}

#[tokio::test]
async fn an_avatar_is_shown_until_cleared() {
    let profiles = InMemoryProfiles::default();
    contract::an_avatar_is_shown_until_cleared(&profiles, &profiles).await;
}

#[tokio::test]
async fn a_peers_profile_is_cached_and_kept_by_every_friendship_with_it() {
    let profiles = InMemoryProfiles::default();
    contract::a_peers_profile_is_cached_and_kept_by_every_friendship_with_it(&profiles, &profiles)
        .await;
}

#[tokio::test]
async fn an_actor_is_heard_of_by_the_accounts_that_befriended_it() {
    let profiles = InMemoryProfiles::default();
    contract::an_actor_is_heard_of_by_the_accounts_that_befriended_it(&profiles, &profiles).await;
}

#[tokio::test]
async fn an_account_reaches_its_accepted_friends_on_other_instances() {
    let profiles = InMemoryProfiles::default();
    contract::an_account_reaches_its_accepted_friends_on_other_instances(&profiles, &profiles)
        .await;
}

#[tokio::test]
async fn a_card_holds_what_an_account_here_shows_and_dates_a_friendship() {
    let profiles = InMemoryProfiles::default();
    contract::a_card_holds_what_an_account_here_shows_and_dates_a_friendship(&profiles, &profiles)
        .await;
}

#[tokio::test]
async fn a_card_knows_another_instances_account_by_a_friendship_or_a_conversation() {
    let profiles = InMemoryProfiles::default();
    contract::a_card_knows_another_instances_account_by_a_friendship_or_a_conversation(
        &profiles, &profiles, &profiles,
    )
    .await;
}

#[tokio::test]
async fn no_card_for_an_account_this_instance_does_not_hold() {
    let profiles = InMemoryProfiles::default();
    contract::no_card_for_an_account_this_instance_does_not_hold(&profiles, &profiles).await;
}
