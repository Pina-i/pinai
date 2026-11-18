use super::*;

#[test]
fn a_name_is_folded_without_its_accents_in_lower_case() {
    assert_eq!(fold("Hōkū"), "hoku");
    assert_eq!(fold("HŌKŪ Tāne"), "hoku tane");
    assert_eq!(fold("100% Pono_"), "100% pono_");
}

#[tokio::test]
async fn names_are_found_in_three_tiers_then_by_name() {
    let search = InMemoryPeopleSearch::default();
    contract::names_are_found_in_three_tiers_then_by_name(&search, &search).await;
}

#[tokio::test]
async fn accents_and_case_never_matter_either_way() {
    let search = InMemoryPeopleSearch::default();
    contract::accents_and_case_never_matter_either_way(&search, &search).await;
}

#[tokio::test]
async fn a_query_is_taken_literally() {
    let search = InMemoryPeopleSearch::default();
    contract::a_query_is_taken_literally(&search, &search).await;
}

#[tokio::test]
async fn the_caller_and_sign_ups_still_to_confirm_are_never_listed() {
    let search = InMemoryPeopleSearch::default();
    contract::the_caller_and_sign_ups_still_to_confirm_are_never_listed(&search, &search).await;
}

#[tokio::test]
async fn groups_hold_the_remote_active_members_of_the_callers_groups_only() {
    let search = InMemoryPeopleSearch::default();
    contract::groups_hold_the_remote_active_members_of_the_callers_groups_only(&search, &search)
        .await;
}

#[tokio::test]
async fn a_group_person_comes_with_the_latest_group_shared() {
    let search = InMemoryPeopleSearch::default();
    contract::a_group_person_comes_with_the_latest_group_shared(&search, &search).await;
}

#[tokio::test]
async fn each_person_comes_with_the_callers_standing() {
    let search = InMemoryPeopleSearch::default();
    contract::each_person_comes_with_the_callers_standing(&search, &search).await;
}

#[tokio::test]
async fn each_section_holds_at_most_the_limit() {
    let search = InMemoryPeopleSearch::default();
    contract::each_section_holds_at_most_the_limit(&search, &search).await;
}

#[tokio::test]
async fn someone_without_an_address_is_left_out() {
    let search = InMemoryPeopleSearch::default();
    contract::someone_without_an_address_is_left_out(&search, &search).await;
}

#[tokio::test]
async fn an_account_here_is_found_by_its_handle_with_the_callers_ties() {
    let search = InMemoryPeopleSearch::default();
    contract::an_account_here_is_found_by_its_handle_with_the_callers_ties(&search, &search).await;
}

#[tokio::test]
async fn the_callers_ties_to_anyone_are_read_alone() {
    let search = InMemoryPeopleSearch::default();
    contract::the_callers_ties_to_anyone_are_read_alone(&search, &search).await;
}
