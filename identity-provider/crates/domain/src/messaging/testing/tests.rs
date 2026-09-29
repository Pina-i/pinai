use super::*;
use crate::identity::testing::account;

#[tokio::test]
async fn a_dm_is_opened_once_for_a_pair_in_either_order() {
    let store = InMemoryMessaging::default();
    contract::a_dm_is_opened_once_for_a_pair_in_either_order(
        &store,
        &account("alice"),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn a_dm_is_opened_under_the_pinned_id_when_the_pair_has_none() {
    let store = InMemoryMessaging::default();
    contract::a_dm_is_opened_under_the_pinned_id_when_the_pair_has_none(&store, &account("alice"))
        .await;
}

#[tokio::test]
async fn a_pair_that_shares_a_dm_keeps_it_whatever_id_is_pinned() {
    let store = InMemoryMessaging::default();
    contract::a_pair_that_shares_a_dm_keeps_it_whatever_id_is_pinned(&store, &account("alice"))
        .await;
}

#[tokio::test]
async fn a_mirrored_group_is_created_with_its_name_and_roster() {
    let store = InMemoryMessaging::default();
    contract::a_mirrored_group_is_created_with_its_name_and_roster(&store, &account("alice")).await;
}

#[tokio::test]
async fn mirroring_again_renames_and_converges_without_removing_anyone() {
    let store = InMemoryMessaging::default();
    contract::mirroring_again_renames_and_converges_without_removing_anyone(
        &store,
        &account("alice"),
    )
    .await;
}

#[tokio::test]
async fn the_conversation_list_shows_the_others_the_last_message_and_unread_counts() {
    let store = InMemoryMessaging::default();
    contract::the_conversation_list_shows_the_others_the_last_message_and_unread_counts(
        &store,
        &store,
        &account("alice"),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn the_most_recently_active_conversation_is_listed_first() {
    let store = InMemoryMessaging::default();
    contract::the_most_recently_active_conversation_is_listed_first(
        &store,
        &store,
        &account("alice"),
    )
    .await;
}

#[tokio::test]
async fn a_recorded_message_is_found_by_id_and_activity_pending_delivery() {
    let store = InMemoryMessaging::default();
    contract::a_recorded_message_is_found_by_id_and_activity_pending_delivery(
        &store,
        &store,
        &account("alice"),
    )
    .await;
}

#[tokio::test]
async fn a_message_takes_the_senders_uploads_along() {
    let store = InMemoryMessaging::default();
    contract::a_message_takes_the_senders_uploads_along(&store, &store, &store, &account("alice"))
        .await;
}

#[tokio::test]
async fn an_upload_the_sender_may_not_attach_stores_nothing() {
    let store = InMemoryMessaging::default();
    contract::an_upload_the_sender_may_not_attach_stores_nothing(
        &store,
        &store,
        &store,
        &account("alice"),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn the_uploads_of_an_undelivered_message_move_to_its_resend() {
    let store = InMemoryMessaging::default();
    contract::the_uploads_of_an_undelivered_message_move_to_its_resend(
        &store,
        &store,
        &store,
        &account("alice"),
    )
    .await;
}

#[tokio::test]
async fn a_received_message_records_the_attachments_it_describes() {
    let store = InMemoryMessaging::default();
    contract::a_received_message_records_the_attachments_it_describes(
        &store,
        &store,
        &account("alice"),
    )
    .await;
}

#[tokio::test]
async fn only_its_sender_edits_a_message() {
    let store = InMemoryMessaging::default();
    contract::only_its_sender_edits_a_message(&store, &store, &account("alice")).await;
}

#[tokio::test]
async fn history_is_newest_first_in_pages_before_a_cursor() {
    let store = InMemoryMessaging::default();
    contract::history_is_newest_first_in_pages_before_a_cursor(&store, &store, &account("alice"))
        .await;
}

#[tokio::test]
async fn a_delivery_outcome_is_recorded_on_the_message() {
    let store = InMemoryMessaging::default();
    contract::a_delivery_outcome_is_recorded_on_the_message(&store, &store, &account("alice"))
        .await;
}

#[tokio::test]
async fn a_pinned_id_naming_a_group_opens_a_separate_dm() {
    let store = InMemoryMessaging::default();
    contract::a_pinned_id_naming_a_group_opens_a_separate_dm(&store, &account("alice")).await;
}

#[tokio::test]
async fn a_pinned_id_naming_another_pairs_dm_opens_a_separate_dm() {
    let store = InMemoryMessaging::default();
    contract::a_pinned_id_naming_another_pairs_dm_opens_a_separate_dm(&store, &account("alice"))
        .await;
}

#[tokio::test]
async fn a_redelivered_message_is_recorded_once() {
    let store = InMemoryMessaging::default();
    contract::a_redelivered_message_is_recorded_once(&store, &store, &account("alice")).await;
}

#[tokio::test]
async fn a_delivery_left_pending_is_failed_once_stale() {
    let store = InMemoryMessaging::default();
    contract::a_delivery_left_pending_is_failed_once_stale(
        &store,
        &store,
        &account("alice"),
        &account("carol"),
    )
    .await;
}

#[tokio::test]
async fn a_group_is_created_with_its_whole_roster() {
    let store = InMemoryMessaging::default();
    contract::a_group_is_created_with_its_whole_roster(&store, &account("alice"), &account("bob"))
        .await;
}

#[tokio::test]
async fn an_added_member_takes_the_given_role_and_one_who_left_rejoins() {
    let store = InMemoryMessaging::default();
    contract::an_added_member_takes_the_given_role_and_one_who_left_rejoins(
        &store,
        &account("alice"),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn a_member_leaves_a_group_once() {
    let store = InMemoryMessaging::default();
    contract::a_member_leaves_a_group_once(&store, &account("alice"), &account("bob")).await;
}

#[tokio::test]
async fn a_role_changes_only_for_an_active_member() {
    let store = InMemoryMessaging::default();
    contract::a_role_changes_only_for_an_active_member(&store, &account("alice"), &account("bob"))
        .await;
}

#[tokio::test]
async fn only_a_group_is_renamed() {
    let store = InMemoryMessaging::default();
    contract::only_a_group_is_renamed(&store, &account("alice"), &account("bob")).await;
}

#[tokio::test]
async fn an_upload_is_recorded_unlinked_and_found() {
    contract::an_upload_is_recorded_unlinked_and_found(
        &InMemoryMessaging::default(),
        &account("alice"),
    )
    .await;
}

#[tokio::test]
async fn an_upload_under_a_taken_id_is_refused() {
    contract::an_upload_under_a_taken_id_is_refused(
        &InMemoryMessaging::default(),
        &account("alice"),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn a_deleted_attachment_is_gone() {
    contract::a_deleted_attachment_is_gone(&InMemoryMessaging::default(), &account("alice")).await;
}

#[tokio::test]
async fn orphans_are_the_unlinked_uploads_recorded_before_the_cutoff() {
    let store = InMemoryMessaging::default();
    contract::orphans_are_the_unlinked_uploads_recorded_before_the_cutoff(
        &store,
        &store,
        &store,
        &account("alice"),
    )
    .await;
}

#[tokio::test]
async fn the_conversations_an_actor_ever_held_include_those_it_left() {
    let store = InMemoryMessaging::default();
    contract::the_conversations_an_actor_ever_held_include_those_it_left(
        &store,
        &account("alice"),
        &account("bob"),
    )
    .await;
}
