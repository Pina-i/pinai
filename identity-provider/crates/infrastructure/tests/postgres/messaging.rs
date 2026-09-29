use domain::AttachmentId;
use domain::identity::ActorUri;
use domain::messaging::Conversations;
use domain::messaging::testing::{Uploads, contract};
use infrastructure::postgres::{PgAttachments, PgConversations, PgMessages};
use sqlx::PgPool;

use super::an_account;

struct PgUploads(PgPool);

#[async_trait::async_trait]
impl Uploads for PgUploads {
    async fn upload(&self, owner: &ActorUri) -> AttachmentId {
        let id = AttachmentId::generate();
        sqlx::query(
            "INSERT INTO message_attachments \
                (id, uploaded_by_actor_uri, storage_key, mime_type, byte_size, original_filename) \
             VALUES ($1, $2, $3, 'image/png', 512, 'cat.png')",
        )
        .bind(id.as_uuid())
        .bind(owner.as_str())
        .bind(id.to_string())
        .execute(&self.0)
        .await
        .expect("seed an upload");
        id
    }
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_dm_is_opened_once_for_a_pair_in_either_order(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    let bob = an_account(&pool, "bob").await;
    contract::a_dm_is_opened_once_for_a_pair_in_either_order(
        &PgConversations::new(pool.clone()),
        &alice,
        &bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_dm_is_opened_under_the_pinned_id_when_the_pair_has_none(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    contract::a_dm_is_opened_under_the_pinned_id_when_the_pair_has_none(
        &PgConversations::new(pool.clone()),
        &alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_pair_that_shares_a_dm_keeps_it_whatever_id_is_pinned(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    contract::a_pair_that_shares_a_dm_keeps_it_whatever_id_is_pinned(
        &PgConversations::new(pool.clone()),
        &alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_mirrored_group_is_created_with_its_name_and_roster(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    contract::a_mirrored_group_is_created_with_its_name_and_roster(
        &PgConversations::new(pool.clone()),
        &alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn mirroring_again_renames_and_converges_without_removing_anyone(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    contract::mirroring_again_renames_and_converges_without_removing_anyone(
        &PgConversations::new(pool.clone()),
        &alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_conversation_list_shows_the_others_the_last_message_and_unread_counts(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    let bob = an_account(&pool, "bob").await;
    contract::the_conversation_list_shows_the_others_the_last_message_and_unread_counts(
        &PgConversations::new(pool.clone()),
        &PgMessages::new(pool.clone()),
        &alice,
        &bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_most_recently_active_conversation_is_listed_first(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    contract::the_most_recently_active_conversation_is_listed_first(
        &PgConversations::new(pool.clone()),
        &PgMessages::new(pool.clone()),
        &alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_recorded_message_is_found_by_id_and_activity_pending_delivery(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    contract::a_recorded_message_is_found_by_id_and_activity_pending_delivery(
        &PgConversations::new(pool.clone()),
        &PgMessages::new(pool.clone()),
        &alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_message_takes_the_senders_uploads_along(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    contract::a_message_takes_the_senders_uploads_along(
        &PgConversations::new(pool.clone()),
        &PgMessages::new(pool.clone()),
        &PgUploads(pool.clone()),
        &alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_upload_the_sender_may_not_attach_stores_nothing(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    let bob = an_account(&pool, "bob").await;
    contract::an_upload_the_sender_may_not_attach_stores_nothing(
        &PgConversations::new(pool.clone()),
        &PgMessages::new(pool.clone()),
        &PgUploads(pool.clone()),
        &alice,
        &bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_uploads_of_an_undelivered_message_move_to_its_resend(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    contract::the_uploads_of_an_undelivered_message_move_to_its_resend(
        &PgConversations::new(pool.clone()),
        &PgMessages::new(pool.clone()),
        &PgUploads(pool.clone()),
        &alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_received_message_records_the_attachments_it_describes(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    contract::a_received_message_records_the_attachments_it_describes(
        &PgConversations::new(pool.clone()),
        &PgMessages::new(pool.clone()),
        &alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn only_its_sender_edits_a_message(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    contract::only_its_sender_edits_a_message(
        &PgConversations::new(pool.clone()),
        &PgMessages::new(pool.clone()),
        &alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn history_is_newest_first_in_pages_before_a_cursor(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    contract::history_is_newest_first_in_pages_before_a_cursor(
        &PgConversations::new(pool.clone()),
        &PgMessages::new(pool.clone()),
        &alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_delivery_outcome_is_recorded_on_the_message(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    contract::a_delivery_outcome_is_recorded_on_the_message(
        &PgConversations::new(pool.clone()),
        &PgMessages::new(pool.clone()),
        &alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_conversation_list_names_each_member_as_their_instance_knows_them(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    let bob = an_account(&pool, "bob").await;
    let dave = contract::remote("dave");
    sqlx::query(
        "INSERT INTO remote_actors (actor_uri, instance, display_name, avatar_url) \
         VALUES ($1, 'idp.remote.test', 'Dave', 'https://idp.remote.test/dave.png')",
    )
    .bind(dave.as_str())
    .execute(&pool)
    .await
    .unwrap();
    let conversations = PgConversations::new(pool.clone());
    conversations
        .open_dm(&alice.actor_uri, &bob.actor_uri, None)
        .await
        .unwrap();
    conversations
        .open_dm(&alice.actor_uri, &dave, None)
        .await
        .unwrap();

    let listed = conversations
        .list_for(alice.id, &alice.actor_uri)
        .await
        .unwrap();

    let mut names: Vec<_> = listed
        .iter()
        .flat_map(|s| &s.members)
        .map(|m| (m.display_name.as_deref(), m.avatar_url.as_deref()))
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            (Some("Dave"), Some("https://idp.remote.test/dave.png")),
            (Some("bob"), None)
        ]
    );
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_pinned_id_naming_a_group_opens_a_separate_dm(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    contract::a_pinned_id_naming_a_group_opens_a_separate_dm(&PgConversations::new(pool), &alice)
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_pinned_id_naming_another_pairs_dm_opens_a_separate_dm(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    contract::a_pinned_id_naming_another_pairs_dm_opens_a_separate_dm(
        &PgConversations::new(pool),
        &alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn concurrent_first_messages_between_a_pair_open_one_dm(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    for peer in ["bob", "cy", "dave", "eve"] {
        let peer = contract::remote(peer);
        let opens: Vec<_> = (0..16)
            .map(|_| {
                let conversations = PgConversations::new(pool.clone());
                let (a, b) = (alice.actor_uri.clone(), peer.clone());
                tokio::spawn(async move { conversations.open_dm(&a, &b, None).await.unwrap() })
            })
            .collect();
        let mut ids = Vec::new();
        for open in opens {
            ids.push(open.await.unwrap());
        }

        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 1, "one DM for alice and {peer}: {ids:?}");
    }
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_redelivered_message_is_recorded_once(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    contract::a_redelivered_message_is_recorded_once(
        &PgConversations::new(pool.clone()),
        &PgMessages::new(pool),
        &alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_delivery_left_pending_is_failed_once_stale(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    let carol = an_account(&pool, "carol").await;
    contract::a_delivery_left_pending_is_failed_once_stale(
        &PgConversations::new(pool.clone()),
        &PgMessages::new(pool),
        &alice,
        &carol,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_group_is_created_with_its_whole_roster(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    let bob = an_account(&pool, "bob").await;
    contract::a_group_is_created_with_its_whole_roster(&PgConversations::new(pool), &alice, &bob)
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_added_member_takes_the_given_role_and_one_who_left_rejoins(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    let bob = an_account(&pool, "bob").await;
    contract::an_added_member_takes_the_given_role_and_one_who_left_rejoins(
        &PgConversations::new(pool),
        &alice,
        &bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_member_leaves_a_group_once(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    let bob = an_account(&pool, "bob").await;
    contract::a_member_leaves_a_group_once(&PgConversations::new(pool), &alice, &bob).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_role_changes_only_for_an_active_member(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    let bob = an_account(&pool, "bob").await;
    contract::a_role_changes_only_for_an_active_member(&PgConversations::new(pool), &alice, &bob)
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn only_a_group_is_renamed(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    let bob = an_account(&pool, "bob").await;
    contract::only_a_group_is_renamed(&PgConversations::new(pool), &alice, &bob).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_upload_is_recorded_unlinked_and_found(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    contract::an_upload_is_recorded_unlinked_and_found(&PgAttachments::new(pool), &alice).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_upload_under_a_taken_id_is_refused(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    let bob = an_account(&pool, "bob").await;
    contract::an_upload_under_a_taken_id_is_refused(&PgAttachments::new(pool), &alice, &bob).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_deleted_attachment_is_gone(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    contract::a_deleted_attachment_is_gone(&PgAttachments::new(pool), &alice).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn orphans_are_the_unlinked_uploads_recorded_before_the_cutoff(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    contract::orphans_are_the_unlinked_uploads_recorded_before_the_cutoff(
        &PgAttachments::new(pool.clone()),
        &PgConversations::new(pool.clone()),
        &PgMessages::new(pool),
        &alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_conversations_an_actor_ever_held_include_those_it_left(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    let bob = an_account(&pool, "bob").await;
    contract::the_conversations_an_actor_ever_held_include_those_it_left(
        &PgConversations::new(pool),
        &alice,
        &bob,
    )
    .await;
}
