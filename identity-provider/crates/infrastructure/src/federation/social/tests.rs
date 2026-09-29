use domain::identity::testing::{account, remote_actor};

use super::*;

fn pair() -> (Account, RemoteActor) {
    (account("alice"), remote_actor("carol_k2m9x@idp.carol.test"))
}

#[test]
fn a_follow_asks_the_remote_account() {
    let (alice, carol) = pair();

    let follow = follow(&alice.actor_uri, &carol.actor_uri);

    assert_eq!(follow["type"], "Follow");
    assert_eq!(follow["actor"], alice.actor_uri.as_str());
    assert_eq!(follow["object"], carol.actor_uri.as_str());
}

#[test]
fn an_accept_answers_the_follow_behind_the_request_and_names_the_dm() {
    let (alice, carol) = pair();
    let (request, dm) = (FriendshipId::generate(), ConversationId::generate());

    let accept = accept(&alice.actor_uri, &carol.actor_uri, request, dm);

    assert_eq!(accept["type"], "Accept");
    assert_eq!(accept["actor"], alice.actor_uri.as_str());
    assert_eq!(accept["conversationId"], dm.to_string());
    assert_eq!(
        accept["object"]["id"],
        format!("{}/follows/{request}", carol.actor_uri)
    );
    assert_eq!(
        (&accept["object"]["actor"], &accept["object"]["object"]),
        (
            &json!(carol.actor_uri.as_str()),
            &json!(alice.actor_uri.as_str())
        )
    );
}

#[test]
fn a_reject_answers_the_follow_behind_the_request() {
    let (alice, carol) = pair();
    let request = FriendshipId::generate();

    let reject = reject(&alice.actor_uri, &carol.actor_uri, request);

    assert_eq!(reject["type"], "Reject");
    assert_eq!(reject["actor"], alice.actor_uri.as_str());
    assert_eq!(
        reject["object"]["id"],
        format!("{}/follows/{request}", carol.actor_uri)
    );
    assert_eq!(reject["object"]["actor"], carol.actor_uri.as_str());
}

#[test]
fn an_undo_withdraws_a_follow_of_the_friend() {
    let (alice, carol) = pair();

    let undo = undo_follow(&alice.actor_uri, &carol.actor_uri);

    assert_eq!(
        (&undo["type"], &undo["actor"]),
        (&json!("Undo"), &json!(alice.actor_uri.as_str()))
    );
    assert_eq!(
        (
            &undo["object"]["type"],
            &undo["object"]["actor"],
            &undo["object"]["object"]
        ),
        (
            &json!("Follow"),
            &json!(alice.actor_uri.as_str()),
            &json!(carol.actor_uri.as_str())
        )
    );
}
