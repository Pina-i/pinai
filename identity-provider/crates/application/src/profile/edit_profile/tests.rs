use domain::profile::{Pronouns, PublicProfile};

use super::*;
use crate::profile::world::world;

fn edit(name: &str) -> ProfileEdit {
    ProfileEdit::parse(Some(name), Some("she"), Some("kia ora")).unwrap()
}

#[tokio::test]
async fn an_edit_is_saved_and_answered_as_userinfo() {
    let w = world().await;

    let userinfo = w
        .edit_profile()
        .execute(w.alice.id, edit("Aroha"))
        .await
        .unwrap();

    assert_eq!(userinfo.profile.display_name.as_deref(), Some("Aroha"));
    assert_eq!(userinfo.profile.pronouns, Some(Pronouns::She));
    assert_eq!(userinfo.profile.bio.as_deref(), Some("kia ora"));
    assert_eq!(userinfo.address, "alice_t3st0@localhost:8080");
    assert_eq!(
        w.read_userinfo().execute(w.alice.id).await.unwrap(),
        userinfo
    );
}

#[tokio::test]
async fn an_edit_is_told_to_the_friends_here_and_elsewhere() {
    let w = world().await;

    w.edit_profile()
        .execute(w.alice.id, edit("Aroha"))
        .await
        .unwrap();

    let shown = PublicProfile {
        actor: w.alice.actor_uri.clone().unwrap(),
        display_name: Some("Aroha".to_owned()),
        avatar_url: None,
        pronouns: Some(Pronouns::She),
        bio: Some("kia ora".to_owned()),
    };
    assert_eq!(w.notifier.notified(), vec![(w.bob.id, shown.clone())]);
    assert_eq!(w.federation.sent(), vec![(shown, w.carol.actor_uri)]);
}

#[tokio::test]
async fn an_edit_of_a_gone_account_is_refused() {
    let w = world().await;

    let refused = w
        .edit_profile()
        .execute(UserId::generate(), edit("Aroha"))
        .await;

    assert!(
        matches!(refused, Err(ProfileError::UnknownUser)),
        "{refused:?}"
    );
    assert!(w.notifier.notified().is_empty());
}
