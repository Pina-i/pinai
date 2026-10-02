use domain::profile::Pronouns;
use domain::profile::testing::ProfileSeeds;

use super::*;
use crate::profile::world::world;

#[tokio::test]
async fn a_peers_profile_is_kept_and_told_to_its_friends_here() {
    let w = world().await;
    let update = PublicProfile {
        actor: w.carol.actor_uri.clone(),
        display_name: Some("Carol R.".to_owned()),
        avatar_url: Some("http://idp.carol.test/avatars/carol.png?v=3".to_owned()),
        pronouns: Some(Pronouns::NonBinary),
        bio: Some("kia ora".to_owned()),
    };

    w.receive_update()
        .execute(&w.carol.actor_uri, update.clone())
        .await
        .unwrap();

    let (cached, kept) = w.profiles.shown(&w.carol.actor_uri).await;
    assert_eq!(cached, Some(update.clone()));
    assert_eq!(kept, vec![update.avatar_url.clone()]);
    assert_eq!(w.notifier.notified(), vec![(w.alice.id, update)]);
}

#[tokio::test]
async fn a_peer_updates_only_its_own_profile() {
    let w = world().await;
    let dave = domain::identity::testing::remote_actor("dave_k2m9x@idp.dave.test");
    let forged = PublicProfile {
        actor: w.carol.actor_uri.clone(),
        display_name: Some("not Carol".to_owned()),
        avatar_url: Some("http://idp.dave.test/whatever.png".to_owned()),
        pronouns: None,
        bio: None,
    };

    let refused = w.receive_update().execute(&dave.actor_uri, forged).await;

    assert!(
        matches!(refused, Err(ProfileError::NotItsOwn)),
        "{refused:?}"
    );
    let (cached, kept) = w.profiles.shown(&w.carol.actor_uri).await;
    assert_eq!(cached.unwrap().display_name, w.carol.display_name);
    assert_eq!(kept, vec![Some("http://old/carol.png".to_owned())]);
    assert!(w.notifier.notified().is_empty());
}

#[tokio::test]
async fn no_peer_updates_the_profile_of_an_account_here() {
    let w = world().await;
    let alice = w.alice.actor_uri.clone().unwrap();
    let forged = PublicProfile {
        actor: alice.clone(),
        display_name: Some("not Alice".to_owned()),
        avatar_url: Some("http://idp.dave.test/whatever.png".to_owned()),
        pronouns: None,
        bio: None,
    };

    let refused = w.receive_update().execute(&alice, forged).await;

    assert!(
        matches!(refused, Err(ProfileError::NotItsOwn)),
        "{refused:?}"
    );
    let (_, kept) = w.profiles.shown(&alice).await;
    assert_eq!(kept, vec![None]);
    assert!(w.notifier.notified().is_empty());
}

#[tokio::test]
async fn a_peers_name_avatar_or_bio_beyond_the_limits_is_taken_as_not_given() {
    let w = world().await;
    let update = PublicProfile {
        actor: w.carol.actor_uri.clone(),
        display_name: Some("x".repeat(51)),
        avatar_url: Some("javascript:alert(1)".to_owned()),
        pronouns: Some(Pronouns::He),
        bio: Some("x".repeat(191)),
    };

    w.receive_update()
        .execute(&w.carol.actor_uri, update)
        .await
        .unwrap();

    let dropped = PublicProfile {
        actor: w.carol.actor_uri.clone(),
        display_name: None,
        avatar_url: None,
        pronouns: Some(Pronouns::He),
        bio: None,
    };
    let (cached, kept) = w.profiles.shown(&w.carol.actor_uri).await;
    assert_eq!(cached, Some(dropped.clone()));
    assert_eq!(kept, vec![None]);
    assert_eq!(w.notifier.notified(), vec![(w.alice.id, dropped)]);
}
