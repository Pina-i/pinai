use domain::identity::RemoteActor;
use domain::identity::testing::remote_actor;
use domain::profile::testing::{ProfileSeeds, own_profile};
use domain::profile::{OwnProfile, Pronouns, PublicProfile};
use time::{Duration, OffsetDateTime};

use crate::profile::world::world;

use super::*;

fn shown(actor: &RemoteActor) -> PublicProfile {
    PublicProfile {
        actor: actor.actor_uri.clone(),
        display_name: actor.display_name.clone(),
        avatar_url: actor.avatar_url.clone(),
        pronouns: None,
        bio: None,
    }
}

#[tokio::test]
async fn an_account_here_is_shown_to_any_account_here() {
    let world = world().await;
    let dave = OwnProfile {
        pronouns: Some(Pronouns::NonBinary),
        bio: Some("kia ora".to_owned()),
        ..own_profile("dave")
    };
    world.profiles.sign_up(&dave).await;

    let card = world
        .read_profile()
        .execute(world.alice.id, dave.actor_uri.as_ref().unwrap())
        .await
        .unwrap();

    assert_eq!(
        card,
        Some(ProfileCard {
            profile: dave.public().unwrap(),
            friends_since: None,
        })
    );
}

#[tokio::test]
async fn a_friend_elsewhere_is_shown_as_cached_with_the_day_they_became_friends() {
    let world = world().await;

    let card = world
        .read_profile()
        .execute(world.alice.id, &world.carol.actor_uri)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(card.profile, shown(&world.carol));
    assert!(card.friends_since.is_some());
    assert_eq!(world.refresh.asked(), []);
}

#[tokio::test]
async fn a_profile_cached_over_a_day_ago_is_shown_and_asked_for_again() {
    let world = world().await;
    let carol = &world.carol.actor_uri;
    let read = world.read_profile();

    world
        .profiles
        .heard_at(carol, OffsetDateTime::now_utc() - Duration::hours(23));
    let fresh = read.execute(world.alice.id, carol).await.unwrap();
    let asked_while_fresh = world.refresh.asked();
    world
        .profiles
        .heard_at(carol, OffsetDateTime::now_utc() - Duration::hours(25));
    let stale = read.execute(world.alice.id, carol).await.unwrap();

    assert!(fresh.is_some() && stale.is_some());
    assert_eq!(asked_while_fresh, []);
    assert_eq!(world.refresh.asked(), std::slice::from_ref(carol));
}

#[tokio::test]
async fn an_account_elsewhere_the_viewer_does_not_know_is_not_shown_nor_asked_for() {
    let world = world().await;
    let erin = remote_actor("erin_k2m9x@idp.erin.test");
    world.profiles.remember(&erin).await;
    world.profiles.heard_at(
        &erin.actor_uri,
        OffsetDateTime::now_utc() - Duration::days(3),
    );

    let card = world
        .read_profile()
        .execute(world.alice.id, &erin.actor_uri)
        .await
        .unwrap();

    assert_eq!(card, None);
    assert_eq!(world.refresh.asked(), []);
}

#[tokio::test]
async fn an_account_this_instance_does_not_hold_is_not_shown() {
    let world = world().await;
    let stranger = remote_actor("zed_k2m9x@idp.far.test").actor_uri;

    let card = world
        .read_profile()
        .execute(world.alice.id, &stranger)
        .await
        .unwrap();

    assert_eq!(card, None);
}

#[tokio::test]
async fn a_viewer_whose_account_is_gone_is_an_unknown_user() {
    let world = world().await;

    let read = world
        .read_profile()
        .execute(UserId::generate(), &world.carol.actor_uri)
        .await;

    assert!(matches!(read, Err(ProfileError::UnknownUser)));
}
