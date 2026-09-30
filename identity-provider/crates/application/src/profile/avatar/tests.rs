use bytes::Bytes;
use domain::profile::{ImageKind, Profiles};

use super::*;
use crate::profile::world::{now, world};

fn image(kind: ImageKind) -> AvatarImage {
    AvatarImage::parse(Some(kind.mime()), Bytes::from_static(b"\x89PNG")).unwrap()
}

#[tokio::test]
async fn an_avatar_is_stored_shown_under_its_upload_time_and_told_to_the_friends() {
    let w = world().await;

    let url = w
        .set_avatar()
        .execute(w.alice.id, image(ImageKind::Png), now())
        .await
        .unwrap();

    assert_eq!(
        url,
        format!("http://s3.test/avatars/{}.png?v=1790000000", w.alice.id)
    );
    let shown = w.profiles.find(w.alice.id).await.unwrap().unwrap();
    assert_eq!(shown.avatar_url.as_deref(), Some(url.as_str()));
    assert_eq!(w.avatars.stored(w.alice.id), vec![ImageKind::Png]);
    let told = w.notifier.notified();
    assert_eq!(told.len(), 1);
    assert_eq!(told[0].1.avatar_url.as_deref(), Some(url.as_str()));
    assert_eq!(w.federation.sent().len(), 1);
}

#[tokio::test]
async fn a_new_avatar_replaces_the_old_one() {
    let w = world().await;
    let set = w.set_avatar();

    set.execute(w.alice.id, image(ImageKind::Png), now())
        .await
        .unwrap();
    set.execute(w.alice.id, image(ImageKind::Webp), now())
        .await
        .unwrap();

    assert_eq!(w.avatars.stored(w.alice.id), vec![ImageKind::Webp]);
}

#[tokio::test]
async fn a_cleared_avatar_is_removed_and_told_to_the_friends() {
    let w = world().await;
    w.set_avatar()
        .execute(w.alice.id, image(ImageKind::Gif), now())
        .await
        .unwrap();

    w.clear_avatar().execute(w.alice.id).await.unwrap();

    let shown = w.profiles.find(w.alice.id).await.unwrap().unwrap();
    assert_eq!(shown.avatar_url, None);
    assert!(w.avatars.stored(w.alice.id).is_empty());
    let told = w.notifier.notified();
    assert_eq!(told.len(), 2);
    assert_eq!(told[1].1.avatar_url, None);
}

async fn showing_a_png(w: &crate::profile::world::World) -> String {
    w.set_avatar()
        .execute(w.alice.id, image(ImageKind::Png), now())
        .await
        .unwrap()
}

async fn shown(w: &crate::profile::world::World) -> Option<String> {
    w.profiles
        .find(w.alice.id)
        .await
        .unwrap()
        .unwrap()
        .avatar_url
}

#[tokio::test]
async fn an_upload_that_fails_leaves_the_avatar_shown_in_place() {
    let w = world().await;
    let png = showing_a_png(&w).await;
    w.avatars.refuse_uploads();

    let failed = w
        .set_avatar()
        .execute(w.alice.id, image(ImageKind::Webp), now())
        .await;

    assert!(failed.is_err());
    assert_eq!(shown(&w).await, Some(png));
    assert_eq!(w.avatars.stored(w.alice.id), vec![ImageKind::Png]);
}

#[tokio::test]
async fn an_avatar_that_cannot_be_recorded_leaves_the_one_shown_in_place() {
    let w = world().await;
    let png = showing_a_png(&w).await;
    w.profiles.refuse_writes();

    let failed = w
        .set_avatar()
        .execute(w.alice.id, image(ImageKind::Webp), now())
        .await;

    assert!(failed.is_err());
    assert_eq!(shown(&w).await, Some(png));
    assert!(w.avatars.stored(w.alice.id).contains(&ImageKind::Png));
}

#[tokio::test]
async fn a_clear_that_cannot_be_recorded_leaves_the_avatar_shown_in_place() {
    let w = world().await;
    let png = showing_a_png(&w).await;
    w.profiles.refuse_writes();

    let failed = w.clear_avatar().execute(w.alice.id).await;

    assert!(failed.is_err());
    assert_eq!(shown(&w).await, Some(png));
    assert_eq!(w.avatars.stored(w.alice.id), vec![ImageKind::Png]);
}

#[tokio::test]
async fn an_old_image_left_behind_fails_nothing() {
    let w = world().await;
    showing_a_png(&w).await;
    w.avatars.refuse_removals();

    let webp = w
        .set_avatar()
        .execute(w.alice.id, image(ImageKind::Webp), now())
        .await
        .unwrap();
    w.clear_avatar().execute(w.alice.id).await.unwrap();

    assert!(webp.contains(".webp?v="), "{webp}");
    assert_eq!(shown(&w).await, None);
    assert_eq!(w.notifier.notified().len(), 3);
}
