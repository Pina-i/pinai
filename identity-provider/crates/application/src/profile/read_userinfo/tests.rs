use domain::profile::testing::{ProfileSeeds, own_profile};
use domain::settings::{SettingsDocument, SettingsPatch, SettingsStore};
use serde_json::json;

use super::*;
use crate::profile::world::world;

#[tokio::test]
async fn userinfo_is_the_account_its_address_its_uri_and_its_settings() {
    let w = world().await;
    let appearance = json!({ "appearance": { "family": "lagoon" } });
    w.settings
        .merge(
            w.alice.id,
            &SettingsPatch::parse(appearance.clone()).unwrap(),
        )
        .await
        .unwrap();

    let userinfo = w.read_userinfo().execute(w.alice.id).await.unwrap();

    assert_eq!(userinfo.profile, w.alice);
    assert_eq!(userinfo.address, "alice_t3st0@localhost:8080");
    assert_eq!(
        userinfo.actor_uri,
        "http://localhost:8080/users/alice_t3st0"
    );
    assert_eq!(userinfo.settings.as_value(), &appearance);
}

#[tokio::test]
async fn an_account_that_never_saved_settings_has_an_empty_document() {
    let w = world().await;

    let userinfo = w.read_userinfo().execute(w.alice.id).await.unwrap();

    assert_eq!(userinfo.settings, SettingsDocument::empty());
}

#[tokio::test]
async fn an_account_older_than_actor_uris_is_given_the_conventional_one() {
    let w = world().await;
    let dave = domain::profile::OwnProfile {
        actor_uri: None,
        ..own_profile("dave")
    };
    w.profiles.sign_up(&dave).await;

    let userinfo = w.read_userinfo().execute(dave.id).await.unwrap();

    assert_eq!(userinfo.actor_uri, "http://localhost:8080/users/dave_t3st0");
}

#[tokio::test]
async fn a_gone_account_has_no_userinfo() {
    let w = world().await;

    let refused = w.read_userinfo().execute(UserId::generate()).await;

    assert!(
        matches!(refused, Err(ProfileError::UnknownUser)),
        "{refused:?}"
    );
}
