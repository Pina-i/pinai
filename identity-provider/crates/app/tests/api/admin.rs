use domain::auth::Registrations;

use crate::helpers::{Account, PASSWORD, location, query_of, spawn_app_with, try_spawn_app};

const ADMIN: &str = "root@journey.test";

#[tokio::test]
async fn the_admin_created_at_startup_signs_in_without_a_code_and_is_told_it_is_admin() {
    let app = spawn_app_with(|config| {
        config.admin_email = Some(ADMIN.into());
        config.admin_password = Some(PASSWORD.into());
    })
    .await;

    let signed_in = app
        .form("/login", &[("email", ADMIN), ("password", PASSWORD)])
        .await;

    assert_eq!(signed_in.status(), 303);
    let landed = location(&signed_in);
    assert!(landed.starts_with(&app.redirect_uri), "{landed}");
    let tokens = app.tokens_for(&query_of(&landed)["code"]).await;
    let admin = Account {
        email: ADMIN.into(),
        handle: String::new(),
        actor_uri: String::new(),
        token: tokens["access_token"].as_str().unwrap().to_owned(),
        refresh_token: tokens["refresh_token"].as_str().unwrap().to_owned(),
        cookie: String::new(),
    };
    let (status, userinfo) = app.get(&admin, "/userinfo").await;
    assert_eq!(status, 200, "{userinfo}");
    assert_eq!(userinfo["admin"], true);
    assert_eq!(userinfo["email_verified"], false);
    assert_eq!(userinfo["display_name"], "Admin");
    assert_eq!(app.mail.count_for(ADMIN), 0, "no code was mailed");
    app.stop().await.unwrap();
}

#[tokio::test]
async fn an_instance_told_to_create_its_admin_without_a_password_does_not_start() {
    let started = try_spawn_app(|config| config.admin_email = Some(ADMIN.into())).await;

    let Err(refused) = started else {
        panic!("the instance started without ADMIN_PASSWORD");
    };
    assert!(
        refused.to_string().contains("ADMIN_PASSWORD"),
        "{refused:#}"
    );
}

#[tokio::test]
async fn an_invite_only_instance_without_an_admin_does_not_start_and_says_how_to_fix_it() {
    let started = try_spawn_app(|config| config.registrations = Registrations::Invite).await;

    let Err(refused) = started else {
        panic!("an invite-only instance started without an admin");
    };
    let said = refused.to_string();
    for fix in ["ADMIN_EMAIL and ADMIN_PASSWORD", "REGISTRATIONS=open"] {
        assert!(said.contains(fix), "{fix} not in {refused:#}");
    }
}

#[tokio::test]
async fn an_invite_only_instance_starts_without_a_relay_and_its_admin_signs_in() {
    let app = spawn_app_with(|config| {
        config.registrations = Registrations::Invite;
        config.smtp_host = String::new();
        config.admin_email = Some(ADMIN.into());
        config.admin_password = Some(PASSWORD.into());
    })
    .await;

    let signed_in = app
        .form("/login", &[("email", ADMIN), ("password", PASSWORD)])
        .await;

    assert_eq!(signed_in.status(), 303);
    let landed = location(&signed_in);
    assert!(landed.starts_with(&app.redirect_uri), "{landed}");
    app.stop().await.unwrap();
}
