use crate::helpers::{PASSWORD, location, query_of, spawn_app};

#[tokio::test]
async fn a_new_account_signs_up_confirms_its_address_and_is_signed_in() {
    let app = spawn_app().await;

    let alice = app.sign_up("alice").await;

    let (status, userinfo) = app.get(&alice, "/userinfo").await;
    assert_eq!(status, 200, "{userinfo}");
    assert_eq!(userinfo["email"], "alice@journey.test");
    assert_eq!(userinfo["email_verified"], true);
    assert!(alice.handle.starts_with("alice_"), "{}", alice.handle);
    assert_eq!(userinfo["address"], alice.address(&app));
    assert_eq!(
        userinfo["actor_uri"],
        format!("{}/users/{}", app.address, alice.handle)
    );
    app.stop().await.unwrap();
}

#[tokio::test]
async fn a_confirmed_account_signs_in_again_with_its_password() {
    let app = spawn_app().await;
    let alice = app.sign_up("alice").await;

    let signed_in = app
        .form("/login", &[("email", &alice.email), ("password", PASSWORD)])
        .await;
    let wrong = app
        .form(
            "/login",
            &[("email", &alice.email), ("password", "not-the-password")],
        )
        .await;

    assert_eq!(signed_in.status(), 303);
    let token = app.exchange(&query_of(&location(&signed_in))["code"]).await;
    let (status, _) = app
        .get(
            &crate::helpers::Account {
                token,
                ..alice.clone()
            },
            "/userinfo",
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(wrong.status(), 303);
    assert_eq!(
        query_of(&location(&wrong))["error"],
        "Invalid email or password"
    );
    assert_eq!(
        app.mail.count_for(&alice.email),
        1,
        "one code, for the sign-up"
    );
    app.stop().await.unwrap();
}
