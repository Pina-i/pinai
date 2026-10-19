use crate::auth::testing::a_request;

use super::*;

fn offline() -> AuthorizationRequest {
    AuthorizationRequest {
        scope: "openid profile email offline_access".to_owned(),
        ..a_request()
    }
}

#[test]
fn a_sign_in_covers_its_app_asking_no_more_than_it_did() {
    let user = UserId::generate();
    let online = ClientSignIn::of(user, &a_request());
    let stays = ClientSignIn::of(user, &offline());

    assert!(!online.offline_access);
    assert!(stays.offline_access);
    assert!(online.covers(&a_request()));
    assert!(
        !online.covers(&offline()),
        "staying signed in asks the password"
    );
    assert!(stays.covers(&offline()));
    assert!(stays.covers(&a_request()));
}

#[test]
fn a_sign_in_never_covers_another_app() {
    let sign_in = ClientSignIn::of(UserId::generate(), &a_request());
    let elsewhere = AuthorizationRequest {
        client: ClientId::parse("https://evil.test/oauth-client.json").unwrap(),
        redirect_uri: "https://evil.test/callback".to_owned(),
        ..a_request()
    };

    assert!(!sign_in.covers(&elsewhere));
}
