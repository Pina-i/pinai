use domain::auth::testing::{Mail, PlainHasher, a_request};
use domain::auth::{AuthorizationRequest, ClientId, Email, SignInAccount};
use domain::identity::{ActorUri, Handle};

use crate::auth::world::{invite_only, now, world};

use super::*;

fn bob() -> RegisterCommand {
    RegisterCommand {
        display_name: "Bōb".to_owned(),
        email: "bob@idp.test".to_owned(),
        password: "bob-password".to_owned(),
    }
}

#[tokio::test]
async fn registering_creates_an_unconfirmed_account_and_mails_it_a_code() {
    let w = world().await;

    let registered = w.register.execute(bob(), None, now()).await.unwrap();

    assert_eq!(
        registered,
        Registered {
            user: registered.user,
            username: "bob_sfx01".to_owned(),
            display_name: "Bōb".to_owned(),
            email: "bob@idp.test".to_owned(),
        }
    );
    assert_eq!(
        w.accounts.created(),
        vec![NewAccount {
            id: registered.user,
            username: Handle::parse("bob_sfx01").unwrap(),
            display_name: "Bōb".to_owned(),
            email: Email::parse("bob@idp.test").unwrap(),
            password_hash: PlainHasher::hash("bob-password"),
            actor_uri: ActorUri::parse("http://localhost:8080/users/bob_sfx01").unwrap(),
        }]
    );
    let account: SignInAccount = w.accounts.by_id(registered.user).await.unwrap().unwrap();
    assert!(!account.email_verified);
    assert_eq!(
        w.mailer.sent(),
        vec![Mail {
            to: "bob@idp.test".to_owned(),
            name: "Bōb".to_owned(),
            code: w.signup_codes.issued()[0].1.clone(),
        }]
    );
}

#[tokio::test]
async fn a_registration_is_refused_with_the_rule_it_breaks() {
    let w = world().await;
    let refused = async |command: RegisterCommand| {
        w.register.execute(command, None, now()).await.unwrap_err()
    };
    let named = |display_name: &str| RegisterCommand {
        display_name: display_name.to_owned(),
        ..bob()
    };

    let names = [
        refused(named("   ")).await,
        refused(named(&"b".repeat(51))).await,
    ];
    let address = refused(RegisterCommand {
        email: "bob".to_owned(),
        ..bob()
    })
    .await;
    let short_password = refused(RegisterCommand {
        password: "1234567".to_owned(),
        ..bob()
    })
    .await;
    let taken = refused(RegisterCommand {
        email: w.alice.email.to_uppercase(),
        ..bob()
    })
    .await;
    let blank = refused(RegisterCommand {
        email: String::new(),
        ..bob()
    })
    .await;

    for name in &names {
        assert!(matches!(name, AuthError::BadDisplayName(_)), "{name:?}");
    }
    assert!(matches!(address, AuthError::BadEmail(_)), "{address:?}");
    assert!(
        matches!(short_password, AuthError::PasswordTooShort),
        "{short_password:?}"
    );
    assert!(matches!(taken, AuthError::EmailTaken), "{taken:?}");
    assert!(matches!(blank, AuthError::MissingField), "{blank:?}");
    assert!(w.accounts.created().is_empty());
    assert!(w.mailer.sent().is_empty());
}

#[tokio::test]
async fn an_address_is_kept_lowercase_and_a_handle_taken_by_chance_drawn_again() {
    let w = world().await;
    w.sign_up(&SignInAccount {
        username: "bob_sfx01".to_owned(),
        ..domain::auth::testing::signed_up("robert")
    })
    .await;

    let registered = w
        .register
        .execute(
            RegisterCommand {
                email: "  Bob@IDP.Test".to_owned(),
                ..bob()
            },
            None,
            now(),
        )
        .await
        .unwrap();

    assert_eq!(
        (registered.username.as_str(), registered.email.as_str()),
        ("bob_sfx02", "bob@idp.test")
    );
}

#[tokio::test]
async fn a_registration_continuing_a_sign_in_is_refused_for_a_request_not_from_a_client() {
    let w = world().await;
    let stranger = AuthorizationRequest {
        client: ClientId::parse("http://localhost:5173/stranger.json").unwrap(),
        ..a_request()
    };
    let elsewhere = AuthorizationRequest {
        redirect_uri: "https://evil.test/callback".to_owned(),
        ..a_request()
    };

    let unknown = w.register.execute(bob(), Some(&stranger), now()).await;
    let unregistered = w.register.execute(bob(), Some(&elsewhere), now()).await;
    let fine = w.register.execute(bob(), Some(&a_request()), now()).await;

    assert!(
        matches!(unknown, Err(AuthError::UnknownClient)),
        "{unknown:?}"
    );
    assert!(
        matches!(unregistered, Err(AuthError::UnregisteredRedirect)),
        "{unregistered:?}"
    );
    assert!(fine.is_ok(), "{fine:?}");
    assert_eq!(w.accounts.created().len(), 1);
}

#[tokio::test]
async fn an_invite_only_instance_refuses_a_registration_creating_and_mailing_nothing() {
    let w = invite_only().await;
    let taken = RegisterCommand {
        email: w.alice.email.clone(),
        ..bob()
    };

    let refusals = [
        w.register.execute(bob(), None, now()).await,
        w.register.execute(bob(), Some(&a_request()), now()).await,
        w.register.execute(taken, None, now()).await,
    ];

    for refused in refusals {
        assert!(
            matches!(refused, Err(AuthError::InvitationRequired)),
            "whatever was typed, the instance tells nothing of its accounts: {refused:?}"
        );
    }
    assert!(w.accounts.created().is_empty());
    assert!(w.signup_codes.issued().is_empty());
    assert!(w.mailer.sent().is_empty());
}
