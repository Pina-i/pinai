use domain::auth::testing::{
    CHALLENGE, CountingSuffixes, InMemorySignInAccounts, PlainHasher, SignUpRecords, a_request,
    web_client,
};
use domain::auth::{
    ClientSignIns, INVITATION_TTL, Invitations, RevokedReason, SessionKind, Sessions, SignInAccount,
};

use crate::auth::world::{World, invite_only, now, world};
use crate::auth::{AuthorizeCommand, Authorized};

use super::*;

fn hoku() -> RegisterCommand {
    RegisterCommand {
        display_name: "Hōkū".to_owned(),
        email: "hoku@idp.test".to_owned(),
        password: "hoku-password".to_owned(),
    }
}

/// An invitation from the instance's admin: who made it, and its token.
async fn invited(w: &World) -> (SignInAccount, InvitationToken) {
    let admin = w.an_admin().await;
    let (_, token) = w
        .accounts
        .issue(admin.id, now(), now() + INVITATION_TTL)
        .await
        .unwrap();
    (admin, token)
}

#[tokio::test]
async fn an_invited_account_is_admitted_vouched_for_and_mailed_nothing() {
    let w = world().await;
    let (admin, token) = invited(&w).await;

    let joined = w
        .register_invited
        .execute(&token, hoku(), None, now())
        .await
        .unwrap();

    let Joined::InWebApp { user, .. } = joined else {
        panic!("{joined:?}");
    };
    let account = w.accounts.by_id(user).await.unwrap().unwrap();
    assert_eq!(
        (account.email.as_str(), account.username.as_str()),
        ("hoku@idp.test", "hoku_sfx01")
    );
    assert!(account.admitted && !account.email_verified && !account.admin);
    assert!(!account.needs_code());
    assert_eq!(w.accounts.invited_by(user).await, Some(admin.id));
    assert!(w.mailer.sent().is_empty());
    assert!(w.signup_codes.issued().is_empty());
    assert_eq!(w.accounts.find_open(&token, now()).await.unwrap(), None);
}

#[tokio::test]
async fn joining_signs_the_browser_in_and_records_the_web_app_as_signed_in_to() {
    let w = world().await;
    let (_, token) = invited(&w).await;

    let joined = w
        .register_invited
        .execute(&token, hoku(), None, now())
        .await
        .unwrap();

    let session = w.sessions.all()[0].clone();
    assert_eq!(
        joined,
        Joined::InWebApp {
            user: session.user,
            session: session.id,
            entry: "http://localhost:5173/?instance=localhost%3A8080".to_owned(),
        }
    );
    assert_eq!(
        (session.kind, session.authenticated_at, session.revoked_at),
        (SessionKind::Browser, now(), None)
    );
    assert_eq!(
        w.sign_ins.remembered(),
        vec![ClientSignIn {
            user: session.user,
            client: web_client().id,
            offline_access: false,
        }]
    );
    assert!(w.codes.issued().is_empty(), "no request is in flight");
}

#[tokio::test]
async fn the_web_app_then_signs_in_without_the_password() {
    let w = world().await;
    let (_, token) = invited(&w).await;
    let Joined::InWebApp { user, session, .. } = w
        .register_invited
        .execute(&token, hoku(), None, now())
        .await
        .unwrap()
    else {
        panic!("not into the web app");
    };
    let request = a_request();

    let authorized = w
        .authorize
        .execute(
            AuthorizeCommand {
                response_type: "code".to_owned(),
                client_id: request.client.as_str().to_owned(),
                redirect_uri: request.redirect_uri.clone(),
                scope: request.scope.clone(),
                state: request.state.clone(),
                code_challenge: CHALLENGE.to_owned(),
                code_challenge_method: "S256".to_owned(),
                nonce: request.nonce.clone(),
                prompt: None,
            },
            Some(session),
            now(),
        )
        .await
        .unwrap();

    assert!(
        matches!(&authorized, Authorized::Code { session: s, .. } if *s == session),
        "{authorized:?}"
    );
    assert_eq!(w.codes.issued()[0].1.user, user);
}

#[tokio::test]
async fn a_browser_signed_in_as_someone_else_is_signed_in_as_the_new_account() {
    let w = world().await;
    let (_, token) = invited(&w).await;
    let alices = w
        .sessions
        .open(w.alice.id, &SessionKind::Browser, now())
        .await
        .unwrap();

    let joined = w
        .register_invited
        .execute(&token, hoku(), Some(alices), now())
        .await
        .unwrap();

    assert!(matches!(joined, Joined::InWebApp { session, .. } if session != alices));
    assert_eq!(w.sessions.reason(alices), Some(RevokedReason::Replaced));
}

#[tokio::test]
async fn without_a_web_app_the_account_is_ready_and_nobody_signed_in() {
    let w = world().await;
    let (_, token) = invited(&w).await;
    let register = RegisterInvited::new(
        w.origin.clone(),
        Registrations::Open,
        None,
        w.accounts.clone(),
        w.accounts.clone(),
        w.accounts.clone(),
        w.hasher.clone(),
        Arc::new(CountingSuffixes::default()),
        Arc::new(CompleteSignIn::new(
            w.sign_ins.clone(),
            w.codes.clone(),
            w.sessions.clone(),
            w.ended.clone(),
        )),
    );

    let joined = register.execute(&token, hoku(), None, now()).await.unwrap();

    let Joined::Ready(registered) = joined else {
        panic!("{joined:?}");
    };
    assert_eq!(registered.email, "hoku@idp.test");
    assert_eq!(register.web_app_entry(), None);
    assert!(w.sessions.all().is_empty());
    assert!(w.sign_ins.remembered().is_empty());
    assert!(w.mailer.sent().is_empty());
}

/// Remembers no app: its store is down.
struct DownSignIns;

#[async_trait::async_trait]
impl ClientSignIns for DownSignIns {
    async fn remember(&self, _: &ClientSignIn, _: OffsetDateTime) -> Result<(), AuthError> {
        Err(anyhow::anyhow!("the store is down").into())
    }

    async fn find(
        &self,
        _: domain::UserId,
        _: &domain::auth::ClientId,
    ) -> Result<Option<ClientSignIn>, AuthError> {
        Ok(None)
    }
}

#[tokio::test]
async fn an_account_created_but_not_signed_in_is_ready_to_sign_in_from_the_app() {
    let w = world().await;
    let (_, token) = invited(&w).await;
    let register = RegisterInvited::new(
        w.origin.clone(),
        Registrations::Open,
        Some(WebApp::parse("http://localhost:5173").unwrap()),
        w.accounts.clone(),
        w.accounts.clone(),
        w.accounts.clone(),
        w.hasher.clone(),
        Arc::new(CountingSuffixes::default()),
        Arc::new(CompleteSignIn::new(
            Arc::new(DownSignIns),
            w.codes.clone(),
            w.sessions.clone(),
            w.ended.clone(),
        )),
    );

    let joined = register.execute(&token, hoku(), None, now()).await.unwrap();

    let Joined::Ready(registered) = joined else {
        panic!("{joined:?}");
    };
    assert!(
        w.accounts
            .by_id(registered.user)
            .await
            .unwrap()
            .is_some_and(|account| account.admitted)
    );
    assert_eq!(w.accounts.find_open(&token, now()).await.unwrap(), None);
}

#[tokio::test]
async fn an_invitation_lets_one_account_in() {
    let w = world().await;
    let (_, token) = invited(&w).await;
    w.register_invited
        .execute(&token, hoku(), None, now())
        .await
        .unwrap();

    let again = w
        .register_invited
        .execute(
            &token,
            RegisterCommand {
                email: "keoni@idp.test".to_owned(),
                ..hoku()
            },
            None,
            now(),
        )
        .await;

    assert!(
        matches!(again, Err(AuthError::InvitationUnusable)),
        "{again:?}"
    );
    assert_eq!(w.accounts.created().len(), 1);
}

#[tokio::test]
async fn an_invitation_spent_after_it_was_found_lets_nobody_in() {
    let w = world().await;
    let (_, token) = invited(&w).await;
    // Another store: it holds no such open invitation, as if a racing sign-up had spent it.
    let elsewhere = Arc::new(InMemorySignInAccounts::default());
    let register = RegisterInvited::new(
        w.origin.clone(),
        Registrations::Open,
        None,
        elsewhere.clone(),
        elsewhere.clone(),
        w.accounts.clone(),
        Arc::new(PlainHasher::default()),
        Arc::new(CountingSuffixes::default()),
        Arc::new(CompleteSignIn::new(
            w.sign_ins.clone(),
            w.codes.clone(),
            w.sessions.clone(),
            w.ended.clone(),
        )),
    );

    let joined = register.execute(&token, hoku(), None, now()).await;

    assert!(
        matches!(joined, Err(AuthError::InvitationUnusable)),
        "{joined:?}"
    );
    assert!(elsewhere.created().is_empty());
}

#[tokio::test]
async fn a_broken_rule_or_a_taken_address_leaves_the_invitation_open() {
    let w = world().await;
    let (_, token) = invited(&w).await;
    let refused = async |command: RegisterCommand| {
        w.register_invited
            .execute(&token, command, None, now())
            .await
            .unwrap_err()
    };

    let name = refused(RegisterCommand {
        display_name: "  ".to_owned(),
        ..hoku()
    })
    .await;
    let address = refused(RegisterCommand {
        email: "hoku".to_owned(),
        ..hoku()
    })
    .await;
    let password = refused(RegisterCommand {
        password: "short".to_owned(),
        ..hoku()
    })
    .await;
    let taken = refused(RegisterCommand {
        email: w.alice.email.to_uppercase(),
        ..hoku()
    })
    .await;

    assert!(matches!(name, AuthError::BadDisplayName(_)), "{name:?}");
    assert!(matches!(address, AuthError::BadEmail(_)), "{address:?}");
    assert!(
        matches!(password, AuthError::PasswordTooShort),
        "{password:?}"
    );
    assert!(matches!(taken, AuthError::EmailTaken), "{taken:?}");
    assert!(w.accounts.find_open(&token, now()).await.unwrap().is_some());
    assert!(w.accounts.created().is_empty());
}

#[tokio::test]
async fn an_unknown_or_expired_invitation_lets_nobody_in() {
    let w = world().await;
    let (_, token) = invited(&w).await;

    let unknown = w
        .register_invited
        .execute(&InvitationToken::from_bytes([3; 32]), hoku(), None, now())
        .await;
    let expired = w
        .register_invited
        .execute(&token, hoku(), None, now() + INVITATION_TTL)
        .await;

    assert!(
        matches!(unknown, Err(AuthError::InvitationUnusable)),
        "{unknown:?}"
    );
    assert!(
        matches!(expired, Err(AuthError::InvitationUnusable)),
        "{expired:?}"
    );
    assert!(w.accounts.created().is_empty());
}

#[tokio::test]
async fn an_invitation_lets_its_person_in_whether_the_instance_is_open_or_invite_only() {
    for w in [world().await, invite_only().await] {
        let (_, token) = invited(&w).await;

        let joined = w
            .register_invited
            .execute(&token, hoku(), None, now())
            .await;

        assert!(matches!(joined, Ok(Joined::InWebApp { .. })), "{joined:?}");
    }
}
