use domain::SessionId;
use domain::UserId;
use domain::auth::testing::{CLIENT_ID, REDIRECT_URI, VERIFIER, a_request, another_web_app};
use domain::auth::{
    AuthorizationCodes, AuthorizationRequest, DESKTOP_REDIRECT_URI, Grant, RefreshToken,
    RevokedReason, SessionKind, Sessions,
};
use time::Duration;

use crate::auth::world::{World, now, world};

use super::*;

/// Alice's code, under a session of hers.
async fn a_code(w: &World) -> AuthorizationCode {
    let session = w.sessions.open_browser(w.alice.id, now()).await.unwrap();
    code_under(w, session).await
}

async fn code_under(w: &World, session: SessionId) -> AuthorizationCode {
    w.codes
        .issue(
            &Grant::answering(w.alice.id, session, &a_request()),
            now() + Duration::minutes(10),
        )
        .await
        .unwrap()
}

fn command(code: &AuthorizationCode) -> TokenCommand {
    TokenCommand {
        code: code.as_str().to_owned(),
        redirect_uri: REDIRECT_URI.to_owned(),
        client_id: CLIENT_ID.to_owned(),
        code_verifier: VERIFIER.to_owned(),
    }
}

/// The web app's session under `browser`.
fn web_app_under(w: &World, browser: SessionId) -> domain::auth::Session {
    w.sessions
        .all()
        .into_iter()
        .find(|session| session.browser() == Some(browser))
        .expect("a web app's session under the browser's")
}

#[tokio::test]
async fn a_code_is_exchanged_once_for_tokens_naming_the_web_apps_session_under_the_browsers() {
    let w = world().await;
    let browser = w.sessions.open_browser(w.alice.id, now()).await.unwrap();
    let code = code_under(&w, browser).await;

    let tokens = w.exchange.execute(command(&code), now()).await.unwrap();
    let again = w.exchange.execute(command(&code), now()).await;

    let web = web_app_under(&w, browser);
    assert_eq!(
        web.kind,
        SessionKind::Web {
            client: a_request().client,
            browser,
        }
    );
    assert_eq!(
        tokens,
        Tokens {
            access_token: format!("access:{}:{}:{CLIENT_ID}", w.alice.id, web.id),
            refresh_token: RefreshToken::new("refresh-1".to_owned()),
            id_token: Some(format!(
                "id:{}:{CLIENT_ID}:{}:the-nonce",
                w.alice.id, w.alice.email
            )),
            expires_in: Duration::hours(1),
        }
    );
    assert!(matches!(again, Err(AuthError::CodeUnusable)), "{again:?}");
    assert_eq!(
        w.refresh_tokens.of(web.id),
        vec![RefreshToken::new("refresh-1".to_owned())],
        "the chain hangs off the web app's session"
    );
    assert!(w.refresh_tokens.of(browser).is_empty());
}

#[tokio::test]
async fn a_web_apps_next_sign_in_in_that_browser_reuses_its_session_and_the_device_it_named() {
    let w = world().await;
    let browser = w.sessions.open_browser(w.alice.id, now()).await.unwrap();
    let first = w
        .exchange
        .execute(command(&code_under(&w, browser).await), now())
        .await
        .unwrap();
    let web = web_app_under(&w, browser);
    let device = domain::DeviceId::generate();
    w.sessions
        .link(w.alice.id, web.id, device, now())
        .await
        .unwrap();
    // A sensitive action asked the password again on the browser's session.
    let typed = now() + Duration::minutes(4);
    w.sessions.authenticate(browser, typed).await.unwrap();

    let reloaded = w
        .exchange
        .execute(
            command(&code_under(&w, browser).await),
            now() + Duration::minutes(5),
        )
        .await
        .unwrap();

    assert_eq!(
        reloaded.access_token,
        format!("access:{}:{}:{CLIENT_ID}", w.alice.id, web.id),
        "the same session"
    );
    assert_ne!(
        reloaded.refresh_token, first.refresh_token,
        "a chain of its own"
    );
    let held = w.sessions.find(web.id).await.unwrap().unwrap();
    assert_eq!(held.device, Some(device), "its device stays named");
    assert_eq!(held.authenticated_at, typed, "the password the browser's");
    assert_eq!(w.sessions.all().len(), 2);
}

#[tokio::test]
async fn two_web_apps_signed_in_through_one_browser_get_a_session_each() {
    let w = world().await;
    let browser = w.sessions.open_browser(w.alice.id, now()).await.unwrap();
    let other = another_web_app();
    let request = AuthorizationRequest {
        client: other.id.clone(),
        redirect_uri: "http://localhost:4173/callback".to_owned(),
        ..a_request()
    };
    let other_code = w
        .codes
        .issue(
            &Grant::answering(w.alice.id, browser, &request),
            now() + Duration::minutes(10),
        )
        .await
        .unwrap();

    w.exchange
        .execute(command(&code_under(&w, browser).await), now())
        .await
        .unwrap();
    let theirs = w
        .exchange
        .execute(
            TokenCommand {
                redirect_uri: "http://localhost:4173/callback".to_owned(),
                client_id: other.id.as_str().to_owned(),
                ..command(&other_code)
            },
            now(),
        )
        .await
        .unwrap();

    let under: Vec<_> = w
        .sessions
        .all()
        .into_iter()
        .filter(|session| session.browser() == Some(browser))
        .collect();
    assert_eq!(under.len(), 2, "one each");
    let other_session = under
        .iter()
        .find(|session| {
            session.kind
                == SessionKind::Web {
                    client: other.id.clone(),
                    browser,
                }
        })
        .expect("the other app's");
    assert_eq!(
        theirs.access_token,
        format!(
            "access:{}:{}:{}",
            w.alice.id,
            other_session.id,
            other.id.as_str()
        )
    );
}

/// What the desktop app sends, under a browser session of Alice's.
async fn a_desktop_code(w: &World, scope: &str) -> (SessionId, TokenCommand) {
    let browser = w.sessions.open_browser(w.alice.id, now()).await.unwrap();
    let request = AuthorizationRequest {
        client: w.desktop.id.clone(),
        redirect_uri: DESKTOP_REDIRECT_URI.to_owned(),
        scope: scope.to_owned(),
        ..a_request()
    };
    let code = w
        .codes
        .issue(
            &Grant::answering(w.alice.id, browser, &request),
            now() + Duration::minutes(10),
        )
        .await
        .unwrap();
    let command = TokenCommand {
        redirect_uri: DESKTOP_REDIRECT_URI.to_owned(),
        client_id: w.desktop.id.as_str().to_owned(),
        ..command(&code)
    };
    (browser, command)
}

#[tokio::test]
async fn an_app_staying_signed_in_gets_a_session_of_its_own_that_outlives_the_browsers() {
    let w = world().await;
    let (browser, command) = a_desktop_code(&w, "openid profile email offline_access").await;

    let tokens = w.exchange.execute(command, now()).await.unwrap();

    let app = w
        .sessions
        .all()
        .into_iter()
        .find(|session| session.id != browser)
        .expect("a second session");
    assert_eq!(app.kind, SessionKind::App(w.desktop.id.clone()));
    assert_eq!(app.user, w.alice.id);
    assert_eq!(
        tokens.access_token,
        format!("access:{}:{}:{}", w.alice.id, app.id, w.desktop.id.as_str())
    );
    assert_eq!(w.refresh_tokens.of(app.id), vec![tokens.refresh_token]);
    assert!(w.refresh_tokens.of(browser).is_empty());

    w.log_out
        .execute(Some(browser), None, None, now())
        .await
        .unwrap();
    assert!(
        w.sessions
            .find(app.id)
            .await
            .unwrap()
            .unwrap()
            .is_live(now()),
        "signing out of the browser leaves the app signed in"
    );
}

#[tokio::test]
async fn an_apps_session_was_signed_in_when_the_browsers_was_not_when_it_opened() {
    let w = world().await;
    let (browser, command) = a_desktop_code(&w, "openid profile email offline_access").await;

    w.exchange
        .execute(command, now() + Duration::minutes(2))
        .await
        .unwrap();

    let app = w
        .sessions
        .all()
        .into_iter()
        .find(|session| session.id != browser)
        .expect("a second session");
    assert_eq!(app.authenticated_at, now());
}

#[tokio::test]
async fn a_client_not_asking_or_not_allowed_to_stay_signed_in_gets_its_session_under_the_browsers()
{
    let w = world().await;
    let (desktop_browser, not_asking) = a_desktop_code(&w, "openid profile email").await;
    let web_browser = w.sessions.open_browser(w.alice.id, now()).await.unwrap();
    let asking = AuthorizationRequest {
        scope: "openid profile email offline_access".to_owned(),
        ..a_request()
    };
    let web_code = w
        .codes
        .issue(
            &Grant::answering(w.alice.id, web_browser, &asking),
            now() + Duration::minutes(10),
        )
        .await
        .unwrap();

    let desktop = w.exchange.execute(not_asking, now()).await.unwrap();
    let web = w.exchange.execute(command(&web_code), now()).await.unwrap();

    let (desktops, webs) = (
        web_app_under(&w, desktop_browser),
        web_app_under(&w, web_browser),
    );
    assert_eq!(
        desktops.kind,
        SessionKind::Web {
            client: w.desktop.id.clone(),
            browser: desktop_browser,
        }
    );
    assert_eq!(
        w.refresh_tokens.of(desktops.id),
        vec![desktop.refresh_token]
    );
    assert_eq!(w.refresh_tokens.of(webs.id), vec![web.refresh_token]);
    assert!(
        !w.sessions
            .all()
            .iter()
            .any(|session| matches!(session.kind, SessionKind::App(_))),
        "no session staying signed in"
    );
}

#[tokio::test]
async fn an_exchange_is_refused_for_another_client_or_redirect_and_a_wrong_verifier() {
    let w = world().await;
    let refused = async |change: fn(TokenCommand) -> TokenCommand| {
        let code = a_code(&w).await;
        w.exchange
            .execute(change(command(&code)), now())
            .await
            .unwrap_err()
    };

    let stranger = refused(|c| TokenCommand {
        client_id: "http://localhost:5173/stranger.json".to_owned(),
        ..c
    })
    .await;
    let elsewhere = refused(|c| TokenCommand {
        redirect_uri: "https://evil.test/callback".to_owned(),
        ..c
    })
    .await;
    let guessed = refused(|c| TokenCommand {
        code_verifier: "a-guess".to_owned(),
        ..c
    })
    .await;
    let unknown = refused(|c| TokenCommand {
        code: "no-such-code".to_owned(),
        ..c
    })
    .await;

    assert!(matches!(stranger, AuthError::UnknownClient), "{stranger:?}");
    assert!(
        matches!(elsewhere, AuthError::RedirectMismatch),
        "{elsewhere:?}"
    );
    assert!(
        matches!(guessed, AuthError::VerifierMismatch),
        "{guessed:?}"
    );
    assert!(matches!(unknown, AuthError::CodeUnusable), "{unknown:?}");
}

#[tokio::test]
async fn a_refused_verifier_still_spends_the_code() {
    let w = world().await;
    let code = a_code(&w).await;

    let guessed = w
        .exchange
        .execute(
            TokenCommand {
                code_verifier: "a-guess".to_owned(),
                ..command(&code)
            },
            now(),
        )
        .await;
    let after = w.exchange.execute(command(&code), now()).await;

    assert!(matches!(guessed, Err(AuthError::VerifierMismatch)));
    assert!(matches!(after, Err(AuthError::CodeUnusable)), "{after:?}");
}

#[tokio::test]
async fn a_code_whose_account_is_gone_is_unusable() {
    let w = world().await;
    let code = w
        .codes
        .issue(
            &Grant::answering(UserId::generate(), SessionId::generate(), &a_request()),
            now() + Duration::minutes(10),
        )
        .await
        .unwrap();

    let refused = w.exchange.execute(command(&code), now()).await;

    assert!(
        matches!(refused, Err(AuthError::CodeUnusable)),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_code_whose_session_ended_before_its_exchange_is_unusable() {
    let w = world().await;
    let session = w.sessions.open_browser(w.alice.id, now()).await.unwrap();
    let code = code_under(&w, session).await;
    w.sessions
        .revoke(session, RevokedReason::SignOut, now())
        .await
        .unwrap();

    let refused = w.exchange.execute(command(&code), now()).await;

    assert!(
        matches!(refused, Err(AuthError::CodeUnusable)),
        "{refused:?}"
    );
}
