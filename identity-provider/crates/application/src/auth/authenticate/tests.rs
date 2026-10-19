use domain::UserId;
use domain::auth::SessionKind;
use domain::auth::testing::InMemorySessions;
use domain::auth::{RevokedReason, SESSION_IDLE, Sessions};
use domain::identity::testing::InMemoryTokens;

use crate::auth::world::now;

use super::*;

fn authenticate(tokens: &Arc<InMemoryTokens>, sessions: &Arc<InMemorySessions>) -> Authenticate {
    Authenticate::new(tokens.clone(), sessions.clone())
}

#[tokio::test]
async fn a_token_of_a_live_session_names_its_user_and_session() {
    let (tokens, sessions) = (
        Arc::new(InMemoryTokens::default()),
        Arc::new(InMemorySessions::default()),
    );
    let alice = UserId::generate();
    let session = sessions
        .open(alice, &SessionKind::Browser, now())
        .await
        .unwrap();
    let token = tokens.issue(alice, session);

    let bearer = authenticate(&tokens, &sessions)
        .execute(&token, now())
        .await
        .unwrap();

    assert_eq!(
        bearer,
        Bearer {
            user: alice,
            session
        }
    );
}

#[tokio::test]
async fn a_token_outlives_no_session_ended_idle_or_unknown() {
    let (tokens, sessions) = (
        Arc::new(InMemoryTokens::default()),
        Arc::new(InMemorySessions::default()),
    );
    let alice = UserId::generate();
    let revoked = sessions
        .open(alice, &SessionKind::Browser, now())
        .await
        .unwrap();
    sessions
        .revoke(revoked, RevokedReason::SignOut, now())
        .await
        .unwrap();
    let idle = sessions
        .open(alice, &SessionKind::Browser, now() - SESSION_IDLE)
        .await
        .unwrap();
    let someone_elses = sessions
        .open(UserId::generate(), &SessionKind::Browser, now())
        .await
        .unwrap();
    let authenticate = authenticate(&tokens, &sessions);

    for session in [revoked, idle, someone_elses, domain::SessionId::generate()] {
        let token = tokens.issue(alice, session);
        let refused = authenticate.execute(&token, now()).await;

        assert!(
            matches!(refused, Err(TokenError::SessionEnded)),
            "{refused:?}"
        );
    }
    assert!(matches!(
        authenticate.execute("forged", now()).await,
        Err(TokenError::Invalid)
    ));
}
