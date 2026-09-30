use domain::auth::testing::signed_up;
use domain::auth::{RESEND_LIMIT, RESEND_WINDOW, SignInAccount};

use crate::auth::world::{now, world};

use super::*;

#[tokio::test]
async fn a_fresh_code_is_mailed_on_asking_up_to_the_limit() {
    let w = world().await;
    let bob = SignInAccount {
        email_verified: false,
        ..signed_up("bob")
    };
    w.sign_up(&bob).await;

    let mut answers = Vec::new();
    for _ in 0..=RESEND_LIMIT {
        answers.push(
            w.resend
                .execute(bob.id, now())
                .await
                .map_err(|e| e.to_string()),
        );
    }

    assert_eq!(answers[..RESEND_LIMIT], vec![Ok(()); RESEND_LIMIT]);
    assert_eq!(
        answers[RESEND_LIMIT],
        Err(AuthError::TooManyCodes.to_string())
    );
    assert_eq!(w.mailer.sent().len(), RESEND_LIMIT);
    assert!(
        w.resend
            .execute(bob.id, now() + RESEND_WINDOW)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_confirmed_or_unknown_account_is_mailed_nothing() {
    let w = world().await;

    let confirmed = w.resend.execute(w.alice.id, now()).await;
    let unknown = w.resend.execute(UserId::generate(), now()).await;

    assert!(
        matches!(confirmed, Err(AuthError::AlreadyVerified)),
        "{confirmed:?}"
    );
    assert!(
        matches!(unknown, Err(AuthError::UnknownUser)),
        "{unknown:?}"
    );
    assert!(w.mailer.sent().is_empty());
}
