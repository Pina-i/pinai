use domain::auth::SignInAccount;
use domain::auth::testing::{StepAuthenticator, signed_up};

use crate::auth::world::{now, world};

use super::*;

#[tokio::test]
async fn an_enrolled_secret_turns_the_second_factor_on_once_the_apps_code_confirms_it() {
    let w = world().await;

    let enrollment = w.enroll.execute(w.alice.id).await.unwrap();
    let pending = w.factors.pending(w.alice.id).await.unwrap().unwrap();
    let codes = w
        .confirm
        .execute(
            w.alice.id,
            &StepAuthenticator::code_at(&pending, now()),
            now(),
        )
        .await
        .unwrap();

    assert_eq!(
        enrollment,
        Enrollment {
            secret_base32: "SECRET1".to_owned(),
            provisioning_url:
                "otpauth://totp/Pina'i (localhost:8080):alice@idp.test?secret=SECRET1".to_owned(),
        }
    );
    assert_eq!(codes.len(), domain::auth::RECOVERY_CODES);
    assert_eq!(w.factors.state_of(w.alice.id), (true, 10, false));
    let alice: SignInAccount = w.accounts.by_id(w.alice.id).await.unwrap().unwrap();
    assert!(alice.totp_enabled);
}

#[tokio::test]
async fn enrolling_again_is_refused_while_on_and_a_confirmation_needs_the_right_code() {
    let w = world().await;
    let bob = SignInAccount {
        totp_enabled: true,
        ..signed_up("bob")
    };
    w.sign_up(&bob).await;

    let again = w.enroll.execute(bob.id).await;
    let unasked = w.confirm.execute(w.alice.id, "123456", now()).await;
    w.enroll.execute(w.alice.id).await.unwrap();
    let pending = w.factors.pending(w.alice.id).await.unwrap().unwrap();
    let right = StepAuthenticator::code_at(&pending, now());
    let wrong = if right == "000000" {
        "111111"
    } else {
        "000000"
    };
    let guessed = w.confirm.execute(w.alice.id, wrong, now()).await;
    let unknown = w.enroll.execute(UserId::generate()).await;

    assert!(matches!(again, Err(AuthError::TotpEnabled)), "{again:?}");
    assert!(
        matches!(unasked, Err(AuthError::NoEnrollment)),
        "{unasked:?}"
    );
    assert!(matches!(guessed, Err(AuthError::WrongCode)), "{guessed:?}");
    assert!(
        matches!(unknown, Err(AuthError::UnknownUser)),
        "{unknown:?}"
    );
    assert_eq!(w.factors.state_of(w.alice.id), (false, 0, true));
}

/// On with recovery codes to use, or off with none; never on while an enrollment waits.
fn consistent((on, codes, pending): (bool, usize, bool)) -> bool {
    on == (codes > 0) && !(on && pending)
}

#[tokio::test]
async fn a_confirmation_the_store_fails_part_way_never_leaves_the_factor_on_without_codes() {
    let w = world().await;
    w.enroll.execute(w.alice.id).await.unwrap();
    let pending = w.factors.pending(w.alice.id).await.unwrap().unwrap();
    w.factors.down_after(1);

    let _ = w
        .confirm
        .execute(
            w.alice.id,
            &StepAuthenticator::code_at(&pending, now()),
            now(),
        )
        .await;

    let state = w.factors.state_of(w.alice.id);
    assert!(consistent(state), "{state:?}");
}
