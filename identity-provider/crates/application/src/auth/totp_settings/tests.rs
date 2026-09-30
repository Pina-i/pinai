use domain::auth::SignInAccount;
use domain::auth::testing::{StepAuthenticator, signed_up};

use crate::auth::world::{World, now, world};

use super::*;

async fn bob_with_an_app(w: &World) -> (SignInAccount, String, Vec<String>) {
    let bob = SignInAccount {
        totp_enabled: true,
        ..signed_up("bob")
    };
    w.sign_up(&bob).await;
    let (secret, recovery) = w.with_authenticator(&bob).await;
    (bob, StepAuthenticator::code_at(&secret, now()), recovery)
}

fn another_than(code: &str) -> &'static str {
    if code == "000000" { "111111" } else { "000000" }
}

#[tokio::test]
async fn turning_the_second_factor_off_needs_the_apps_code_and_clears_everything() {
    let w = world().await;
    let (bob, code, _) = bob_with_an_app(&w).await;

    let guessed = w.disable.execute(bob.id, another_than(&code), now()).await;
    let still = w.factors.state_of(bob.id);
    w.disable.execute(bob.id, &code, now()).await.unwrap();

    assert!(matches!(guessed, Err(AuthError::WrongCode)), "{guessed:?}");
    assert_eq!(still, (true, 10, false));
    assert_eq!(w.factors.state_of(bob.id), (false, 0, false));
    assert!(
        !w.accounts
            .by_id(bob.id)
            .await
            .unwrap()
            .unwrap()
            .totp_enabled
    );
}

#[tokio::test]
async fn new_recovery_codes_need_the_apps_code_and_void_the_old() {
    let w = world().await;
    let (bob, code, old) = bob_with_an_app(&w).await;

    let guessed = w
        .regenerate
        .execute(bob.id, another_than(&code), now())
        .await;
    let fresh = w.regenerate.execute(bob.id, &code, now()).await.unwrap();

    assert!(matches!(guessed, Err(AuthError::WrongCode)), "{guessed:?}");
    assert_eq!(fresh.len(), 10);
    assert!(!w.factors.use_recovery_code(bob.id, &old[0]).await.unwrap());
    assert!(
        w.factors
            .use_recovery_code(bob.id, &fresh[0])
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn neither_is_done_for_an_account_without_a_second_factor_or_unknown() {
    let w = world().await;

    let off = w.disable.execute(w.alice.id, "123456", now()).await;
    let none = w.regenerate.execute(w.alice.id, "123456", now()).await;
    let unknown = w.disable.execute(UserId::generate(), "123456", now()).await;

    assert!(matches!(off, Err(AuthError::TotpNotEnabled)), "{off:?}");
    assert!(matches!(none, Err(AuthError::TotpNotEnabled)), "{none:?}");
    assert!(
        matches!(unknown, Err(AuthError::UnknownUser)),
        "{unknown:?}"
    );
}

#[tokio::test]
async fn a_disabling_the_store_fails_part_way_never_leaves_codes_without_the_factor() {
    let w = world().await;
    let (bob, code, _) = bob_with_an_app(&w).await;
    w.factors.down_after(1);

    let _ = w.disable.execute(bob.id, &code, now()).await;

    let (on, codes, _) = w.factors.state_of(bob.id);
    assert_eq!(on, codes > 0, "on: {on}, codes: {codes}");
}
