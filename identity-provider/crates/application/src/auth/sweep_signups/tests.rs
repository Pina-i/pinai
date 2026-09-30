use domain::auth::testing::{a_request, signed_up};
use domain::auth::{LoginTickets, SignInAccounts, SignupCodes};
use domain::auth::{SIGNUP_CODE_TTL, SignInAccount};
use time::Duration;

use crate::auth::world::world;

use super::*;

#[tokio::test]
async fn the_sweep_deletes_what_was_spent_a_day_ago_and_the_accounts_never_confirmed() {
    let w = world().await;
    let now = OffsetDateTime::now_utc();
    let bob = SignInAccount {
        email_verified: false,
        ..signed_up("bob")
    };
    w.sign_up(&bob).await;
    w.signup_codes
        .issue(bob.id, now - Duration::days(2))
        .await
        .unwrap();
    w.tickets
        .open(w.alice.id, &a_request(), now - Duration::days(2))
        .await
        .unwrap();
    w.signup_codes
        .issue(w.alice.id, now + SIGNUP_CODE_TTL)
        .await
        .unwrap();

    let a_week_on = now + UNVERIFIED_TTL + Duration::minutes(1);

    let today = w.sweep.execute(now).await.unwrap();
    let swept = w.sweep.execute(a_week_on).await.unwrap();

    assert_eq!(
        today,
        Swept {
            codes: 1,
            tickets: 1,
            accounts: 0,
        }
    );
    assert_eq!(
        swept,
        Swept {
            codes: 1,
            tickets: 0,
            accounts: 1,
        }
    );
    assert_eq!(w.accounts.by_id(bob.id).await.unwrap(), None);
    assert!(w.accounts.by_id(w.alice.id).await.unwrap().is_some());
}
