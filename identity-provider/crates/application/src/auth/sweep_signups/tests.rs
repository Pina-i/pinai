use domain::auth::SessionKind;
use domain::auth::testing::{a_request, signed_up};
use domain::auth::{
    INVITATION_TTL, Invitations, RefreshTokens, SESSION_IDLE, SIGNUP_CODE_TTL, SignInAccount,
};
use domain::auth::{LoginTickets, SignInAccounts, SignupCodes};
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
            sessions: 0,
            refresh_tokens: 0,
            invitations: 0,
        }
    );
    assert_eq!(
        swept,
        Swept {
            codes: 1,
            tickets: 0,
            accounts: 1,
            sessions: 0,
            refresh_tokens: 0,
            invitations: 0,
        }
    );
    assert_eq!(w.accounts.by_id(bob.id).await.unwrap(), None);
    assert!(w.accounts.by_id(w.alice.id).await.unwrap().is_some());
}

#[tokio::test]
async fn a_session_is_swept_a_month_after_it_ended() {
    let w = world().await;
    let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
    let signed_out = w
        .sessions
        .open(w.alice.id, &SessionKind::Browser, now)
        .await
        .unwrap();
    w.sessions
        .revoke(signed_out, domain::auth::RevokedReason::SignOut, now)
        .await
        .unwrap();
    let live = w
        .sessions
        .open(w.alice.id, &SessionKind::Browser, now)
        .await
        .unwrap();

    let a_month_on = w
        .sweep
        .execute(now + domain::auth::SESSION_RETENTION + Duration::minutes(1))
        .await
        .unwrap();

    assert_eq!(a_month_on.sessions, 1);
    assert_eq!(
        w.sessions.all().iter().map(|s| s.id).collect::<Vec<_>>(),
        vec![live]
    );
}

#[tokio::test]
async fn a_refresh_token_is_swept_after_ninety_days_unused() {
    let w = world().await;
    let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
    let session = w
        .sessions
        .open(w.alice.id, &SessionKind::Browser, now)
        .await
        .unwrap();
    let client = a_request().client;
    let abandoned = w.refresh_tokens.start(session, &client, now).await.unwrap();
    let used = w
        .refresh_tokens
        .start(session, &client, now - Duration::days(1))
        .await
        .unwrap();
    let head = match w
        .refresh_tokens
        .rotate(&used, &client, now + Duration::days(1))
        .await
        .unwrap()
    {
        domain::auth::Rotation::Rotated { successor, .. } => successor,
        other => panic!("{other:?}"),
    };

    let swept = w
        .sweep
        .execute(now + SESSION_IDLE + Duration::minutes(1))
        .await
        .unwrap();

    assert_eq!(swept.refresh_tokens, 1);
    assert_eq!(w.refresh_tokens.of(session), vec![used, head]);
    assert!(!w.refresh_tokens.of(session).contains(&abandoned));
}

#[tokio::test]
async fn an_invitation_is_swept_a_month_after_it_ended() {
    let w = world().await;
    let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
    let admin = w.an_admin().await;
    let (_, expiring) = w
        .accounts
        .issue(admin.id, now, now + INVITATION_TTL)
        .await
        .unwrap();
    let (revoked, _) = w
        .accounts
        .issue(admin.id, now, now + INVITATION_TTL)
        .await
        .unwrap();
    w.accounts.revoke(revoked, now).await.unwrap();

    let a_month_on = w
        .sweep
        .execute(now + INVITATION_RETENTION + Duration::minutes(1))
        .await
        .unwrap();
    let after_expiry = w
        .sweep
        .execute(now + INVITATION_TTL + INVITATION_RETENTION + Duration::minutes(1))
        .await
        .unwrap();

    assert_eq!((a_month_on.invitations, after_expiry.invitations), (1, 1));
    assert_eq!(
        w.accounts.find_open(&expiring, now).await.unwrap(),
        None,
        "gone"
    );
}
