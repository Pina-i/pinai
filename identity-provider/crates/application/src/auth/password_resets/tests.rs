use domain::auth::testing::{PlainHasher, StepAuthenticator, a_request, signed_up};
use domain::auth::{RevokedReason, SessionKind, Sessions, SignInAccount};
use time::Duration;

use crate::auth::world::{World, invite_only, now, world};
use crate::auth::{LoginOutcome, SecondFactorOutcome};

use super::*;

const NEW: &str = "a-new-password";

/// The world, its admin, and a link of theirs for alice.
async fn a_link_for_alice(w: &World) -> (SignInAccount, IssuedReset) {
    let admin = w.an_admin().await;
    let issued = w
        .issue_reset
        .execute(admin.id, Some(w.alice.id), now())
        .await
        .unwrap();
    (admin, issued)
}

#[tokio::test]
async fn an_admin_gets_a_link_for_a_member_open_for_a_day() {
    let w = world().await;

    let (_, issued) = a_link_for_alice(&w).await;

    assert_eq!(issued.member, w.alice.id);
    assert_eq!(issued.expires_at, now() + Duration::hours(24));
    let open = w
        .resets
        .find_open(&issued.token, now())
        .await
        .unwrap()
        .expect("open");
    assert_eq!(
        (open.member, open.display_name.as_deref()),
        (w.alice.id, Some("alice"))
    );
}

#[tokio::test]
async fn an_open_and_an_invite_only_instance_both_give_links() {
    for w in [world().await, invite_only().await] {
        let admin = w.an_admin().await;

        let issued = w
            .issue_reset
            .execute(admin.id, Some(w.alice.id), now())
            .await;

        assert!(issued.is_ok(), "{issued:?}");
    }
}

#[tokio::test]
async fn only_an_admin_gets_a_link_whatever_account_is_named() {
    let w = world().await;
    let bob = signed_up("bob");
    w.sign_up(&bob).await;

    for caller in [w.alice.id, UserId::generate()] {
        for member in [Some(bob.id), Some(UserId::generate()), None] {
            let issued = w.issue_reset.execute(caller, member, now()).await;

            assert!(matches!(issued, Err(AuthError::NotAdmin)), "{issued:?}");
        }
    }
}

#[tokio::test]
async fn no_admin_gets_a_link_not_even_for_themselves() {
    let w = world().await;
    let admin = w.an_admin().await;
    let other = SignInAccount {
        admin: true,
        ..signed_up("kahu")
    };
    w.sign_up(&other).await;

    for target in [admin.id, other.id] {
        let issued = w.issue_reset.execute(admin.id, Some(target), now()).await;

        assert!(
            matches!(issued, Err(AuthError::AdminNotResettable)),
            "{issued:?}"
        );
    }
}

#[tokio::test]
async fn an_unknown_or_unnamed_account_gets_no_link() {
    let w = world().await;
    let admin = w.an_admin().await;

    for member in [Some(UserId::generate()), None] {
        let issued = w.issue_reset.execute(admin.id, member, now()).await;

        assert!(matches!(issued, Err(AuthError::UnknownUser)), "{issued:?}");
    }
}

#[tokio::test]
async fn an_account_still_to_confirm_its_address_is_no_member_and_gets_no_link() {
    let w = world().await;
    let admin = w.an_admin().await;
    let signing_up = SignInAccount {
        email_verified: false,
        ..signed_up("bob")
    };
    w.sign_up(&signing_up).await;

    let issued = w
        .issue_reset
        .execute(admin.id, Some(signing_up.id), now())
        .await;

    assert!(matches!(issued, Err(AuthError::UnknownUser)), "{issued:?}");
}

#[tokio::test]
async fn a_new_link_replaces_the_members_open_one() {
    let w = world().await;
    let (admin, first) = a_link_for_alice(&w).await;

    let second = w
        .issue_reset
        .execute(admin.id, Some(w.alice.id), now())
        .await
        .unwrap();
    let with_first = w
        .reset_password
        .execute(&first.token, NEW, NEW, now())
        .await;

    assert!(
        matches!(with_first, Err(AuthError::ResetUnusable)),
        "{with_first:?}"
    );
    assert!(
        w.resets
            .find_open(&second.token, now())
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn a_reset_sets_the_password_and_ends_every_session_closing_their_sockets() {
    let w = world().await;
    let open =
        async |user: UserId, kind: SessionKind| w.sessions.open(user, &kind, now()).await.unwrap();
    let browser = open(w.alice.id, SessionKind::Browser).await;
    let desktop = open(w.alice.id, SessionKind::App(w.desktop.id.clone())).await;
    let (admin, issued) = a_link_for_alice(&w).await;
    let admins = open(admin.id, SessionKind::Browser).await;
    let at = now() + Duration::hours(1);

    let member = w
        .reset_password
        .execute(&issued.token, NEW, NEW, at)
        .await
        .unwrap();

    assert_eq!(member, w.alice.id);
    assert_eq!(
        w.accounts
            .by_id(w.alice.id)
            .await
            .unwrap()
            .unwrap()
            .password_hash,
        PlainHasher::hash(NEW)
    );
    for ended in [browser, desktop] {
        assert_eq!(w.sessions.reason(ended), Some(RevokedReason::PasswordReset));
    }
    let mut closed = w.ended.ended();
    closed.sort();
    let mut theirs = vec![browser, desktop];
    theirs.sort();
    assert_eq!(closed, theirs, "their sockets close");
    assert!(w.sessions.find(admins).await.unwrap().unwrap().is_live(at));
}

#[tokio::test]
async fn the_old_password_stops_signing_in_and_the_new_one_does() {
    let w = world().await;
    let (_, issued) = a_link_for_alice(&w).await;

    w.reset_password
        .execute(&issued.token, NEW, NEW, now())
        .await
        .unwrap();
    let old = w
        .log_in
        .execute(&w.alice.email, "alice-password", &a_request(), None, now())
        .await
        .unwrap();
    let new = w
        .log_in
        .execute(&w.alice.email, NEW, &a_request(), None, now())
        .await
        .unwrap();

    assert_eq!(old, LoginOutcome::Refused);
    assert!(matches!(new, LoginOutcome::SignedIn { .. }), "{new:?}");
}

#[tokio::test]
async fn a_member_with_an_authenticator_still_needs_it_after_a_reset() {
    let w = world().await;
    w.with_authenticator(&w.alice).await;
    let (_, issued) = a_link_for_alice(&w).await;

    w.reset_password
        .execute(&issued.token, NEW, NEW, now())
        .await
        .unwrap();
    let signed_in = w
        .log_in
        .execute(&w.alice.email, NEW, &a_request(), None, now())
        .await
        .unwrap();

    assert!(
        matches!(signed_in, LoginOutcome::SecondFactor(_)),
        "{signed_in:?}"
    );
    assert!(w.factors.state_of(w.alice.id).0, "still on");
}

#[tokio::test]
async fn a_sign_in_half_done_with_the_old_password_cannot_finish_after_a_reset() {
    let w = world().await;
    let (secret, _) = w.with_authenticator(&w.alice).await;
    let LoginOutcome::SecondFactor(ticket) = w
        .log_in
        .execute(&w.alice.email, "alice-password", &a_request(), None, now())
        .await
        .unwrap()
    else {
        panic!("the authenticator's code is asked");
    };
    let (_, issued) = a_link_for_alice(&w).await;

    w.reset_password
        .execute(&issued.token, NEW, NEW, now())
        .await
        .unwrap();
    let finished = w
        .pass
        .execute(
            ticket,
            Some(&StepAuthenticator::code_at(&secret, now())),
            None,
            None,
            now(),
        )
        .await
        .unwrap();

    assert_eq!(finished, SecondFactorOutcome::Expired);
}

#[tokio::test]
async fn a_short_or_mismatched_password_changes_nothing() {
    let w = world().await;
    let session = w
        .sessions
        .open(w.alice.id, &SessionKind::Browser, now())
        .await
        .unwrap();
    let (_, issued) = a_link_for_alice(&w).await;

    let short = w
        .reset_password
        .execute(&issued.token, "short", "short", now())
        .await;
    let mismatched = w
        .reset_password
        .execute(&issued.token, NEW, "a-new-passwrod", now())
        .await;

    assert!(
        matches!(short, Err(AuthError::PasswordTooShort)),
        "{short:?}"
    );
    assert!(
        matches!(mismatched, Err(AuthError::PasswordMismatch)),
        "{mismatched:?}"
    );
    assert_eq!(
        w.accounts
            .by_id(w.alice.id)
            .await
            .unwrap()
            .unwrap()
            .password_hash,
        w.alice.password_hash
    );
    assert!(
        w.resets
            .find_open(&issued.token, now())
            .await
            .unwrap()
            .is_some(),
        "still open"
    );
    assert!(
        w.sessions
            .find(session)
            .await
            .unwrap()
            .unwrap()
            .is_live(now())
    );
    assert!(w.ended.ended().is_empty());
}

#[tokio::test]
async fn a_spent_or_expired_link_sets_no_password() {
    let w = world().await;
    let (admin, issued) = a_link_for_alice(&w).await;
    let bob = signed_up("bob");
    w.sign_up(&bob).await;
    let bobs = w
        .issue_reset
        .execute(admin.id, Some(bob.id), now())
        .await
        .unwrap();

    w.reset_password
        .execute(&issued.token, NEW, NEW, now())
        .await
        .unwrap();
    let again = w
        .reset_password
        .execute(&issued.token, "another-password", "another-password", now())
        .await;
    let expired = w
        .reset_password
        .execute(&bobs.token, NEW, NEW, bobs.expires_at)
        .await;

    assert!(matches!(again, Err(AuthError::ResetUnusable)), "{again:?}");
    assert!(
        matches!(expired, Err(AuthError::ResetUnusable)),
        "{expired:?}"
    );
    assert_eq!(
        w.accounts
            .by_id(w.alice.id)
            .await
            .unwrap()
            .unwrap()
            .password_hash,
        PlainHasher::hash(NEW),
        "set once"
    );
    assert_eq!(
        w.accounts
            .by_id(bob.id)
            .await
            .unwrap()
            .unwrap()
            .password_hash,
        bob.password_hash
    );
}

#[tokio::test]
async fn the_web_app_is_where_the_member_signs_in_again() {
    let w = world().await;

    assert_eq!(
        w.reset_password.web_app_entry().as_deref(),
        Some("http://localhost:5173/?instance=localhost%3A8080")
    );
}
