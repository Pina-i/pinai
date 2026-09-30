use domain::auth::testing::{StepAuthenticator, a_request, signed_up};
use domain::auth::{LOGIN_TICKET_TTL, LoginTickets, SignInAccount};

use crate::auth::world::{World, now, world};

use super::*;

/// Bob, whose second factor is on, past his password: his ticket and his app's secret.
async fn at_the_second_step(w: &World) -> (SignInAccount, TicketId, Vec<String>) {
    let bob = SignInAccount {
        totp_enabled: true,
        ..signed_up("bob")
    };
    w.sign_up(&bob).await;
    let (_, recovery) = w.with_authenticator(&bob).await;
    let ticket = w
        .tickets
        .open(bob.id, &a_request(), now() + LOGIN_TICKET_TTL)
        .await
        .unwrap();
    (bob, ticket, recovery)
}

/// What Bob's app shows now: `with_authenticator` gives every account the same secret.
fn app_code() -> String {
    let secret = domain::auth::TotpSecret::parse(vec![7; domain::auth::TotpSecret::LEN]).unwrap();
    StepAuthenticator::code_at(&secret, now())
}

#[tokio::test]
async fn the_apps_code_ends_the_sign_in_with_a_code_for_the_request() {
    let w = world().await;
    let (bob, ticket, _) = at_the_second_step(&w).await;

    let outcome = w
        .pass
        .execute(ticket, Some(&app_code()), None, now())
        .await
        .unwrap();

    let issued = w.codes.issued();
    assert_eq!(
        outcome,
        SecondFactorOutcome::SignedIn {
            user: bob.id,
            request: a_request(),
            code: issued[0].0.clone(),
        }
    );
    assert_eq!(issued[0].1, Grant::answering(bob.id, &a_request()));
    assert_eq!(w.tickets.find(ticket, now()).await.unwrap(), None);
}

#[tokio::test]
async fn a_recovery_code_does_too_once() {
    let w = world().await;
    let (bob, ticket, recovery) = at_the_second_step(&w).await;

    let first = w
        .pass
        .execute(ticket, None, Some(&recovery[0]), now())
        .await
        .unwrap();
    let again_ticket = w
        .tickets
        .open(bob.id, &a_request(), now() + LOGIN_TICKET_TTL)
        .await
        .unwrap();
    let again = w
        .pass
        .execute(again_ticket, Some(""), Some(&recovery[0]), now())
        .await
        .unwrap();

    assert!(
        matches!(first, SecondFactorOutcome::SignedIn { .. }),
        "{first:?}"
    );
    assert_eq!(again, SecondFactorOutcome::UnknownRecoveryCode);
}

#[tokio::test]
async fn wrong_codes_are_counted_and_the_fifth_closes_the_ticket() {
    let w = world().await;
    let (_, ticket, _) = at_the_second_step(&w).await;
    let right = app_code();
    let wrong = if right == "000000" {
        "111111"
    } else {
        "000000"
    };

    let mut answers = Vec::new();
    for _ in 0..TICKET_ATTEMPTS {
        answers.push(
            w.pass
                .execute(ticket, Some(wrong), None, now())
                .await
                .unwrap(),
        );
    }
    let too_late = w
        .pass
        .execute(ticket, Some(&right), None, now())
        .await
        .unwrap();

    assert_eq!(answers, vec![SecondFactorOutcome::WrongCode; 5]);
    assert_eq!(too_late, SecondFactorOutcome::TooManyAttempts);
}

#[tokio::test]
async fn an_expired_or_unknown_ticket_starts_over_and_nothing_sent_is_not_counted() {
    let w = world().await;
    let (_, ticket, _) = at_the_second_step(&w).await;

    let nothing = w
        .pass
        .execute(ticket, Some(""), Some(""), now())
        .await
        .unwrap();
    let expired = w
        .pass
        .execute(ticket, Some(&app_code()), None, now() + LOGIN_TICKET_TTL)
        .await
        .unwrap();
    let unknown = w
        .pass
        .execute(TicketId::generate(), Some(&app_code()), None, now())
        .await
        .unwrap();

    assert_eq!(nothing, SecondFactorOutcome::Missing);
    assert_eq!(
        w.tickets
            .find(ticket, now())
            .await
            .unwrap()
            .unwrap()
            .attempts,
        0
    );
    assert_eq!(
        (expired, unknown),
        (SecondFactorOutcome::Expired, SecondFactorOutcome::Expired)
    );
}

#[tokio::test]
async fn a_code_used_once_is_refused_the_second_time_within_its_window() {
    let w = world().await;
    let (bob, ticket, _) = at_the_second_step(&w).await;
    let code = app_code();

    let first = w
        .pass
        .execute(ticket, Some(&code), None, now())
        .await
        .unwrap();
    let again_ticket = w
        .tickets
        .open(bob.id, &a_request(), now() + LOGIN_TICKET_TTL)
        .await
        .unwrap();
    let replayed = w
        .pass
        .execute(again_ticket, Some(&code), None, now())
        .await
        .unwrap();
    let to_disable = w.disable.execute(bob.id, &code, now()).await;

    assert!(
        matches!(first, SecondFactorOutcome::SignedIn { .. }),
        "{first:?}"
    );
    assert_eq!(replayed, SecondFactorOutcome::WrongCode);
    assert!(
        matches!(to_disable, Err(AuthError::WrongCode)),
        "{to_disable:?}"
    );
}

#[tokio::test]
async fn the_right_code_on_the_fifth_attempt_still_signs_in() {
    let w = world().await;
    let (_, ticket, _) = at_the_second_step(&w).await;
    let right = app_code();
    let wrong = if right == "000000" {
        "111111"
    } else {
        "000000"
    };

    for _ in 1..TICKET_ATTEMPTS {
        w.pass
            .execute(ticket, Some(wrong), None, now())
            .await
            .unwrap();
    }
    let fifth = w
        .pass
        .execute(ticket, Some(&right), None, now())
        .await
        .unwrap();

    assert!(
        matches!(fifth, SecondFactorOutcome::SignedIn { .. }),
        "{fifth:?}"
    );
}
