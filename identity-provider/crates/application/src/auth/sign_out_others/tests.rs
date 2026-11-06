use domain::UserId;
use domain::auth::testing::{another_web_app, web_client};
use domain::auth::{AuthError, ClientId, RevokedReason, Sessions};
use domain::identity::Bearer;

use crate::auth::world::{now, world};

#[tokio::test]
async fn every_other_session_of_the_account_ends_and_this_browser_stays_whole() {
    let w = world().await;
    let browser = async |user: UserId| w.sessions.open_browser(user, now()).await.unwrap();
    let under = async |browser, client: &ClientId| {
        w.sessions
            .open_under(browser, client, now())
            .await
            .unwrap()
            .unwrap()
            .id
    };
    let here = browser(w.alice.id).await;
    let current = under(here, &web_client().id).await;
    let beside = under(here, &another_web_app().id).await;
    let other_browser = browser(w.alice.id).await;
    let there = under(other_browser, &web_client().id).await;
    let (window, desktop) = w.on_the_desktop(w.alice.id).await;
    let bobs = browser(UserId::generate()).await;

    let ended = w
        .sign_out_others
        .execute(
            Bearer {
                user: w.alice.id,
                session: current,
                authenticated_at: now(),
            },
            now(),
        )
        .await
        .unwrap();

    let gone = [other_browser, there, window, desktop];
    assert_eq!(ended, gone.len());
    for gone in gone {
        assert_eq!(
            w.sessions.reason(gone),
            Some(RevokedReason::SignedOutElsewhere),
            "{gone}"
        );
    }
    assert_eq!(w.ended.ended(), gone.to_vec(), "their sockets close");
    for kept in [here, current, beside, bobs] {
        assert!(
            w.sessions.find(kept).await.unwrap().unwrap().is_live(now()),
            "{kept}: its cookie would sign it in again anyway"
        );
    }
}

#[tokio::test]
async fn signing_out_elsewhere_from_the_desktop_keeps_its_own_session_only() {
    let w = world().await;
    let web = w.sessions.live_at(w.alice.id, now());
    let (window, desktop) = w.on_the_desktop(w.alice.id).await;

    let ended = w
        .sign_out_others
        .execute(
            Bearer {
                user: w.alice.id,
                session: desktop,
                authenticated_at: now(),
            },
            now(),
        )
        .await
        .unwrap();

    assert_eq!(ended, 3, "the web app, its browser, the desktop's window");
    for gone in [web, window] {
        assert_eq!(
            w.sessions.reason(gone),
            Some(RevokedReason::SignedOutElsewhere)
        );
    }
    assert!(
        w.sessions
            .find(desktop)
            .await
            .unwrap()
            .unwrap()
            .is_live(now())
    );
}

#[tokio::test]
async fn only_an_approved_device_signs_the_others_out_once_the_account_has_a_key() {
    let w = world().await;
    let (laptop, on_the_laptop) = w.on_a_device().await;
    let (_, on_a_fresh_one) = w.on_a_device().await;
    w.keyed_from(laptop).await;
    let unnamed = w.bearer_of(w.alice.id);

    let by_the_fresh_one = w.sign_out_others.execute(on_a_fresh_one, now()).await;
    let unnamed_signs_out = w.sign_out_others.execute(unnamed, now()).await;
    let nobody_signed_out = w.ended.ended();
    let by_the_laptop = w.sign_out_others.execute(on_the_laptop, now()).await;

    for refused in [by_the_fresh_one, unnamed_signs_out] {
        assert!(
            matches!(refused, Err(AuthError::ApprovalRequired(_))),
            "{refused:?}"
        );
    }
    assert_eq!(nobody_signed_out, Vec::new());
    assert_eq!(
        by_the_laptop.unwrap(),
        4,
        "the fresh device's and the unnamed web apps, with their browsers"
    );
    for gone in [on_a_fresh_one.session, unnamed.session] {
        assert_eq!(
            w.sessions.reason(gone),
            Some(RevokedReason::SignedOutElsewhere)
        );
    }
}

#[tokio::test]
async fn without_a_history_key_a_device_nobody_approved_signs_the_others_out() {
    let w = world().await;
    let (_, on_a_device) = w.on_a_device().await;
    let other = w.bearer_of(w.alice.id);

    let ended = w.sign_out_others.execute(on_a_device, now()).await;

    assert_eq!(ended.unwrap(), 2, "the other web app and its browser");
    assert_eq!(
        w.sessions.reason(other.session),
        Some(RevokedReason::SignedOutElsewhere)
    );
}
