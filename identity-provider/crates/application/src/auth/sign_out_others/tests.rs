use domain::UserId;
use domain::auth::testing::{another_web_app, web_client};
use domain::auth::{ClientId, RevokedReason, Sessions};
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
