use domain::auth::{RevokedReason, SessionKind, Sessions};
use domain::e2ee::{DeviceKind, DeviceLabel, Devices, KeyPackages};
use domain::identity::Bearer;
use domain::{DeviceId, SessionId, UserId};

use crate::auth::world::{World, now, world};

use super::*;

async fn device_of(w: &World, owner: UserId) -> DeviceId {
    let device = DeviceId::generate();
    let label = DeviceLabel {
        name: "Firefox on Linux".to_owned(),
        kind: DeviceKind::Laptop,
    };
    w.devices.stash(owner, device, &label, &[]).await.unwrap();
    device
}

async fn signed_in(w: &World, user: UserId) -> SessionId {
    w.sessions
        .open(user, &SessionKind::Browser, now())
        .await
        .unwrap()
}

#[tokio::test]
async fn a_session_links_its_device_and_takes_it_over_from_the_one_before() {
    let w = world().await;
    let device = device_of(&w, w.alice.id).await;
    let (before, after) = (
        signed_in(&w, w.alice.id).await,
        signed_in(&w, w.alice.id).await,
    );
    let bearer = |session| Bearer {
        user: w.alice.id,
        session,
    };

    w.link.execute(bearer(before), device, now()).await.unwrap();
    w.link.execute(bearer(after), device, now()).await.unwrap();

    assert_eq!(w.sessions.reason(before), Some(RevokedReason::Replaced));
    assert_eq!(w.ended.ended(), vec![before], "its sockets close");
    let linked = w.sessions.find(after).await.unwrap().unwrap();
    assert_eq!((linked.device, linked.is_live(now())), (Some(device), true));
}

#[tokio::test]
async fn a_device_that_isnt_the_accounts_or_was_revoked_is_refused() {
    let w = world().await;
    let bob = UserId::generate();
    let bobs = device_of(&w, bob).await;
    let revoked = device_of(&w, w.alice.id).await;
    w.devices.revoke(w.alice.id, revoked).await.unwrap();
    let session = signed_in(&w, w.alice.id).await;

    for device in [bobs, revoked, DeviceId::generate()] {
        let refused = w
            .link
            .execute(
                Bearer {
                    user: w.alice.id,
                    session,
                },
                device,
                now(),
            )
            .await;

        assert!(
            matches!(refused, Err(AuthError::DeviceRefused)),
            "{device:?}: {refused:?}"
        );
    }
    assert_eq!(
        w.sessions.find(session).await.unwrap().unwrap().device,
        None
    );
}
