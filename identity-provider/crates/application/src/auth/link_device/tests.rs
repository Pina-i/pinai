use domain::auth::{RevokedReason, Sessions, naming_bytes};
use domain::e2ee::testing::plain_signature;
use domain::e2ee::{
    Attestation, DeviceKind, DeviceLabel, DeviceRootKey, Devices, Ed25519Signature, HpkeKeyWrite,
    KeyPackages,
};
use domain::identity::Bearer;
use domain::{DeviceId, SessionId, UserId};

use crate::auth::world::{World, now, world};

use super::*;

fn root() -> DeviceRootKey {
    DeviceRootKey::parse(&[9; 32]).unwrap()
}

/// A device of `owner`'s, its root key registered.
async fn device_of(w: &World, owner: UserId) -> DeviceId {
    let device = DeviceId::generate();
    let label = DeviceLabel {
        name: "Firefox on Linux".to_owned(),
        kind: DeviceKind::Laptop,
    };
    let attestation = Attestation {
        root_key: root(),
        signature: vec![1; 64],
        kid: "key-1".to_owned(),
        issued_at: now(),
        expires_at: now() + time::Duration::days(365),
    };
    w.devices
        .attest(
            owner,
            device,
            &label,
            None,
            &attestation,
            &HpkeKeyWrite::Clear,
        )
        .await
        .unwrap();
    device
}

/// What a client holding `device`'s root key signs to name it on `bearer`'s session.
fn proof(w: &World, bearer: Bearer, device: DeviceId) -> Option<Ed25519Signature> {
    Some(plain_signature(
        &root(),
        &naming_bytes(&w.actor, device, bearer.session),
    ))
}

async fn signed_in(w: &World, user: UserId) -> SessionId {
    w.sessions.live_at(user, now())
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
        authenticated_at: now(),
    };

    w.link
        .execute(
            bearer(before),
            device,
            proof(&w, bearer(before), device),
            now(),
        )
        .await
        .unwrap();
    w.link
        .execute(
            bearer(after),
            device,
            proof(&w, bearer(after), device),
            now(),
        )
        .await
        .unwrap();

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
    w.devices
        .revoke(
            w.alice.id,
            revoked,
            Some(revoked),
            time::OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
    let session = signed_in(&w, w.alice.id).await;

    for device in [bobs, revoked, DeviceId::generate()] {
        let refused = w
            .link
            .execute(
                Bearer {
                    user: w.alice.id,
                    session,
                    authenticated_at: now(),
                },
                device,
                proof(
                    &w,
                    Bearer {
                        user: w.alice.id,
                        session,
                        authenticated_at: now(),
                    },
                    device,
                ),
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

#[tokio::test]
async fn a_session_that_named_its_device_names_it_again_but_no_other() {
    let w = world().await;
    let (laptop, phone) = (
        device_of(&w, w.alice.id).await,
        device_of(&w, w.alice.id).await,
    );
    let (on_the_laptop, on_the_phone) = (
        signed_in(&w, w.alice.id).await,
        signed_in(&w, w.alice.id).await,
    );
    let bearer = |session| Bearer {
        user: w.alice.id,
        session,
        authenticated_at: now(),
    };
    w.link
        .execute(
            bearer(on_the_laptop),
            laptop,
            proof(&w, bearer(on_the_laptop), laptop),
            now(),
        )
        .await
        .unwrap();
    w.link
        .execute(
            bearer(on_the_phone),
            phone,
            proof(&w, bearer(on_the_phone), phone),
            now(),
        )
        .await
        .unwrap();

    let again = w
        .link
        .execute(
            bearer(on_the_laptop),
            laptop,
            proof(&w, bearer(on_the_laptop), laptop),
            now(),
        )
        .await;
    let elsewhere = w
        .link
        .execute(
            bearer(on_the_laptop),
            phone,
            proof(&w, bearer(on_the_laptop), phone),
            now(),
        )
        .await;

    assert!(again.is_ok(), "{again:?}");
    assert!(
        matches!(elsewhere, Err(AuthError::DeviceMismatch)),
        "{elsewhere:?}"
    );
    assert_eq!(
        w.sessions
            .find(on_the_laptop)
            .await
            .unwrap()
            .unwrap()
            .device,
        Some(laptop)
    );
    assert!(
        w.sessions
            .find(on_the_phone)
            .await
            .unwrap()
            .unwrap()
            .is_live(now()),
        "the phone keeps its session"
    );
}

#[tokio::test]
async fn a_session_gone_since_its_token_was_checked_is_unexpected_and_takes_no_device_over() {
    let w = world().await;
    let device = device_of(&w, w.alice.id).await;
    let current = signed_in(&w, w.alice.id).await;
    let bearer = |session| Bearer {
        user: w.alice.id,
        session,
        authenticated_at: now(),
    };
    w.link
        .execute(
            bearer(current),
            device,
            proof(&w, bearer(current), device),
            now(),
        )
        .await
        .unwrap();

    let unknown = bearer(SessionId::generate());
    let gone = w
        .link
        .execute(unknown, device, proof(&w, unknown, device), now())
        .await;

    assert!(matches!(gone, Err(AuthError::Unexpected(_))), "{gone:?}");
    assert!(
        w.sessions
            .find(current)
            .await
            .unwrap()
            .unwrap()
            .is_live(now()),
        "the device keeps its session"
    );
    assert!(w.ended.ended().is_empty());
}

#[tokio::test]
async fn a_session_ended_since_its_token_was_checked_names_no_device() {
    let w = world().await;
    let device = device_of(&w, w.alice.id).await;
    let session = signed_in(&w, w.alice.id).await;
    w.sessions
        .revoke(session, RevokedReason::SignOut, now())
        .await
        .unwrap();

    let refused = w
        .link
        .execute(
            Bearer {
                user: w.alice.id,
                session,
                authenticated_at: now(),
            },
            device,
            proof(
                &w,
                Bearer {
                    user: w.alice.id,
                    session,
                    authenticated_at: now(),
                },
                device,
            ),
            now(),
        )
        .await;

    assert!(
        matches!(refused, Err(AuthError::SessionEnded)),
        "{refused:?}"
    );
    assert_eq!(
        w.sessions.find(session).await.unwrap().unwrap().device,
        None
    );
}

#[tokio::test]
async fn a_naming_without_the_devices_proof_is_refused_and_the_device_keeps_its_session() {
    let w = world().await;
    let laptop = device_of(&w, w.alice.id).await;
    let (on_the_laptop, thiefs) = (w.bearer_of(w.alice.id), w.bearer_of(w.alice.id));
    w.link
        .execute(
            on_the_laptop,
            laptop,
            proof(&w, on_the_laptop, laptop),
            now(),
        )
        .await
        .unwrap();
    let lifted = proof(&w, on_the_laptop, laptop);
    let forged = Some(Ed25519Signature::parse("signature", &[1; 64]).unwrap());

    for proof in [None, lifted, forged] {
        let refused = w.link.execute(thiefs, laptop, proof.clone(), now()).await;

        assert!(
            matches!(refused, Err(AuthError::DeviceProofInvalid)),
            "{proof:?}: {refused:?}"
        );
    }
    let laptops = w
        .sessions
        .find(on_the_laptop.session)
        .await
        .unwrap()
        .unwrap();
    assert!(laptops.is_live(now()), "the laptop stays signed in");
    assert_eq!(laptops.device, Some(laptop));
    let thiefs = w.sessions.find(thiefs.session).await.unwrap().unwrap();
    assert_eq!(thiefs.device, None);
    assert!(w.ended.ended().is_empty());
}

#[tokio::test]
async fn a_device_with_no_root_key_is_named_by_no_session() {
    let w = world().await;
    let device = DeviceId::generate();
    w.devices
        .stash(w.alice.id, device, &DeviceLabel::unknown(), false, &[])
        .await
        .unwrap();
    let bearer = w.bearer_of(w.alice.id);

    let refused = w
        .link
        .execute(bearer, device, proof(&w, bearer, device), now())
        .await;

    assert!(
        matches!(refused, Err(AuthError::DeviceProofInvalid)),
        "{refused:?}"
    );
}
