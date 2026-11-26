//! The push registrations in memory, and the contract every store of them must satisfy.

use super::*;
use crate::e2ee::{
    Delivery, KeyDirectoryError, PushNotice, PushRegistrations, PushRelays, PushToken, PushWrite,
    may_register_push,
};

#[async_trait::async_trait]
impl PushRegistrations for InMemoryKeyDirectory {
    async fn set(
        &self,
        owner: UserId,
        id: DeviceId,
        named: Option<DeviceId>,
        registration: &PushRegistration,
        _now: OffsetDateTime,
    ) -> Result<PushWrite, KeyStoreError> {
        let mut state = self.state.lock().unwrap();
        let device = state.devices.iter().find(|device| device.id == id);
        if let Err(refusal) = may_register_push(named, owner, id, device) {
            return Ok(PushWrite::Refused(refusal));
        }
        state.pushes.retain(|(_, of, _)| *of != id);
        state.pushes.push((owner, id, registration.clone()));
        Ok(PushWrite::Done)
    }

    async fn remove(
        &self,
        owner: UserId,
        id: DeviceId,
        named: Option<DeviceId>,
    ) -> Result<PushWrite, KeyStoreError> {
        let mut state = self.state.lock().unwrap();
        let device = state.devices.iter().find(|device| device.id == id);
        if let Err(refusal) = may_register_push(named, owner, id, device) {
            return Ok(PushWrite::Refused(refusal));
        }
        state.pushes.retain(|(_, of, _)| *of != id);
        Ok(PushWrite::Done)
    }

    async fn held(
        &self,
        owner: UserId,
    ) -> Result<Vec<(DeviceId, PushRegistration)>, KeyStoreError> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .pushes
            .iter()
            .filter(|(of, _, _)| *of == owner)
            .map(|(_, id, registration)| (*id, registration.clone()))
            .collect())
    }

    async fn forget(
        &self,
        owner: UserId,
        id: DeviceId,
        token: &PushToken,
    ) -> Result<(), KeyStoreError> {
        self.state
            .lock()
            .unwrap()
            .pushes
            .retain(|(of, device, held)| !(*of == owner && *device == id && held.token == *token));
        Ok(())
    }
}

/// Sends nothing: records each notice, and answers [`Delivery::Gone`] for the tokens it is told
/// to.
#[derive(Default)]
pub struct RecordingPushRelays {
    pub sent: Mutex<Vec<(PushRegistration, PushNotice)>>,
    gone: Mutex<Vec<PushToken>>,
}

impl RecordingPushRelays {
    pub fn no_longer_reaching(&self, token: &PushToken) {
        self.gone.lock().unwrap().push(token.clone());
    }

    pub fn tokens_sent(&self) -> Vec<(String, PushNotice)> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .map(|(to, notice)| (to.token.as_str().to_owned(), *notice))
            .collect()
    }
}

#[async_trait::async_trait]
impl PushRelays for RecordingPushRelays {
    async fn send(&self, to: &PushRegistration, notice: PushNotice) -> anyhow::Result<Delivery> {
        self.sent.lock().unwrap().push((to.clone(), notice));
        Ok(if self.gone.lock().unwrap().contains(&to.token) {
            Delivery::Gone
        } else {
            Delivery::Sent
        })
    }
}

pub mod contract {
    use time::Duration;

    use super::super::contract::{at, attestation, register};
    use super::*;
    use crate::e2ee::{DeviceRequired, PushRelay, PushToken};

    async fn a_device(devices: &dyn Devices, owner: UserId, key: u8) -> DeviceId {
        let id = DeviceId::generate();
        register(devices, owner, id, &attestation(key), HpkeKeyWrite::Clear).await;
        id
    }

    fn registration(token: &str) -> PushRegistration {
        PushRegistration {
            relay: PushRelay::parse("https://exp.host/--/api/v2/push/send").unwrap(),
            token: PushToken::parse(token).unwrap(),
        }
    }

    async fn set(
        pushes: &dyn PushRegistrations,
        owner: UserId,
        id: DeviceId,
        named: Option<DeviceId>,
        token: &str,
    ) -> PushWrite {
        pushes
            .set(owner, id, named, &registration(token), at(Duration::ZERO))
            .await
            .unwrap()
    }

    pub async fn a_device_keeps_the_last_push_registration_its_session_set(
        devices: &dyn Devices,
        pushes: &dyn PushRegistrations,
        alice: UserId,
    ) {
        let (phone, laptop) = (
            a_device(devices, alice, 1).await,
            a_device(devices, alice, 2).await,
        );

        let first = set(
            pushes,
            alice,
            phone,
            Some(phone),
            "ExponentPushToken[first]",
        )
        .await;
        let again = set(
            pushes,
            alice,
            phone,
            Some(phone),
            "ExponentPushToken[again]",
        )
        .await;
        let other = set(
            pushes,
            alice,
            laptop,
            Some(laptop),
            "ExponentPushToken[laptop]",
        )
        .await;

        for write in [first, again, other] {
            assert!(matches!(write, PushWrite::Done), "{write:?}");
        }
        let mut held = pushes.held(alice).await.unwrap();
        held.sort_by_key(|(id, _)| *id != phone);
        assert_eq!(
            held,
            vec![
                (phone, registration("ExponentPushToken[again]")),
                (laptop, registration("ExponentPushToken[laptop]")),
            ]
        );
        assert!(pushes.held(UserId::generate()).await.unwrap().is_empty());
    }

    pub async fn a_device_removes_its_push_registration(
        devices: &dyn Devices,
        pushes: &dyn PushRegistrations,
        alice: UserId,
    ) {
        let phone = a_device(devices, alice, 1).await;
        set(
            pushes,
            alice,
            phone,
            Some(phone),
            "ExponentPushToken[phone]",
        )
        .await;

        let removed = pushes.remove(alice, phone, Some(phone)).await.unwrap();
        let again = pushes.remove(alice, phone, Some(phone)).await.unwrap();

        for write in [removed, again] {
            assert!(matches!(write, PushWrite::Done), "{write:?}");
        }
        assert!(pushes.held(alice).await.unwrap().is_empty());
    }

    pub async fn only_a_devices_own_session_writes_its_push_registration(
        devices: &dyn Devices,
        pushes: &dyn PushRegistrations,
        alice: UserId,
        bob: UserId,
    ) {
        let (phone, laptop, bobs) = (
            a_device(devices, alice, 1).await,
            a_device(devices, alice, 2).await,
            a_device(devices, bob, 3).await,
        );
        set(pushes, alice, phone, Some(phone), "ExponentPushToken[kept]").await;

        let unnamed = set(pushes, alice, phone, None, "ExponentPushToken[unnamed]").await;
        let anothers = set(
            pushes,
            alice,
            phone,
            Some(laptop),
            "ExponentPushToken[laptop]",
        )
        .await;
        let not_hers = set(pushes, alice, bobs, Some(bobs), "ExponentPushToken[bob]").await;
        let removed_by_another = pushes.remove(alice, phone, Some(laptop)).await.unwrap();

        assert!(
            matches!(
                unnamed,
                PushWrite::Refused(KeyDirectoryError::DeviceRequired(DeviceRequired))
            ),
            "{unnamed:?}"
        );
        for refused in [anothers, removed_by_another] {
            assert!(
                matches!(
                    refused,
                    PushWrite::Refused(KeyDirectoryError::NotTheSessionsDevice)
                ),
                "{refused:?}"
            );
        }
        assert!(
            matches!(
                not_hers,
                PushWrite::Refused(KeyDirectoryError::DeviceNotFound)
            ),
            "{not_hers:?}"
        );
        assert_eq!(
            pushes.held(alice).await.unwrap(),
            vec![(phone, registration("ExponentPushToken[kept]"))]
        );
        assert!(pushes.held(bob).await.unwrap().is_empty());
    }

    pub async fn a_registration_is_forgotten_only_while_it_holds_the_token_gone(
        devices: &dyn Devices,
        pushes: &dyn PushRegistrations,
        alice: UserId,
    ) {
        let phone = a_device(devices, alice, 1).await;
        set(pushes, alice, phone, Some(phone), "ExponentPushToken[old]").await;
        set(pushes, alice, phone, Some(phone), "ExponentPushToken[new]").await;

        let old = PushToken::parse("ExponentPushToken[old]").unwrap();
        pushes.forget(alice, phone, &old).await.unwrap();
        let kept = pushes.held(alice).await.unwrap();
        let new = PushToken::parse("ExponentPushToken[new]").unwrap();
        pushes.forget(alice, phone, &new).await.unwrap();

        assert_eq!(kept, vec![(phone, registration("ExponentPushToken[new]"))]);
        assert!(pushes.held(alice).await.unwrap().is_empty());
    }

    pub async fn a_revoked_device_holds_no_push_registration(
        devices: &dyn Devices,
        pushes: &dyn PushRegistrations,
        alice: UserId,
    ) {
        let phone = a_device(devices, alice, 1).await;
        set(
            pushes,
            alice,
            phone,
            Some(phone),
            "ExponentPushToken[phone]",
        )
        .await;

        devices
            .revoke(alice, phone, Some(phone), at(Duration::minutes(1)))
            .await
            .unwrap();
        let after = set(
            pushes,
            alice,
            phone,
            Some(phone),
            "ExponentPushToken[after]",
        )
        .await;

        assert!(
            matches!(after, PushWrite::Refused(KeyDirectoryError::DeviceRevoked)),
            "{after:?}"
        );
        assert!(pushes.held(alice).await.unwrap().is_empty());
    }
}
