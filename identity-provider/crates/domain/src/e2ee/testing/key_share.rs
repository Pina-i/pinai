//! The key shares in memory, and the contract every store of them must satisfy.

use crate::e2ee::{
    CheckedShare, Deposit, KeyShare, KeyShares, SealedShare, ShareCiphertext, ShareEnc, share_aad,
    share_signed_bytes,
};

use super::*;

#[async_trait::async_trait]
impl KeyShares for InMemoryKeyDirectory {
    async fn deposit(&self, owner: UserId, share: &CheckedShare) -> Result<Deposit, KeyStoreError> {
        let generation = share.generation();
        let current = self
            .history
            .as_ref()
            .and_then(|history| history.state.lock().unwrap().generation(owner));
        if check_history_generation(generation, current).is_err() {
            return Ok(Deposit::Stale);
        }
        let state = self.state.lock().unwrap();
        let unrevoked = |id: DeviceId| {
            state
                .devices
                .iter()
                .find(|device| device.id == id && device.owner == owner && !device.is_revoked())
        };
        fn root(device: &Device) -> Option<&DeviceRootKey> {
            device.attestation.as_ref().map(|held| &held.root_key)
        }
        let sender_holds = unrevoked(share.sender()).is_some_and(|device| {
            root(device) == Some(share.sender_key())
                && device.history_generation == Some(generation)
        });
        let recipient_holds = unrevoked(share.recipient()).is_some_and(|device| {
            root(device) == Some(share.recipient_key())
                && device.hpke_key.as_ref().map(|held| &held.key)
                    == Some(share.recipient_hpke_key())
                && device.history_generation != Some(generation)
        });
        let approvals = self.approvals.lock().unwrap();
        let still_approved = share.relied_on().iter().all(|relied| {
            approvals.iter().any(|(of, held)| {
                *of == owner
                    && held.device == relied.device
                    && held.approver == relied.approver
                    && held.root_key == relied.root_key
            })
        });
        if !(sender_holds && recipient_holds && still_approved) {
            return Ok(Deposit::Stale);
        }
        let mut shares = self.shares.lock().unwrap();
        if shares
            .iter()
            .any(|(_, held)| held.recipient == share.recipient() && held.generation == generation)
        {
            return Ok(Deposit::AlreadyHeld);
        }
        shares.push((
            owner,
            KeyShare {
                sender: share.sender(),
                recipient: share.recipient(),
                generation,
                sealed: share.sealed().clone(),
                created_at: OffsetDateTime::now_utc(),
            },
        ));
        Ok(Deposit::Stored)
    }

    async fn of_recipient(
        &self,
        owner: UserId,
        recipient: DeviceId,
        generation: HistoryGeneration,
    ) -> Result<Option<KeyShare>, KeyStoreError> {
        Ok(self
            .shares
            .lock()
            .unwrap()
            .iter()
            .find(|(of, share)| {
                *of == owner && share.recipient == recipient && share.generation == generation
            })
            .map(|(_, share)| share.clone()))
    }
}

/// `sender`'s share of `generation` for `recipient`, an account of `actor`'s, its seal made of
/// `byte`s and signed by `root` as [`PlainEd25519Verifier`] takes it.
pub fn sealed_share(
    root: &DeviceRootKey,
    actor: &ActorUri,
    sender: DeviceId,
    recipient: DeviceId,
    generation: HistoryGeneration,
    byte: u8,
) -> SealedShare {
    let enc = ShareEnc::parse(&[byte; 32]).unwrap();
    let ciphertext = ShareCiphertext::parse(vec![byte; 120]).unwrap();
    let aad = share_aad(actor, sender, recipient, generation);
    let signature = plain_signature(root, &share_signed_bytes(&aad, &enc, &ciphertext));
    SealedShare {
        enc,
        ciphertext,
        signature,
    }
}

/// What every store of key shares must do.
pub mod contract {
    use super::super::approval::contract::{actor, by_device, by_passphrase, found, root_key};
    use super::super::contract::{attestation, history_key, register};
    use super::*;
    use crate::e2ee::{DeviceApprovals, HistoryKey, KeyDirectoryError, ShareFacts, may_share};

    /// The stores a share is decided on and kept in, over one database.
    #[derive(Clone, Copy)]
    pub struct ShareStores<'a> {
        pub devices: &'a dyn Devices,
        pub approvals: &'a dyn DeviceApprovals,
        pub keys: &'a dyn HistoryKeys,
        pub shares: &'a dyn KeyShares,
    }

    /// A device of `owner`'s, its root key and HPKE key made of `key`s.
    async fn a_device(s: ShareStores<'_>, owner: UserId, key: u8) -> DeviceId {
        let id = DeviceId::generate();
        register(
            s.devices,
            owner,
            id,
            &attestation(key),
            HpkeKeyWrite::Set(hpke_key(key)),
        )
        .await;
        id
    }

    /// `device` approved by `key`'s approval key and holding it, as a device the words were typed
    /// on is.
    async fn holding(s: ShareStores<'_>, owner: UserId, device: DeviceId, key: &HistoryKey) {
        let approval = by_passphrase(s.devices, device, key).await;
        s.approvals.approve(owner, &approval).await.unwrap();
        s.devices
            .hold_history_key(owner, device, key.generation)
            .await
            .unwrap();
    }

    /// `owner`'s laptop, which set `first`, holds it and is approved by it.
    async fn an_account(s: ShareStores<'_>, owner: UserId, first: &HistoryKey) -> DeviceId {
        let laptop = a_device(s, owner, 1).await;
        s.keys.replace(owner, first, laptop).await.unwrap();
        holding(s, owner, laptop, first).await;
        laptop
    }

    /// Another holder of `key`, its keys made of `byte`s.
    async fn a_holder(s: ShareStores<'_>, owner: UserId, byte: u8, key: &HistoryKey) -> DeviceId {
        let device = a_device(s, owner, byte).await;
        holding(s, owner, device, key).await;
        device
    }

    async fn approve(s: ShareStores<'_>, owner: UserId, approver: DeviceId, device: DeviceId) {
        let approval = by_device(s.devices, approver, device).await;
        s.approvals.approve(owner, &approval).await.unwrap();
    }

    /// A device approved by `approver`, its keys made of `byte`s.
    async fn approved_by(
        s: ShareStores<'_>,
        owner: UserId,
        byte: u8,
        approver: DeviceId,
    ) -> DeviceId {
        let device = a_device(s, owner, byte).await;
        approve(s, owner, approver, device).await;
        device
    }

    /// `sender`'s share for `recipient`, decided as the use case decides it, on what the stores
    /// hold now.
    async fn checked(
        s: ShareStores<'_>,
        owner: UserId,
        sender: DeviceId,
        recipient: DeviceId,
        byte: u8,
    ) -> CheckedShare {
        decide(s, owner, sender, recipient, byte)
            .await
            .expect("a well-made share")
    }

    async fn decide(
        s: ShareStores<'_>,
        owner: UserId,
        sender: DeviceId,
        recipient: DeviceId,
        byte: u8,
    ) -> Result<CheckedShare, KeyDirectoryError> {
        let devices = s.devices.list(owner).await.unwrap();
        let approvals = s.approvals.of_owner(owner).await.unwrap();
        let current = s
            .keys
            .current(owner)
            .await
            .unwrap()
            .map(|held| held.key.generation);
        let generation = current.expect("a history key");
        let sending = found(s.devices, sender).await;
        let sealed = sealed_share(
            &root_key(&sending),
            &actor(),
            sender,
            recipient,
            generation,
            byte,
        );
        let facts = ShareFacts {
            actor: &actor(),
            sender: &sending,
            devices: &devices,
            approvals: &approvals,
            current,
        };
        may_share(recipient, generation, sealed, facts, &PlainEd25519Verifier)
    }

    async fn deposit(s: ShareStores<'_>, owner: UserId, share: &CheckedShare) -> Deposit {
        s.shares.deposit(owner, share).await.unwrap()
    }

    /// Who sent `recipient` its share of `generation`, and what.
    async fn held_for(
        s: ShareStores<'_>,
        owner: UserId,
        recipient: DeviceId,
        generation: HistoryGeneration,
    ) -> Option<(DeviceId, SealedShare)> {
        s.shares
            .of_recipient(owner, recipient, generation)
            .await
            .unwrap()
            .map(|share| {
                assert_eq!((share.recipient, share.generation), (recipient, generation));
                (share.sender, share.sealed)
            })
    }

    fn sent(share: &CheckedShare) -> Option<(DeviceId, SealedShare)> {
        Some((share.sender(), share.sealed().clone()))
    }

    /// A new account of `owner`'s whose laptop set generation 1, holds it and approved a phone, and
    /// the laptop's share for the phone, checked: for the races a store's own tests run.
    pub async fn a_share_to_deposit(s: ShareStores<'_>, owner: UserId) -> CheckedShare {
        let laptop = an_account(s, owner, &history_key(1, 1)).await;
        let phone = approved_by(s, owner, 2, laptop).await;
        checked(s, owner, laptop, phone, 1).await
    }

    /// A new account of `owner`'s whose laptop set generation 1; a relay the laptop approved, which
    /// holds it, shares with a device the words approved: the share, checked, and the laptop, the
    /// relay's approver — a link of the share's that is neither of its devices.
    pub async fn a_share_through_an_approver(
        s: ShareStores<'_>,
        owner: UserId,
    ) -> (CheckedShare, DeviceId) {
        let first = history_key(1, 1);
        let laptop = an_account(s, owner, &first).await;
        let relay = approved_by(s, owner, 8, laptop).await;
        s.devices
            .hold_history_key(owner, relay, first.generation)
            .await
            .unwrap();
        let typed_on = a_device(s, owner, 11).await;
        let by_its_words = by_passphrase(s.devices, typed_on, &first).await;
        s.approvals.approve(owner, &by_its_words).await.unwrap();
        approve(s, owner, relay, typed_on).await;
        (checked(s, owner, relay, typed_on, 8).await, laptop)
    }

    pub async fn a_share_is_stored_once_per_recipient_and_generation_and_read_by_its_recipient(
        s: ShareStores<'_>,
        alice: UserId,
        bob: UserId,
    ) {
        let first = history_key(1, 1);
        let laptop = an_account(s, alice, &first).await;
        let tablet = a_holder(s, alice, 2, &first).await;
        let phone = approved_by(s, alice, 3, laptop).await;
        approve(s, alice, tablet, phone).await;
        let bobs = an_account(s, bob, &first).await;
        let bobs_phone = approved_by(s, bob, 4, bobs).await;
        let laptops = checked(s, alice, laptop, phone, 1).await;
        let tablets = checked(s, alice, tablet, phone, 2).await;
        let for_bob = checked(s, bob, bobs, bobs_phone, 3).await;

        let stored = deposit(s, alice, &laptops).await;
        let again = deposit(s, alice, &laptops).await;
        let anothers = deposit(s, alice, &tablets).await;
        deposit(s, bob, &for_bob).await;

        assert_eq!(
            (stored, again, anothers),
            (Deposit::Stored, Deposit::AlreadyHeld, Deposit::AlreadyHeld)
        );
        let g1 = first.generation;
        assert_eq!(held_for(s, alice, phone, g1).await, sent(&laptops));
        assert_eq!(held_for(s, alice, laptop, g1).await, None);
        assert_eq!(held_for(s, alice, tablet, g1).await, None);
        assert_eq!(held_for(s, bob, phone, g1).await, None, "another account's");
        let g2 = HistoryGeneration::parse(2).unwrap();
        assert_eq!(held_for(s, alice, phone, g2).await, None);
        assert_eq!(held_for(s, bob, bobs_phone, g1).await, sent(&for_bob));
    }

    /// The rule decided on what the stores list: the recipient approved by another device only is
    /// refused the sender's share, and takes it once the sender approved it too.
    pub async fn a_holder_that_did_not_approve_the_recipient_shares_nothing(
        s: ShareStores<'_>,
        alice: UserId,
    ) {
        let first = history_key(1, 1);
        let laptop = an_account(s, alice, &first).await;
        let tablet = a_holder(s, alice, 2, &first).await;
        let phone = approved_by(s, alice, 3, laptop).await;

        let refused = decide(s, alice, tablet, phone, 2).await;
        approve(s, alice, tablet, phone).await;
        let once_approved = deposit(s, alice, &checked(s, alice, tablet, phone, 2).await).await;

        assert!(
            matches!(refused, Err(KeyDirectoryError::NotTheApprover)),
            "{refused:?}"
        );
        assert_eq!(once_approved, Deposit::Stored);
        assert_eq!(
            held_for(s, alice, phone, first.generation)
                .await
                .map(|(sender, _)| sender),
            Some(tablet)
        );
    }

    pub async fn a_share_is_stored_only_while_what_it_was_checked_on_holds(
        s: ShareStores<'_>,
        alice: UserId,
    ) {
        let first = history_key(1, 1);
        let laptop = an_account(s, alice, &first).await;
        let tablet = a_holder(s, alice, 2, &first).await;
        let watch = a_holder(s, alice, 3, &first).await;
        let revoked = approved_by(s, alice, 4, laptop).await;
        let reporting = approved_by(s, alice, 5, laptop).await;
        let resealed = approved_by(s, alice, 6, laptop).await;
        let rotated = approved_by(s, alice, 7, laptop).await;
        let relay = approved_by(s, alice, 8, tablet).await;
        s.devices
            .hold_history_key(alice, relay, first.generation)
            .await
            .unwrap();
        let typed_on = a_device(s, alice, 11).await;
        let by_its_words = by_passphrase(s.devices, typed_on, &first).await;
        s.approvals.approve(alice, &by_its_words).await.unwrap();
        approve(s, alice, relay, typed_on).await;
        let from_the_watch = approved_by(s, alice, 9, watch).await;
        let last = approved_by(s, alice, 10, laptop).await;
        let stale = [
            checked(s, alice, laptop, revoked, 1).await,
            checked(s, alice, laptop, reporting, 1).await,
            checked(s, alice, laptop, resealed, 1).await,
            checked(s, alice, laptop, rotated, 1).await,
            checked(s, alice, relay, typed_on, 8).await,
            checked(s, alice, watch, from_the_watch, 3).await,
        ];
        let before_the_new_generation = checked(s, alice, laptop, last, 1).await;

        s.devices.revoke(alice, revoked).await.unwrap();
        s.devices
            .hold_history_key(alice, reporting, first.generation)
            .await
            .unwrap();
        register(
            s.devices,
            alice,
            resealed,
            &attestation(6),
            HpkeKeyWrite::Set(hpke_key(60)),
        )
        .await;
        register(
            s.devices,
            alice,
            rotated,
            &attestation(70),
            HpkeKeyWrite::Set(hpke_key(7)),
        )
        .await;
        s.devices.revoke(alice, tablet).await.unwrap();
        s.devices.revoke(alice, watch).await.unwrap();

        for share in &stale {
            assert_eq!(deposit(s, alice, share).await, Deposit::Stale, "{share:?}");
            assert_eq!(
                held_for(s, alice, share.recipient(), first.generation).await,
                None
            );
        }
        s.keys
            .replace(alice, &history_key(2, 2), laptop)
            .await
            .unwrap();
        assert_eq!(
            deposit(s, alice, &before_the_new_generation).await,
            Deposit::Stale
        );
    }

    pub async fn a_new_generation_deletes_the_accounts_shares(
        s: ShareStores<'_>,
        alice: UserId,
        bob: UserId,
    ) {
        let first = history_key(1, 1);
        let laptop = an_account(s, alice, &first).await;
        let phone = approved_by(s, alice, 2, laptop).await;
        let bobs = an_account(s, bob, &first).await;
        let bobs_phone = approved_by(s, bob, 3, bobs).await;
        deposit(s, alice, &checked(s, alice, laptop, phone, 1).await).await;
        let for_bob = checked(s, bob, bobs, bobs_phone, 2).await;
        deposit(s, bob, &for_bob).await;

        s.keys
            .replace(alice, &history_key(2, 2), laptop)
            .await
            .unwrap();

        assert_eq!(held_for(s, alice, phone, first.generation).await, None);
        assert_eq!(
            held_for(s, bob, bobs_phone, first.generation).await,
            sent(&for_bob)
        );
    }

    pub async fn revoking_a_device_deletes_the_shares_it_sent_or_was_sent(
        s: ShareStores<'_>,
        alice: UserId,
    ) {
        let first = history_key(1, 1);
        let laptop = an_account(s, alice, &first).await;
        let tablet = a_holder(s, alice, 2, &first).await;
        let (phone, watch, tv) = (
            approved_by(s, alice, 3, laptop).await,
            approved_by(s, alice, 4, tablet).await,
            approved_by(s, alice, 5, laptop).await,
        );
        deposit(s, alice, &checked(s, alice, laptop, phone, 1).await).await;
        deposit(s, alice, &checked(s, alice, tablet, watch, 2).await).await;
        let kept = checked(s, alice, laptop, tv, 1).await;
        deposit(s, alice, &kept).await;

        s.devices.revoke(alice, phone).await.unwrap();
        s.devices.revoke(alice, tablet).await.unwrap();

        let g1 = first.generation;
        assert_eq!(held_for(s, alice, phone, g1).await, None, "its recipient");
        assert_eq!(held_for(s, alice, watch, g1).await, None, "its sender");
        assert_eq!(held_for(s, alice, tv, g1).await, sent(&kept));
    }

    pub async fn a_new_root_key_or_hpke_key_deletes_the_shares_it_no_longer_fits(
        s: ShareStores<'_>,
        alice: UserId,
    ) {
        let first = history_key(1, 1);
        let laptop = an_account(s, alice, &first).await;
        let tablet = a_holder(s, alice, 2, &first).await;
        let (phone, watch, tv, renewed) = (
            approved_by(s, alice, 3, laptop).await,
            approved_by(s, alice, 4, laptop).await,
            approved_by(s, alice, 5, tablet).await,
            approved_by(s, alice, 6, laptop).await,
        );
        for (sender, recipient) in [
            (laptop, phone),
            (laptop, watch),
            (tablet, tv),
            (laptop, renewed),
        ] {
            deposit(s, alice, &checked(s, alice, sender, recipient, 1).await).await;
        }
        let kept = held_for(s, alice, renewed, first.generation).await;

        register(
            s.devices,
            alice,
            phone,
            &attestation(3),
            HpkeKeyWrite::Set(hpke_key(30)),
        )
        .await;
        register(
            s.devices,
            alice,
            watch,
            &attestation(40),
            HpkeKeyWrite::Set(hpke_key(4)),
        )
        .await;
        register(
            s.devices,
            alice,
            tablet,
            &attestation(20),
            HpkeKeyWrite::Set(hpke_key(2)),
        )
        .await;
        register(
            s.devices,
            alice,
            renewed,
            &attestation(6),
            HpkeKeyWrite::Keep,
        )
        .await;

        let g1 = first.generation;
        assert_eq!(held_for(s, alice, phone, g1).await, None, "a new HPKE key");
        assert_eq!(held_for(s, alice, watch, g1).await, None, "a new root key");
        assert_eq!(
            held_for(s, alice, tv, g1).await,
            None,
            "its sender's new root key"
        );
        assert!(kept.is_some());
        assert_eq!(held_for(s, alice, renewed, g1).await, kept, "a renewal");
    }

    pub async fn the_recipient_holding_the_generation_deletes_its_share(
        s: ShareStores<'_>,
        alice: UserId,
    ) {
        let first = history_key(1, 1);
        let laptop = an_account(s, alice, &first).await;
        let (phone, tablet) = (
            approved_by(s, alice, 2, laptop).await,
            approved_by(s, alice, 3, laptop).await,
        );
        deposit(s, alice, &checked(s, alice, laptop, phone, 1).await).await;
        let kept = checked(s, alice, laptop, tablet, 2).await;
        deposit(s, alice, &kept).await;

        s.devices
            .hold_history_key(alice, phone, first.generation)
            .await
            .unwrap();

        assert_eq!(held_for(s, alice, phone, first.generation).await, None);
        assert_eq!(
            held_for(s, alice, tablet, first.generation).await,
            sent(&kept)
        );
    }
}
