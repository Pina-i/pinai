use domain::auth::SignInAccount;
use domain::auth::testing::{StepAuthenticator, signed_up};

use domain::UserId;

use crate::auth::world::{now, world};

use super::*;

#[tokio::test]
async fn an_enrolled_secret_turns_the_second_factor_on_once_the_apps_code_confirms_it() {
    let w = world().await;

    let enrollment = w.enroll.execute(&w.bearer_of(w.alice.id)).await.unwrap();
    let pending = w.factors.pending(w.alice.id).await.unwrap().unwrap();
    let codes = w
        .confirm
        .execute(
            &w.bearer_of(w.alice.id),
            &StepAuthenticator::code_at(&pending, now()),
            now(),
        )
        .await
        .unwrap();

    assert_eq!(
        enrollment,
        Enrollment {
            secret_base32: "SECRET1".to_owned(),
            provisioning_url:
                "otpauth://totp/Pina'i (localhost:8080):alice@idp.test?secret=SECRET1".to_owned(),
        }
    );
    assert_eq!(codes.len(), domain::auth::RECOVERY_CODES);
    assert_eq!(w.factors.state_of(w.alice.id), (true, 10, false));
    let alice: SignInAccount = w.accounts.by_id(w.alice.id).await.unwrap().unwrap();
    assert!(alice.totp_enabled);
}

#[tokio::test]
async fn enrolling_again_is_refused_while_on_and_a_confirmation_needs_the_right_code() {
    let w = world().await;
    let bob = SignInAccount {
        totp_enabled: true,
        ..signed_up("bob")
    };
    w.sign_up(&bob).await;

    let again = w.enroll.execute(&w.bearer_of(bob.id)).await;
    let unasked = w
        .confirm
        .execute(&w.bearer_of(w.alice.id), "123456", now())
        .await;
    w.enroll.execute(&w.bearer_of(w.alice.id)).await.unwrap();
    let pending = w.factors.pending(w.alice.id).await.unwrap().unwrap();
    let right = StepAuthenticator::code_at(&pending, now());
    let wrong = if right == "000000" {
        "111111"
    } else {
        "000000"
    };
    let guessed = w
        .confirm
        .execute(&w.bearer_of(w.alice.id), wrong, now())
        .await;
    let unknown = w.enroll.execute(&w.bearer_of(UserId::generate())).await;

    assert!(matches!(again, Err(AuthError::TotpEnabled)), "{again:?}");
    assert!(
        matches!(unasked, Err(AuthError::NoEnrollment)),
        "{unasked:?}"
    );
    assert!(matches!(guessed, Err(AuthError::WrongCode)), "{guessed:?}");
    assert!(
        matches!(unknown, Err(AuthError::UnknownUser)),
        "{unknown:?}"
    );
    assert_eq!(w.factors.state_of(w.alice.id), (false, 0, true));
}

/// On with recovery codes to use, or off with none; never on while an enrollment waits.
fn consistent((on, codes, pending): (bool, usize, bool)) -> bool {
    on == (codes > 0) && !(on && pending)
}

#[tokio::test]
async fn a_confirmation_the_store_fails_part_way_never_leaves_the_factor_on_without_codes() {
    let w = world().await;
    w.enroll.execute(&w.bearer_of(w.alice.id)).await.unwrap();
    let pending = w.factors.pending(w.alice.id).await.unwrap().unwrap();
    w.factors.down_after(1);

    let _ = w
        .confirm
        .execute(
            &w.bearer_of(w.alice.id),
            &StepAuthenticator::code_at(&pending, now()),
            now(),
        )
        .await;

    let state = w.factors.state_of(w.alice.id);
    assert!(consistent(state), "{state:?}");
}

mod with_a_history_key {
    use domain::DeviceId;
    use domain::e2ee::{
        ApprovalPublicKey, Attestation, DeviceLabel, DeviceRootKey, Devices, HistoryCheckValue,
        HistoryGeneration, HistoryKey, HistoryKeys, HistorySalt, HpkeKeyWrite,
    };
    use domain::identity::Bearer;

    use super::*;
    use crate::auth::world::World;

    /// A device of Alice's, its root key registered, and a session naming it.
    async fn on_a_device(w: &World) -> (DeviceId, Bearer) {
        let device = DeviceId::generate();
        let attestation = Attestation {
            root_key: DeviceRootKey::parse(&[1; 32]).unwrap(),
            signature: vec![1; 64],
            kid: "key-1".to_owned(),
            issued_at: now(),
            expires_at: now() + time::Duration::days(365),
        };
        w.devices
            .attest(
                w.alice.id,
                device,
                &DeviceLabel::unknown(),
                None,
                &attestation,
                &HpkeKeyWrite::Clear,
            )
            .await
            .unwrap();
        let bearer = w.bearer_of(w.alice.id);
        w.sessions
            .link(w.alice.id, bearer.session, device, now())
            .await
            .unwrap();
        (device, bearer)
    }

    #[tokio::test]
    async fn only_an_approved_device_turns_the_second_factor_on() {
        let w = world().await;
        let first = HistoryKey {
            generation: HistoryGeneration::FIRST,
            salt: HistorySalt::parse(&[1; 16]).unwrap(),
            check_value: HistoryCheckValue::parse(&[1; 32]).unwrap(),
            approval_public_key: ApprovalPublicKey::parse(&[1; 32]).unwrap(),
        };
        let (laptop, on_the_laptop) = on_a_device(&w).await;
        let (_, on_a_fresh_one) = on_a_device(&w).await;
        w.archive
            .replace(w.alice.id, &first, laptop, now())
            .await
            .unwrap();
        w.devices
            .approved_by_words(w.alice.id, laptop, &first)
            .await;
        let unnamed = w.bearer_of(w.alice.id);

        let fresh_enrolls = w.enroll.execute(&on_a_fresh_one).await;
        let unnamed_enrolls = w.enroll.execute(&unnamed).await;
        w.enroll.execute(&on_the_laptop).await.unwrap();
        let pending = w.factors.pending(w.alice.id).await.unwrap().unwrap();
        let code = StepAuthenticator::code_at(&pending, now());
        let fresh_confirms = w.confirm.execute(&on_a_fresh_one, &code, now()).await;
        let still_off = w.factors.state_of(w.alice.id);
        let laptop_confirms = w.confirm.execute(&on_the_laptop, &code, now()).await;

        for refused in [fresh_enrolls.map(|_| ()), unnamed_enrolls.map(|_| ())] {
            assert!(
                matches!(refused, Err(AuthError::ApprovalRequired(_))),
                "{refused:?}"
            );
        }
        assert!(
            matches!(fresh_confirms, Err(AuthError::ApprovalRequired(_))),
            "{fresh_confirms:?}"
        );
        assert_eq!(still_off, (false, 0, true));
        assert!(laptop_confirms.is_ok(), "{laptop_confirms:?}");
        assert!(w.factors.state_of(w.alice.id).0);
    }
}
