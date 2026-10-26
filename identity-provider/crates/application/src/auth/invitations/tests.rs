use domain::auth::SignUps;
use domain::auth::testing::contract;
use time::Duration;

use crate::auth::world::{now, world};

use super::*;

#[tokio::test]
async fn an_admin_creates_an_invitation_open_for_a_week() {
    let w = world().await;
    let admin = w.an_admin().await;

    let created = w.create_invitation.execute(admin.id, now()).await.unwrap();

    assert_eq!(created.expires_at, now() + Duration::days(7));
    let open = w
        .accounts
        .find_open(&created.token, now())
        .await
        .unwrap()
        .expect("open");
    assert_eq!(
        (open.id, open.inviter, open.expires_at),
        (created.id, Some("root".to_owned()), created.expires_at)
    );
}

#[tokio::test]
async fn only_an_admin_creates_lists_or_revokes_invitations() {
    let w = world().await;
    let admin = w.an_admin().await;
    let open = w.create_invitation.execute(admin.id, now()).await.unwrap();

    for caller in [w.alice.id, UserId::generate()] {
        let created = w.create_invitation.execute(caller, now()).await;
        let listed = w.list_invitations.execute(caller, now()).await;
        let revoked = w
            .revoke_invitation
            .execute(caller, Some(open.id), now())
            .await;
        let unnamed = w.revoke_invitation.execute(caller, None, now()).await;

        assert!(matches!(created, Err(AuthError::NotAdmin)), "{created:?}");
        assert!(matches!(listed, Err(AuthError::NotAdmin)), "{listed:?}");
        assert!(matches!(revoked, Err(AuthError::NotAdmin)), "{revoked:?}");
        assert!(matches!(unnamed, Err(AuthError::NotAdmin)), "{unnamed:?}");
    }
    assert!(
        w.accounts
            .find_open(&open.token, now())
            .await
            .unwrap()
            .is_some(),
        "still open"
    );
}

#[tokio::test]
async fn an_admin_lists_the_open_invitations_only() {
    let w = world().await;
    let admin = w.an_admin().await;
    let used = w
        .create_invitation
        .execute(admin.id, now() - Duration::days(2))
        .await
        .unwrap();
    w.accounts
        .create_invited(
            &contract::a_new_account("bob"),
            used.id,
            now() - Duration::days(1),
        )
        .await
        .unwrap();
    w.create_invitation
        .execute(admin.id, now() - Duration::days(8))
        .await
        .unwrap();
    let revoked = w
        .create_invitation
        .execute(admin.id, now() - Duration::days(1))
        .await
        .unwrap();
    w.revoke_invitation
        .execute(admin.id, Some(revoked.id), now())
        .await
        .unwrap();
    let older = w
        .create_invitation
        .execute(admin.id, now() - Duration::hours(5))
        .await
        .unwrap();
    let newer = w.create_invitation.execute(admin.id, now()).await.unwrap();

    let listed = w.list_invitations.execute(admin.id, now()).await.unwrap();

    assert_eq!(
        listed.iter().map(|open| open.id).collect::<Vec<_>>(),
        vec![newer.id, older.id]
    );
    assert_eq!(listed[0].inviter.as_deref(), Some("root"));
}

#[tokio::test]
async fn an_admin_revokes_an_open_invitation_once() {
    let w = world().await;
    let admin = w.an_admin().await;
    let created = w.create_invitation.execute(admin.id, now()).await.unwrap();

    let revoked = w
        .revoke_invitation
        .execute(admin.id, Some(created.id), now())
        .await;
    let again = w
        .revoke_invitation
        .execute(admin.id, Some(created.id), now())
        .await;
    let unknown = w
        .revoke_invitation
        .execute(admin.id, Some(InvitationId::generate()), now())
        .await;
    let unnamed = w.revoke_invitation.execute(admin.id, None, now()).await;

    assert!(revoked.is_ok(), "{revoked:?}");
    assert!(
        matches!(again, Err(AuthError::InvitationUnusable)),
        "{again:?}"
    );
    assert!(
        matches!(unknown, Err(AuthError::InvitationUnusable)),
        "{unknown:?}"
    );
    assert!(
        matches!(unnamed, Err(AuthError::InvitationUnusable)),
        "{unnamed:?}"
    );
    assert_eq!(
        w.accounts.find_open(&created.token, now()).await.unwrap(),
        None
    );
    assert!(
        w.list_invitations
            .execute(admin.id, now())
            .await
            .unwrap()
            .is_empty(),
        "a revoked invitation is not listed"
    );
}
