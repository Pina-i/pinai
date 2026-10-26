use domain::auth::testing::{PlainHasher, signed_up};
use domain::auth::{
    AddressHolder, AdminFacts, AdminRefusal, NewAccount, Registrations, SignInAccount,
    SignInAccounts,
};
use domain::identity::{ActorUri, Handle};

use crate::auth::world::{World, now, world};

use super::*;

const ROOT: &str = "root@idp.test";

async fn open(w: &World, address: Option<&str>, password: Option<&str>) -> AdminBootstrap<Email> {
    w.ensure_admin
        .execute(Registrations::Open, address, password, now())
        .await
        .unwrap()
}

async fn invite(w: &World, address: Option<&str>, password: Option<&str>) -> AdminBootstrap<Email> {
    w.ensure_admin
        .execute(Registrations::Invite, address, password, now())
        .await
        .unwrap()
}

async fn facts(sign_ups: &dyn SignUps, address: &str) -> AdminFacts {
    sign_ups
        .admin_facts(Some(&Email::parse(address).unwrap()))
        .await
        .unwrap()
}

#[tokio::test]
async fn an_address_nobody_has_becomes_the_admin_account_admitted_and_unconfirmed() {
    let w = world().await;

    let bootstrap = open(&w, Some("  Root@IDP.test"), Some("admin-password")).await;

    assert_eq!(
        bootstrap,
        AdminBootstrap::Create(Email::parse(ROOT).unwrap())
    );
    let created = w.accounts.created();
    assert_eq!(
        created,
        vec![NewAccount {
            id: created[0].id,
            username: Handle::parse("admin_sfx01").unwrap(),
            display_name: "Admin".to_owned(),
            email: Email::parse(ROOT).unwrap(),
            password_hash: PlainHasher::hash("admin-password"),
            actor_uri: ActorUri::parse("http://localhost:8080/users/admin_sfx01").unwrap(),
        }]
    );
    let account = w.accounts.by_id(created[0].id).await.unwrap().unwrap();
    assert!(!account.email_verified, "its address is not confirmed");
    assert!(!account.needs_code(), "it is admitted");
    assert_eq!(facts(&*w.accounts, ROOT).await.holder, AddressHolder::Admin);
    assert!(w.mailer.sent().is_empty());
}

#[tokio::test]
async fn a_later_start_leaves_the_admin_and_its_password_alone() {
    let w = world().await;
    open(&w, Some(ROOT), Some("admin-password")).await;

    let reminded = open(&w, Some(ROOT), Some("another-password")).await;
    let quiet = open(&w, Some(ROOT), None).await;

    assert_eq!(
        (reminded, quiet),
        (
            AdminBootstrap::AlreadyAdmin {
                password_unused: true
            },
            AdminBootstrap::AlreadyAdmin {
                password_unused: false
            }
        )
    );
    assert_eq!(w.accounts.created().len(), 1);
    let admin = w
        .accounts
        .by_email(&Email::parse(ROOT).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(admin.password_hash, PlainHasher::hash("admin-password"));
}

#[tokio::test]
async fn an_account_holding_the_address_is_not_made_admin() {
    let w = world().await;

    let alone = open(&w, Some(&w.alice.email), Some("admin-password")).await;
    open(&w, Some(ROOT), Some("admin-password")).await;
    let beside_an_admin = open(&w, Some(&w.alice.email), Some("admin-password")).await;

    assert_eq!(
        (alone, beside_an_admin),
        (
            AdminBootstrap::NotPromoted { no_admin: true },
            AdminBootstrap::NotPromoted { no_admin: false }
        )
    );
    assert_eq!(
        facts(&*w.accounts, &w.alice.email).await.holder,
        AddressHolder::NotAdmin
    );
    assert_eq!(w.accounts.created().len(), 1, "the admin only");
}

#[tokio::test]
async fn without_an_address_the_instance_is_told_whether_it_has_an_admin() {
    let w = world().await;

    let none = open(&w, None, None).await;
    open(&w, Some(ROOT), Some("admin-password")).await;
    let settled = open(&w, None, Some("admin-password")).await;

    assert_eq!(
        (none, settled),
        (AdminBootstrap::NoAdmin, AdminBootstrap::Settled)
    );
}

#[tokio::test]
async fn no_admin_account_is_created_without_a_password_within_the_rule_or_with_a_bad_address() {
    let w = world().await;

    let without = open(&w, Some(ROOT), None).await;
    let short = open(&w, Some(ROOT), Some("1234567")).await;
    let bad_address = open(&w, Some("root"), Some("admin-password")).await;

    assert_eq!(
        (without, short),
        (
            AdminBootstrap::Refused(AdminRefusal::NoPassword),
            AdminBootstrap::Refused(AdminRefusal::PasswordTooShort)
        )
    );
    assert!(
        matches!(
            bad_address,
            AdminBootstrap::Refused(AdminRefusal::BadAddress(_))
        ),
        "{bad_address:?}"
    );
    assert!(w.accounts.created().is_empty());
}

#[tokio::test]
async fn a_handle_taken_by_chance_is_drawn_again_for_the_admin() {
    let w = world().await;
    w.sign_up(&SignInAccount {
        username: "admin_sfx01".to_owned(),
        ..signed_up("robert")
    })
    .await;

    open(&w, Some(ROOT), Some("admin-password")).await;

    assert_eq!(w.accounts.created()[0].username.as_str(), "admin_sfx02");
}

#[tokio::test]
async fn an_invite_only_instance_without_an_admin_is_refused_and_creates_nothing() {
    let w = world().await;

    let unset = invite(&w, None, None).await;
    let a_members = invite(&w, Some(&w.alice.email), Some("admin-password")).await;

    assert_eq!(
        (unset, a_members),
        (
            AdminBootstrap::Refused(AdminRefusal::NoAdminToInvite {
                not_promoted: false
            }),
            AdminBootstrap::Refused(AdminRefusal::NoAdminToInvite { not_promoted: true })
        )
    );
    assert!(w.accounts.created().is_empty());
    assert_eq!(
        facts(&*w.accounts, &w.alice.email).await.holder,
        AddressHolder::NotAdmin
    );
}

#[tokio::test]
async fn an_invite_only_instance_creates_its_admin_and_then_starts_without_the_address() {
    let w = world().await;

    let created = invite(&w, Some(ROOT), Some("admin-password")).await;
    let later = invite(&w, None, None).await;

    assert_eq!(
        (created, later),
        (
            AdminBootstrap::Create(Email::parse(ROOT).unwrap()),
            AdminBootstrap::Settled
        )
    );
}
