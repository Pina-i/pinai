use super::*;

const PASSWORD: Option<&str> = Some("admin-password");

fn root() -> Email {
    Email::parse("root@idp.test").unwrap()
}

fn held_by(holder: AddressHolder) -> Option<(Email, AddressHolder)> {
    Some((root(), holder))
}

fn create(password: &str) -> AdminBootstrap<NewAdmin> {
    AdminBootstrap::Create(NewAdmin {
        address: root(),
        password: AdminPassword::parse(password).unwrap(),
    })
}

#[test]
fn an_address_nobody_has_is_given_to_a_new_admin_account_with_the_password() {
    for admin_exists in [false, true] {
        assert_eq!(
            admin_bootstrap(admin_exists, held_by(AddressHolder::Nobody), PASSWORD),
            create("admin-password")
        );
    }
}

#[test]
fn a_new_admin_account_needs_a_password_within_the_rule() {
    let nobody = |password| admin_bootstrap(false, held_by(AddressHolder::Nobody), password);

    assert_eq!(
        nobody(None),
        AdminBootstrap::Refused(AdminRefusal::NoPassword)
    );
    assert_eq!(
        nobody(Some("1234567")),
        AdminBootstrap::Refused(AdminRefusal::PasswordTooShort)
    );
    assert_eq!(nobody(Some("12345678")), create("12345678"));
}

#[test]
fn the_admin_holding_the_address_is_left_alone_and_a_password_still_set_called_unused() {
    let admin = |password| admin_bootstrap(true, held_by(AddressHolder::Admin), password);

    assert_eq!(
        admin(PASSWORD),
        AdminBootstrap::AlreadyAdmin {
            password_unused: true
        }
    );
    assert_eq!(
        admin(Some("short")),
        AdminBootstrap::AlreadyAdmin {
            password_unused: true
        }
    );
    assert_eq!(
        admin(None),
        AdminBootstrap::AlreadyAdmin {
            password_unused: false
        }
    );
}

#[test]
fn an_account_holding_the_address_is_never_promoted_and_a_missing_admin_said_so() {
    assert_eq!(
        admin_bootstrap(false, held_by(AddressHolder::NotAdmin), PASSWORD),
        AdminBootstrap::NotPromoted { no_admin: true }
    );
    assert_eq!(
        admin_bootstrap(true, held_by(AddressHolder::NotAdmin), None),
        AdminBootstrap::NotPromoted { no_admin: false }
    );
}

#[test]
fn without_an_address_an_instance_with_no_admin_is_said_so_and_one_with_an_admin_left_alone() {
    for password in [PASSWORD, None] {
        assert_eq!(
            admin_bootstrap(false, None, password),
            AdminBootstrap::NoAdmin
        );
        assert_eq!(
            admin_bootstrap(true, None, password),
            AdminBootstrap::Settled
        );
    }
}

#[test]
fn what_is_told_of_a_creation_leaves_the_password_behind() {
    let told = create("admin-password").map_create(|admin| admin.address);

    assert_eq!(told, AdminBootstrap::Create(root()));
}

#[test]
fn the_admin_password_is_never_shown() {
    let shown = format!("{:?}", create("admin-password"));

    assert!(!shown.contains("admin-password"), "{shown}");
}

#[test]
fn the_admin_is_named_admin() {
    assert_eq!(admin_display_name().as_str(), "Admin");
}
