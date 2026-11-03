use super::*;

fn used_at(at: OffsetDateTime) -> Session {
    Session {
        id: SessionId::generate(),
        user: UserId::generate(),
        kind: SessionKind::Browser,
        device: None,
        created_at: at,
        last_used_at: at,
        authenticated_at: at,
        revoked_at: None,
    }
}

#[test]
fn a_session_lives_until_ninety_days_without_use() {
    let at = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
    let session = used_at(at);

    assert!(session.is_live(at));
    assert!(session.is_live(at + SESSION_IDLE - Duration::days(1)));
    assert!(!session.is_live(at + SESSION_IDLE));
    assert!(!session.is_live(at + SESSION_IDLE + Duration::days(1)));
}

#[test]
fn a_revoked_session_is_over_at_once() {
    let at = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
    let session = Session {
        revoked_at: Some(at),
        ..used_at(at)
    };

    assert!(!session.is_live(at));
}

#[test]
fn a_device_was_last_active_at_its_live_sessions_last_use_and_is_signed_out_without_one() {
    let at = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
    let device = DeviceId::generate();
    let on = |session: Session| Session {
        device: Some(device),
        ..session
    };
    let earlier = on(used_at(at - Duration::days(2)));
    let latest = on(used_at(at - Duration::hours(3)));
    let ended = Session {
        revoked_at: Some(at),
        ..on(used_at(at - Duration::minutes(5)))
    };
    let elsewhere = used_at(at - Duration::minutes(1));

    assert_eq!(
        last_active(
            &[earlier.clone(), latest, ended.clone(), elsewhere.clone()],
            device,
            at
        ),
        Some(at - Duration::hours(3))
    );
    assert_eq!(last_active(&[ended, elsewhere], device, at), None);
    assert_eq!(
        last_active(&[earlier], device, at + SESSION_IDLE),
        None,
        "idle 90 days is signed out"
    );
}

/// A browser session with two web apps under it, the first naming `device`.
struct Tree {
    browser: Session,
    on_device: Session,
    sibling: Session,
}

fn web_app(browser: &Session, client: &str) -> Session {
    Session {
        kind: SessionKind::Web {
            client: ClientId::parse(client).unwrap(),
            browser: browser.id,
        },
        user: browser.user,
        ..used_at(browser.created_at)
    }
}

fn a_tree(device: DeviceId) -> Tree {
    a_tree_of(UserId::generate(), device)
}

/// `user`'s.
fn a_tree_of(user: UserId, device: DeviceId) -> Tree {
    let at = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
    let browser = Session {
        user,
        ..used_at(at)
    };
    let on_device = Session {
        device: Some(device),
        ..web_app(&browser, "https://app.pinai.test/oauth-client.json")
    };
    let sibling = Session {
        device: Some(DeviceId::generate()),
        ..web_app(&browser, "https://idp.example.org/web/oauth-client.json")
    };
    Tree {
        browser,
        on_device,
        sibling,
    }
}

fn desktop_of(user: UserId, device: Option<DeviceId>) -> Session {
    let at = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
    Session {
        user,
        kind: SessionKind::App(ClientId::parse("https://idp.test/clients/desktop.json").unwrap()),
        device,
        ..used_at(at)
    }
}

#[test]
fn a_web_apps_session_hangs_under_its_browser_session_and_no_other_kind_does() {
    let tree = a_tree(DeviceId::generate());

    assert_eq!(tree.on_device.browser(), Some(tree.browser.id));
    assert_eq!(tree.browser.browser(), None);
    assert_eq!(desktop_of(tree.browser.user, None).browser(), None);
}

#[test]
fn only_a_live_browser_session_signs_apps_in() {
    let tree = a_tree(DeviceId::generate());
    let at = tree.browser.created_at;
    let ended = Session {
        revoked_at: Some(at),
        ..tree.browser.clone()
    };

    assert!(tree.browser.signs_apps_in(at));
    assert!(!tree.browser.signs_apps_in(at + SESSION_IDLE), "idle");
    assert!(!ended.signs_apps_in(at));
    assert!(!tree.on_device.signs_apps_in(at), "a web app's own");
    assert!(!desktop_of(tree.browser.user, None).signs_apps_in(at));
}

#[test]
fn ending_a_browser_session_ends_its_web_apps_and_ending_a_web_app_ends_only_it() {
    let tree = a_tree(DeviceId::generate());
    let desktop = desktop_of(tree.browser.user, None);
    let other_browser = used_at(tree.browser.created_at);
    let sessions = [
        tree.browser.clone(),
        tree.on_device.clone(),
        tree.sibling.clone(),
        desktop.clone(),
        other_browser,
    ];

    assert_eq!(
        ending(&sessions, tree.browser.id),
        vec![tree.browser.id, tree.on_device.id, tree.sibling.id],
        "never the desktop's, nor another browser's"
    );
    assert_eq!(ending(&sessions, tree.sibling.id), vec![tree.sibling.id]);
    assert_eq!(ending(&sessions, desktop.id), vec![desktop.id]);
}

#[test]
fn what_ended_already_is_not_ended_again() {
    let tree = a_tree(DeviceId::generate());
    let at = tree.browser.created_at;
    let revoked = Session {
        revoked_at: Some(at),
        ..tree.sibling.clone()
    };
    let sessions = [tree.browser.clone(), tree.on_device.clone(), revoked];

    assert_eq!(
        ending(&sessions, tree.browser.id),
        vec![tree.browser.id, tree.on_device.id]
    );
    assert_eq!(ending(&sessions, tree.sibling.id), Vec::<SessionId>::new());
}

#[test]
fn revoking_a_web_apps_device_ends_its_browser_session_and_that_browsers_other_web_apps() {
    let device = DeviceId::generate();
    let tree = a_tree(device);
    let elsewhere = a_tree_of(tree.browser.user, DeviceId::generate());
    let desktop = desktop_of(tree.browser.user, Some(DeviceId::generate()));
    let sessions = [
        tree.browser.clone(),
        tree.on_device.clone(),
        tree.sibling.clone(),
        elsewhere.browser.clone(),
        elsewhere.on_device.clone(),
        desktop,
    ];

    assert_eq!(
        ending_with_device(&sessions, device),
        vec![tree.browser.id, tree.on_device.id, tree.sibling.id],
        "the cookie left there would sign the device in again as a new one"
    );
}

#[test]
fn revoking_a_desktops_device_ends_its_session_only() {
    let device = DeviceId::generate();
    let tree = a_tree(DeviceId::generate());
    let desktop = desktop_of(tree.browser.user, Some(device));
    let sessions = [
        tree.browser.clone(),
        tree.on_device.clone(),
        desktop.clone(),
    ];

    assert_eq!(ending_with_device(&sessions, device), vec![desktop.id]);
}

#[test]
fn a_device_whose_session_ended_already_ends_no_browser_session() {
    let device = DeviceId::generate();
    let tree = a_tree(device);
    let signed_out = Session {
        revoked_at: Some(tree.browser.created_at),
        ..tree.on_device.clone()
    };

    assert_eq!(
        ending_with_device(&[tree.browser, signed_out, tree.sibling], device),
        Vec::<SessionId>::new(),
        "the web app signed in again as another device"
    );
}

#[test]
fn signing_out_elsewhere_keeps_the_callers_whole_browser_and_nothing_else() {
    let tree = a_tree(DeviceId::generate());
    let elsewhere = a_tree_of(tree.browser.user, DeviceId::generate());
    let desktop = desktop_of(tree.browser.user, Some(DeviceId::generate()));
    let sessions = [
        tree.browser.clone(),
        tree.on_device.clone(),
        tree.sibling.clone(),
        elsewhere.browser.clone(),
        elsewhere.on_device.clone(),
        desktop.clone(),
    ];

    assert_eq!(
        ending_all_but(&sessions, tree.on_device.id),
        vec![elsewhere.browser.id, elsewhere.on_device.id, desktop.id],
        "its browser session and the web app beside it, which its cookie signs in again anyway"
    );
    assert_eq!(
        ending_all_but(&sessions, desktop.id),
        vec![
            tree.browser.id,
            tree.on_device.id,
            tree.sibling.id,
            elsewhere.browser.id,
            elsewhere.on_device.id,
        ],
        "a desktop keeps its own session only"
    );
}

#[test]
fn a_live_web_app_or_app_session_names_one_device_and_a_browser_session_none() {
    let (laptop, phone) = (DeviceId::generate(), DeviceId::generate());
    let tree = a_tree(laptop);
    let at = tree.browser.created_at;
    let unnamed = Session {
        device: None,
        ..tree.sibling.clone()
    };
    let ended = Session {
        revoked_at: Some(at),
        ..unnamed.clone()
    };

    assert!(may_link(&unnamed, phone, at).is_ok());
    assert!(may_link(&desktop_of(tree.browser.user, None), phone, at).is_ok());
    assert!(
        may_link(&tree.on_device, laptop, at).is_ok(),
        "the same again"
    );
    for refused in [
        may_link(&tree.on_device, phone, at),
        may_link(&tree.browser, phone, at),
    ] {
        assert!(
            matches!(refused, Err(AuthError::DeviceMismatch)),
            "{refused:?}"
        );
    }
    for over in [
        may_link(&ended, phone, at),
        may_link(&unnamed, phone, at + SESSION_IDLE),
    ] {
        assert!(matches!(over, Err(AuthError::SessionEnded)), "{over:?}");
    }
}

#[test]
fn a_web_apps_live_session_is_reused_an_idle_one_replaced_and_none_opened() {
    let tree = a_tree(DeviceId::generate());
    let at = tree.on_device.last_used_at;

    assert_eq!(
        web_app_sign_in(Some(&tree.on_device), at + Duration::days(1)),
        WebAppSignIn::Reuse(tree.on_device.id)
    );
    assert_eq!(
        web_app_sign_in(Some(&tree.on_device), at + SESSION_IDLE),
        WebAppSignIn::Replace(tree.on_device.id)
    );
    assert_eq!(web_app_sign_in(None, at), WebAppSignIn::Open);
}
