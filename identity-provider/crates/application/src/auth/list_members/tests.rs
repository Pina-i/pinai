use domain::auth::testing::{seeded_actor, signed_up};
use domain::auth::{SessionKind, Sessions, SignInAccount};
use domain::presence::PresenceState;
use time::Duration;

use crate::auth::world::{now, world};

use super::*;

#[tokio::test]
async fn only_an_admin_lists_the_members() {
    let w = world().await;

    for caller in [w.alice.id, UserId::generate()] {
        let listed = w.list_members.execute(caller, now()).await;

        assert!(matches!(listed, Err(AuthError::NotAdmin)), "{listed:?}");
    }
}

#[tokio::test]
async fn each_member_is_online_while_the_presence_board_says_it_is_around() {
    let w = world().await;
    let admin = w.an_admin().await;
    let (bob, carol, dave) = (signed_up("bob"), signed_up("carol"), signed_up("dave"));
    for account in [&bob, &carol, &dave] {
        w.sign_up(account).await;
    }
    let hours_ago = |hours| now() - Duration::hours(hours);
    for (account, last_used) in [
        (&w.alice, hours_ago(1)),
        (&admin, hours_ago(2)),
        (&bob, hours_ago(3)),
        (&carol, hours_ago(4)),
    ] {
        w.sessions
            .open(account.id, &SessionKind::Browser, last_used)
            .await
            .unwrap();
    }
    let heard = |account: &SignInAccount, state| w.board.set(&seeded_actor(account), state);
    heard(&w.alice, PresenceState::Online);
    heard(&admin, PresenceState::Away);
    heard(&bob, PresenceState::Dnd);
    // Invisible.
    heard(&carol, PresenceState::Offline);

    let listed = w.list_members.execute(admin.id, now()).await.unwrap();

    assert_eq!(
        listed
            .iter()
            .map(|member| (member.display_name.as_deref().unwrap(), member.online))
            .collect::<Vec<_>>(),
        vec![
            ("alice", true),
            ("root", true),
            ("bob", true),
            ("carol", false),
            ("dave", false),
        ]
    );
    assert_eq!(
        listed[0],
        ListedMember {
            id: w.alice.id,
            display_name: Some("alice".to_owned()),
            admin: false,
            last_active_at: Some(hours_ago(1)),
            online: true,
        }
    );
    assert!(listed[1].admin);
    assert_eq!(listed[4].last_active_at, None, "dave never signed in");
}
