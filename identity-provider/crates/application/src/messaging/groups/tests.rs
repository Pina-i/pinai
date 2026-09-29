use std::sync::Arc;

use domain::ConversationId;
use domain::identity::testing::{InMemoryAccounts, InMemoryRemoteActors, account, remote_actor};
use domain::identity::{Account, ActorUri, RemoteActor};
use domain::messaging::testing::{GroupNotice, InMemoryMessaging, RecordingGroupNotifier};
use domain::messaging::{ConversationKind, Conversations, GroupName, Member, MessagingError, Role};

use super::*;

struct World {
    alice: Account,
    bob: Account,
    eve: Account,
    carol: RemoteActor,
    accounts: Arc<InMemoryAccounts>,
    remote_actors: Arc<InMemoryRemoteActors>,
    store: Arc<InMemoryMessaging>,
    notifier: Arc<RecordingGroupNotifier>,
}

/// Alice, Bob and Eve here; Carol on another instance.
fn world() -> World {
    let (alice, bob, eve) = (account("alice"), account("bob"), account("eve"));
    let carol = remote_actor("carol_k2m9x@idp.carol.test");
    World {
        accounts: Arc::new(InMemoryAccounts::with([
            alice.clone(),
            bob.clone(),
            eve.clone(),
        ])),
        remote_actors: Arc::new(InMemoryRemoteActors::with([carol.clone()])),
        alice,
        bob,
        eve,
        carol,
        store: Arc::new(InMemoryMessaging::default()),
        notifier: Arc::new(RecordingGroupNotifier::default()),
    }
}

fn member(actor_uri: &ActorUri, role: Role) -> Member {
    Member {
        actor_uri: actor_uri.clone(),
        role,
    }
}

/// "crew": Alice (admin), Bob and Carol; Eve is not in it. Nothing announced yet.
async fn crew(w: &World) -> ConversationId {
    let roster = [
        member(&w.alice.actor_uri, Role::Admin),
        member(&w.bob.actor_uri, Role::Member),
        member(&w.carol.actor_uri, Role::Member),
    ];
    let name = GroupName::parse("crew").unwrap();
    w.store.create_group(Some(&name), &roster).await.unwrap().id
}

fn create(w: &World) -> CreateGroup {
    CreateGroup::new(
        w.accounts.clone(),
        w.remote_actors.clone(),
        w.store.clone(),
        w.notifier.clone(),
    )
}

fn add(w: &World) -> AddGroupMember {
    AddGroupMember::new(
        w.accounts.clone(),
        w.remote_actors.clone(),
        w.store.clone(),
        w.notifier.clone(),
    )
}

fn remove(w: &World) -> RemoveGroupMember {
    RemoveGroupMember::new(w.accounts.clone(), w.store.clone(), w.notifier.clone())
}

fn rename(w: &World) -> RenameGroup {
    RenameGroup::new(
        w.accounts.clone(),
        w.remote_actors.clone(),
        w.store.clone(),
        w.notifier.clone(),
    )
}

fn set_role(w: &World) -> SetMemberRole {
    SetMemberRole::new(
        w.accounts.clone(),
        w.remote_actors.clone(),
        w.store.clone(),
        w.notifier.clone(),
    )
}

fn names(members: &[MemberProfile]) -> Vec<(Option<&str>, Role)> {
    members
        .iter()
        .map(|p| (p.display_name.as_deref(), p.member.role))
        .collect()
}

#[tokio::test]
async fn a_new_group_has_its_creator_as_admin_and_is_announced_to_its_local_members() {
    let w = world();

    let view = create(&w)
        .execute(
            w.alice.id,
            Some(GroupName::parse("crew").unwrap()),
            vec![
                w.bob.actor_uri.clone(),
                w.carol.actor_uri.clone(),
                w.alice.actor_uri.clone(),
            ],
        )
        .await
        .unwrap();

    let group = &view.group;
    assert_eq!(
        (group.kind, group.name.as_deref()),
        (ConversationKind::Group, Some("crew"))
    );
    assert_eq!(
        names(&view.members),
        vec![
            (Some("alice"), Role::Admin),
            (Some("bob"), Role::Member),
            (Some("carol_k2m9x"), Role::Member),
        ]
    );
    assert_eq!(
        w.notifier.sent(),
        vec![
            GroupNotice::Joined(w.alice.id, group.id, w.alice.actor_uri.clone()),
            GroupNotice::Joined(w.bob.id, group.id, w.alice.actor_uri.clone()),
        ],
        "carol's own instance announces it to her"
    );
}

#[tokio::test]
async fn a_group_with_nobody_invited_is_refused() {
    let w = world();

    let refused = create(&w).execute(w.alice.id, None, Vec::new()).await;

    assert!(matches!(refused, Err(MessagingError::GroupNeedsMembers)));
}

#[tokio::test]
async fn a_member_lists_the_group_with_names_and_roles_and_an_outsider_cannot() {
    let w = world();
    let group = crew(&w).await;
    let list = ListGroupMembers::new(w.accounts.clone(), w.remote_actors.clone(), w.store.clone());

    let members = list.execute(w.bob.id, group).await.unwrap();
    let outsider = list.execute(w.eve.id, group).await;

    assert_eq!(
        names(&members),
        vec![
            (Some("alice"), Role::Admin),
            (Some("bob"), Role::Member),
            (Some("carol_k2m9x"), Role::Member),
        ]
    );
    assert!(matches!(
        outsider,
        Err(MessagingError::ConversationNotFound)
    ));
}

#[tokio::test]
async fn an_admin_adds_a_member_and_every_local_member_is_told() {
    let w = world();
    let group = crew(&w).await;

    let added = add(&w)
        .execute(w.alice.id, group, w.eve.actor_uri.clone())
        .await
        .unwrap();

    let eve = member(&w.eve.actor_uri, Role::Member);
    assert_eq!(
        (added.member.clone(), added.display_name.as_deref()),
        (eve.clone(), Some("eve"))
    );
    let told: Vec<_> = [&w.alice, &w.bob, &w.eve]
        .iter()
        .map(|a| GroupNotice::MemberAdded(a.id, group, eve.clone(), w.alice.actor_uri.clone()))
        .collect();
    assert_eq!(w.notifier.sent(), told);
}

#[tokio::test]
async fn only_an_admin_manages_a_group() {
    let w = world();
    let group = crew(&w).await;
    let name = || GroupName::parse("ours").unwrap();

    for (who, expected) in [(&w.bob, "NotAnAdmin"), (&w.eve, "ConversationNotFound")] {
        let outcomes = [
            add(&w)
                .execute(who.id, group, w.eve.actor_uri.clone())
                .await
                .map(|_| ()),
            remove(&w)
                .execute(who.id, group, w.alice.actor_uri.clone())
                .await,
            rename(&w).execute(who.id, group, name()).await.map(|_| ()),
            set_role(&w)
                .execute(who.id, group, w.bob.actor_uri.clone(), Role::Admin)
                .await
                .map(|_| ()),
        ];
        for outcome in outcomes {
            assert_eq!(
                outcome.map_err(|e| format!("{e:?}")),
                Err(expected.to_owned())
            );
        }
    }
    assert!(w.notifier.sent().is_empty());
}

#[tokio::test]
async fn a_removed_member_and_everyone_who_was_in_the_group_are_told() {
    let w = world();
    let group = crew(&w).await;

    remove(&w)
        .execute(w.alice.id, group, w.bob.actor_uri.clone())
        .await
        .unwrap();

    assert_eq!(
        w.notifier.sent(),
        [&w.alice, &w.bob]
            .iter()
            .map(|a| GroupNotice::MemberRemoved(
                a.id,
                group,
                w.bob.actor_uri.clone(),
                Some(w.alice.actor_uri.clone())
            ))
            .collect::<Vec<_>>()
    );
    assert_eq!(w.store.members(group).await.unwrap().len(), 2);
}

#[tokio::test]
async fn a_member_leaves_on_their_own() {
    let w = world();
    let group = crew(&w).await;

    remove(&w)
        .execute(w.bob.id, group, w.bob.actor_uri.clone())
        .await
        .unwrap();

    assert!(w.notifier.sent().contains(&GroupNotice::MemberRemoved(
        w.alice.id,
        group,
        w.bob.actor_uri.clone(),
        None
    )));
}

#[tokio::test]
async fn removing_someone_outside_the_group_is_refused() {
    let w = world();
    let group = crew(&w).await;

    let refused = remove(&w)
        .execute(w.alice.id, group, w.eve.actor_uri.clone())
        .await;

    assert!(matches!(refused, Err(MessagingError::MemberNotFound)));
}

#[tokio::test]
async fn an_admin_renames_the_group_and_its_local_members_are_told() {
    let w = world();
    let group = crew(&w).await;

    let view = rename(&w)
        .execute(w.alice.id, group, GroupName::parse("new crew").unwrap())
        .await
        .unwrap();

    assert_eq!(view.group.name.as_deref(), Some("new crew"));
    assert_eq!(view.members.len(), 3);
    assert_eq!(
        w.notifier.sent(),
        [&w.alice, &w.bob]
            .iter()
            .map(|a| GroupNotice::Renamed(
                a.id,
                group,
                Some("new crew".to_owned()),
                w.alice.actor_uri.clone()
            ))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn an_admin_changes_a_role_and_its_local_members_are_told() {
    let w = world();
    let group = crew(&w).await;

    let promoted = set_role(&w)
        .execute(w.alice.id, group, w.bob.actor_uri.clone(), Role::Admin)
        .await
        .unwrap();

    let bob = member(&w.bob.actor_uri, Role::Admin);
    assert_eq!(promoted.member, bob);
    assert_eq!(
        w.notifier.sent(),
        [&w.alice, &w.bob]
            .iter()
            .map(|a| GroupNotice::RoleChanged(a.id, group, bob.clone(), w.alice.actor_uri.clone()))
            .collect::<Vec<_>>()
    );
    let outsider = set_role(&w)
        .execute(w.alice.id, group, w.eve.actor_uri.clone(), Role::Admin)
        .await;
    assert!(matches!(outsider, Err(MessagingError::MemberNotFound)));
}

#[tokio::test]
async fn a_dm_is_managed_by_no_group_route() {
    let w = world();
    let dm = w
        .store
        .open_dm(&w.alice.actor_uri, &w.bob.actor_uri, None)
        .await
        .unwrap();
    let list = ListGroupMembers::new(w.accounts.clone(), w.remote_actors.clone(), w.store.clone());

    let outcomes = [
        list.execute(w.alice.id, dm).await.map(|_| ()),
        add(&w)
            .execute(w.alice.id, dm, w.eve.actor_uri.clone())
            .await
            .map(|_| ()),
        remove(&w)
            .execute(w.alice.id, dm, w.alice.actor_uri.clone())
            .await,
        rename(&w)
            .execute(w.alice.id, dm, GroupName::parse("ours").unwrap())
            .await
            .map(|_| ()),
        set_role(&w)
            .execute(w.alice.id, dm, w.bob.actor_uri.clone(), Role::Admin)
            .await
            .map(|_| ()),
    ];

    for outcome in outcomes {
        assert_eq!(
            outcome.map_err(|e| format!("{e:?}")),
            Err("ConversationNotFound".to_owned())
        );
    }
    assert_eq!(
        w.store.members(dm).await.unwrap().len(),
        2,
        "nobody left the DM"
    );
}

#[tokio::test]
async fn the_last_admin_neither_leaves_nor_is_demoted_while_others_remain() {
    let w = world();
    let group = crew(&w).await;

    let leaving = remove(&w)
        .execute(w.alice.id, group, w.alice.actor_uri.clone())
        .await;
    let demoted = set_role(&w)
        .execute(w.alice.id, group, w.alice.actor_uri.clone(), Role::Member)
        .await;

    assert!(
        matches!(leaving, Err(MessagingError::LastAdmin)),
        "{leaving:?}"
    );
    assert!(
        matches!(demoted, Err(MessagingError::LastAdmin)),
        "{:?}",
        demoted.map(|p| p.member)
    );
    assert!(
        w.store
            .members(group)
            .await
            .unwrap()
            .contains(&member(&w.alice.actor_uri, Role::Admin))
    );
    assert!(w.notifier.sent().is_empty());
}

#[tokio::test]
async fn an_admin_steps_down_once_another_is_promoted() {
    let w = world();
    let group = crew(&w).await;
    set_role(&w)
        .execute(w.alice.id, group, w.bob.actor_uri.clone(), Role::Admin)
        .await
        .unwrap();

    remove(&w)
        .execute(w.alice.id, group, w.alice.actor_uri.clone())
        .await
        .unwrap();

    assert_eq!(w.store.members(group).await.unwrap().len(), 2);
}

#[tokio::test]
async fn adding_someone_already_in_the_group_is_refused_and_keeps_their_role() {
    let w = world();
    let group = crew(&w).await;

    let refused = add(&w)
        .execute(w.alice.id, group, w.alice.actor_uri.clone())
        .await;

    assert!(
        matches!(refused, Err(MessagingError::AlreadyAMember)),
        "{:?}",
        refused.map(|p| p.member)
    );
    assert!(
        w.store
            .members(group)
            .await
            .unwrap()
            .contains(&member(&w.alice.actor_uri, Role::Admin)),
        "still an admin"
    );
    assert!(w.notifier.sent().is_empty());
}

#[tokio::test]
async fn a_member_who_left_can_be_added_back() {
    let w = world();
    let group = crew(&w).await;
    remove(&w)
        .execute(w.bob.id, group, w.bob.actor_uri.clone())
        .await
        .unwrap();

    let back = add(&w)
        .execute(w.alice.id, group, w.bob.actor_uri.clone())
        .await
        .unwrap();

    assert_eq!(back.member, member(&w.bob.actor_uri, Role::Member));
}
