use std::sync::Arc;

use domain::identity::testing::{InMemoryAccounts, InMemoryRemoteActors, account, remote_actor};
use domain::identity::{Account, ActorUri, InstanceOrigin, RemoteActor};
use domain::messaging::testing::{
    Announced, GroupNotice, InMemoryMessaging, RecordingGroupFederation, RecordingGroupNotifier,
};
use domain::messaging::{
    ConversationKind, Conversations, GroupChange, GroupChangeKind, GroupName, MAX_MEMBERS, Member,
    MessagingError, Role,
};
use domain::social::testing::{BLOCKED, KEPT_OUT_BY_THE_SETTING, StubReachability};
use domain::{ConversationId, UserId};

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
    federation: Arc<RecordingGroupFederation>,
    reach: Arc<StubReachability>,
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
        federation: Arc::new(RecordingGroupFederation::default()),
        reach: Arc::new(StubReachability::default()),
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
        InstanceOrigin::parse("http://localhost:8080").unwrap(),
        w.accounts.clone(),
        w.remote_actors.clone(),
        w.store.clone(),
        w.reach.clone(),
        w.notifier.clone(),
        w.store.clone(),
    )
}

fn add(w: &World) -> AddGroupMember {
    AddGroupMember::new(
        InstanceOrigin::parse("http://localhost:8080").unwrap(),
        w.accounts.clone(),
        w.remote_actors.clone(),
        w.store.clone(),
        w.reach.clone(),
        w.notifier.clone(),
        w.federation.clone(),
        w.store.clone(),
    )
}

fn remove(w: &World) -> RemoveGroupMember {
    RemoveGroupMember::new(
        w.accounts.clone(),
        w.remote_actors.clone(),
        w.store.clone(),
        w.notifier.clone(),
        w.federation.clone(),
        w.store.clone(),
    )
}

fn rename(w: &World) -> RenameGroup {
    RenameGroup::new(
        w.accounts.clone(),
        w.remote_actors.clone(),
        w.store.clone(),
        w.notifier.clone(),
        w.federation.clone(),
        w.store.clone(),
    )
}

fn set_role(w: &World) -> SetMemberRole {
    SetMemberRole::new(
        w.accounts.clone(),
        w.remote_actors.clone(),
        w.store.clone(),
        w.notifier.clone(),
        w.federation.clone(),
        w.store.clone(),
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
    let departure = w.store.departure(group, &w.bob.actor_uri).await.unwrap();
    assert_eq!(
        departure.and_then(|d| d.removed_by),
        Some(w.alice.actor_uri.clone()),
        "kept for bob's list"
    );
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
    let departure = w.store.departure(group, &w.bob.actor_uri).await.unwrap();
    assert_eq!(departure.map(|d| d.removed_by), Some(None));
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

impl World {
    async fn groups_of(&self, account: &Account) -> usize {
        self.store
            .list_for(account.id, &account.actor_uri)
            .await
            .unwrap()
            .len()
    }
}

/// Alice must not tell Bob's block from his setting, and nobody gets a group half made.
#[tokio::test]
async fn a_group_with_a_local_invitee_who_does_not_admit_the_creator_is_refused_whole() {
    let mut refusals = Vec::new();
    for kept_out in [BLOCKED, KEPT_OUT_BY_THE_SETTING] {
        let w = world();
        w.reach.set(w.bob.id, &w.alice.actor_uri, kept_out);

        let refused = create(&w)
            .execute(
                w.alice.id,
                None,
                vec![w.carol.actor_uri.clone(), w.bob.actor_uri.clone()],
            )
            .await;

        refusals.push(format!("{:?}", refused.map(|_| ())));
        assert_eq!(w.groups_of(&w.alice).await, 0);
        assert!(w.notifier.sent().is_empty());
    }
    assert_eq!(
        refusals,
        vec![format!("Err(CannotAdd({:?}))", account("bob").actor_uri); 2]
    );
}

#[tokio::test]
async fn a_group_with_someone_the_creator_blocked_is_refused() {
    let w = world();
    w.reach.set(w.alice.id, &w.carol.actor_uri, BLOCKED);

    let refused = create(&w)
        .execute(
            w.alice.id,
            None,
            vec![w.bob.actor_uri.clone(), w.carol.actor_uri.clone()],
        )
        .await;

    assert!(
        matches!(&refused, Err(MessagingError::YouBlockedInvitee(a)) if *a == w.carol.actor_uri),
        "{:?}",
        refused.map(|_| ())
    );
    assert_eq!(w.groups_of(&w.alice).await, 0);
}

#[tokio::test]
async fn a_creator_naming_themselves_is_no_invitee() {
    let w = world();
    w.reach
        .set(w.alice.id, &w.alice.actor_uri, KEPT_OUT_BY_THE_SETTING);

    let created = create(&w)
        .execute(
            w.alice.id,
            None,
            vec![w.alice.actor_uri.clone(), w.bob.actor_uri.clone()],
        )
        .await;

    assert!(created.is_ok());
}

#[tokio::test]
async fn adding_someone_who_does_not_admit_the_admin_or_whom_they_blocked_is_refused() {
    let mut w = world();
    let dave_there = remote_actor("dave_k2m9x@idp.dave.test");
    w.remote_actors = Arc::new(InMemoryRemoteActors::with([w.carol.clone(), dave_there]));
    let id = crew(&w).await;
    w.reach
        .set(w.eve.id, &w.alice.actor_uri, KEPT_OUT_BY_THE_SETTING);

    let refused = add(&w)
        .execute(w.alice.id, id, w.eve.actor_uri.clone())
        .await;

    assert!(
        matches!(&refused, Err(MessagingError::CannotAdd(a)) if *a == w.eve.actor_uri),
        "{:?}",
        refused.map(|_| ())
    );
    let dave = ActorUri::parse("https://idp.dave.test/users/dave_k2m9x").unwrap();
    w.reach.set(w.alice.id, &dave, BLOCKED);
    let refused = add(&w).execute(w.alice.id, id, dave.clone()).await;
    assert!(
        matches!(&refused, Err(MessagingError::YouBlockedInvitee(a)) if *a == dave),
        "{:?}",
        refused.map(|_| ())
    );
    let members = w.store.members(id).await.unwrap();
    assert_eq!(members.len(), 3, "nobody added");
    assert!(w.notifier.sent().is_empty());
}

/// Someone's existence, and their name, come from their own instance — never from this one's
/// cache, which would tell who here has met whom.
#[tokio::test]
async fn an_invitee_who_names_no_account_is_refused_and_nothing_written() {
    let mut w = world();
    let gone = remote_actor("gone_k2m9x@idp.gone.test");
    w.remote_actors =
        Arc::new(InMemoryRemoteActors::with([w.carol.clone()]).and_cached_only([gone.clone()]));
    let nobody_here = ActorUri::parse("http://localhost:8080/users/nobody_t3st0").unwrap();
    let nobody_there = ActorUri::parse("https://idp.dave.test/users/dave_k2m9x").unwrap();
    let not_its_id = ActorUri::parse("http://idp.carol.test/users/carol_k2m9x").unwrap();

    for invitee in [
        nobody_here,
        nobody_there,
        gone.actor_uri.clone(),
        not_its_id,
    ] {
        let refused = create(&w)
            .execute(
                w.alice.id,
                None,
                vec![w.bob.actor_uri.clone(), invitee.clone()],
            )
            .await;

        assert!(
            matches!(&refused, Err(MessagingError::InviteeNotFound(a)) if *a == invitee),
            "{invitee}: {:?}",
            refused.map(|_| ())
        );
    }
    assert_eq!(w.groups_of(&w.alice).await, 0);
    let id = crew(&w).await;
    let refused = add(&w)
        .execute(w.alice.id, id, gone.actor_uri.clone())
        .await;
    assert!(
        matches!(&refused, Err(MessagingError::InviteeNotFound(_))),
        "{:?}",
        refused.map(|_| ())
    );
}

#[tokio::test]
async fn an_invitee_whose_instance_does_not_answer_is_refused_naming_them() {
    let mut w = world();
    w.remote_actors =
        Arc::new(InMemoryRemoteActors::with([w.carol.clone()]).and_down("idp.down.test"));
    let down = ActorUri::parse("https://idp.down.test/users/dave_k2m9x").unwrap();

    let refused = create(&w)
        .execute(
            w.alice.id,
            None,
            vec![w.bob.actor_uri.clone(), down.clone()],
        )
        .await;

    assert!(
        matches!(&refused, Err(MessagingError::InviteeUnavailable(a)) if *a == down),
        "{:?}",
        refused.map(|_| ())
    );
    assert_eq!(w.groups_of(&w.alice).await, 0);
}

/// Accounts their own instances know and this one never met: each costs a lookup to add.
fn strangers(count: usize) -> Vec<RemoteActor> {
    (0..count)
        .map(|i| remote_actor(&format!("guest{i}_k2m9x@idp.guests.test")))
        .collect()
}

fn uris(actors: &[RemoteActor]) -> Vec<ActorUri> {
    actors.iter().map(|a| a.actor_uri.clone()).collect()
}

#[tokio::test]
async fn a_group_of_fifty_is_created_and_a_bigger_one_refused_before_anyone_is_looked_up() {
    let guests = strangers(MAX_MEMBERS);
    let w = World {
        remote_actors: Arc::new(InMemoryRemoteActors::default().and_uncached(guests.clone())),
        ..world()
    };

    let refused = create(&w).execute(w.alice.id, None, uris(&guests)).await;
    assert!(
        matches!(refused, Err(MessagingError::TooManyMembers(MAX_MEMBERS))),
        "{refused:?}"
    );
    assert_eq!(w.remote_actors.lookups(), 0);

    let view = create(&w)
        .execute(w.alice.id, None, uris(&guests[1..]))
        .await
        .unwrap();
    assert_eq!(view.members.len(), MAX_MEMBERS);
}

#[tokio::test]
async fn a_full_group_takes_nobody_more_before_anyone_is_looked_up() {
    let w = world();
    let mut roster = vec![member(&w.alice.actor_uri, Role::Admin)];
    roster.extend(
        strangers(MAX_MEMBERS - 1)
            .iter()
            .map(|g| member(&g.actor_uri, Role::Member)),
    );
    let group = w.store.create_group(None, &roster).await.unwrap().id;

    let refused = add(&w)
        .execute(w.alice.id, group, w.carol.actor_uri.clone())
        .await;
    assert!(
        matches!(refused, Err(MessagingError::GroupFull(MAX_MEMBERS))),
        "{refused:?}"
    );
    assert_eq!(w.remote_actors.lookups(), 0);

    w.store
        .remove_member(group, &roster[1].actor_uri, None, None)
        .await
        .unwrap();
    add(&w)
        .execute(w.alice.id, group, w.carol.actor_uri.clone())
        .await
        .unwrap();
}

fn dismiss(w: &World) -> DismissGroup {
    DismissGroup::new(w.accounts.clone(), w.store.clone())
}

#[tokio::test]
async fn someone_removed_from_a_group_clears_it_from_their_list_once() {
    let w = world();
    let group = crew(&w).await;
    remove(&w)
        .execute(w.alice.id, group, w.bob.actor_uri.clone())
        .await
        .unwrap();

    dismiss(&w).execute(w.bob.id, group).await.unwrap();

    assert!(
        w.store
            .list_for(w.bob.id, &w.bob.actor_uri)
            .await
            .unwrap()
            .is_empty()
    );
    let again = dismiss(&w).execute(w.bob.id, group).await;
    assert!(
        matches!(again, Err(MessagingError::ConversationNotFound)),
        "{again:?}"
    );
}

#[tokio::test]
async fn only_someone_removed_from_a_group_clears_it() {
    let w = world();
    let group = crew(&w).await;
    let dm = w
        .store
        .open_dm(&w.alice.actor_uri, &w.eve.actor_uri, None)
        .await
        .unwrap();
    remove(&w)
        .execute(w.bob.id, group, w.bob.actor_uri.clone())
        .await
        .unwrap();

    let member = dismiss(&w).execute(w.alice.id, group).await;
    assert!(
        matches!(member, Err(MessagingError::StillAMember)),
        "{member:?}"
    );
    for (who, conversation) in [(&w.bob, group), (&w.eve, group), (&w.eve, dm)] {
        let refused = dismiss(&w).execute(who.id, conversation).await;
        assert!(
            matches!(refused, Err(MessagingError::ConversationNotFound)),
            "{refused:?}: one who left, a stranger, a DM"
        );
    }
}

fn dave() -> RemoteActor {
    remote_actor("dave_k2m9x@idp.dave.test")
}

/// The stamp this copy holds for `actor`'s membership.
async fn membership(
    w: &World,
    group: ConversationId,
    actor: &ActorUri,
) -> domain::messaging::Membership {
    w.store
        .memberships(group)
        .await
        .unwrap()
        .into_iter()
        .find(|m| &m.member.actor_uri == actor)
        .unwrap()
}

fn sent(w: &World) -> Announced {
    w.federation.sent().last().cloned().expect("a change sent")
}

#[tokio::test]
async fn each_change_made_here_goes_to_the_remote_members_with_its_stamp() {
    let w = World {
        remote_actors: Arc::new(InMemoryRemoteActors::with([
            remote_actor("carol_k2m9x@idp.carol.test"),
            dave(),
        ])),
        ..world()
    };
    let group = crew(&w).await;
    let (carol, dave) = (w.carol.actor_uri.clone(), dave().actor_uri);
    let by_alice = |at, kind| GroupChange {
        group,
        by: w.alice.actor_uri.clone(),
        at,
        kind,
    };

    add(&w)
        .execute(w.alice.id, group, dave.clone())
        .await
        .unwrap();
    let joined = membership(&w, group, &dave).await.joined_at;
    assert_eq!(
        sent(&w),
        Announced {
            from: w.alice.actor_uri.clone(),
            to: vec![carol.clone(), dave.clone()],
            change: by_alice(joined, GroupChangeKind::Added(dave.clone())),
        }
    );

    set_role(&w)
        .execute(w.alice.id, group, w.bob.actor_uri.clone(), Role::Admin)
        .await
        .unwrap();
    let promoted = membership(&w, group, &w.bob.actor_uri).await.role_at;
    assert_eq!(
        sent(&w).change,
        by_alice(
            promoted,
            GroupChangeKind::RoleChanged(w.bob.actor_uri.clone(), Role::Admin)
        )
    );

    let name = GroupName::parse("new crew").unwrap();
    let renamed = rename(&w)
        .execute(w.alice.id, group, name.clone())
        .await
        .unwrap();
    assert_eq!(
        sent(&w).change,
        by_alice(renamed.group.name_at, GroupChangeKind::Renamed(name))
    );

    remove(&w)
        .execute(w.alice.id, group, carol.clone())
        .await
        .unwrap();
    let removed = w.store.departure(group, &carol).await.unwrap().unwrap();
    assert_eq!(
        sent(&w),
        Announced {
            from: w.alice.actor_uri.clone(),
            to: vec![carol.clone(), dave.clone()],
            change: by_alice(removed.left_at, GroupChangeKind::Removed(carol)),
        },
        "the member removed is told too"
    );

    remove(&w)
        .execute(w.bob.id, group, w.bob.actor_uri.clone())
        .await
        .unwrap();
    let left = w
        .store
        .departure(group, &w.bob.actor_uri)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        sent(&w),
        Announced {
            from: w.bob.actor_uri.clone(),
            to: vec![dave],
            change: GroupChange {
                group,
                by: w.bob.actor_uri.clone(),
                at: left.left_at,
                kind: GroupChangeKind::Left,
            },
        }
    );
}

#[tokio::test]
async fn a_change_to_a_group_held_only_here_goes_nowhere() {
    let w = world();
    let roster = [
        member(&w.alice.actor_uri, Role::Admin),
        member(&w.bob.actor_uri, Role::Member),
    ];
    let group = w.store.create_group(None, &roster).await.unwrap().id;

    rename(&w)
        .execute(w.alice.id, group, GroupName::parse("crew").unwrap())
        .await
        .unwrap();

    assert!(w.federation.sent().is_empty());
}

fn receive(w: &World) -> ReceiveGroupChange {
    ReceiveGroupChange::new(
        w.accounts.clone(),
        w.remote_actors.clone(),
        w.store.clone(),
        w.reach.clone(),
        w.notifier.clone(),
        w.store.clone(),
    )
}

/// A group another instance holds too: Carol, there, administers it; Alice and Bob are in it.
async fn carols(w: &World) -> ConversationId {
    let roster = [
        member(&w.carol.actor_uri, Role::Admin),
        member(&w.alice.actor_uri, Role::Member),
        member(&w.bob.actor_uri, Role::Member),
    ];
    let name = GroupName::parse("crew").unwrap();
    w.store.create_group(Some(&name), &roster).await.unwrap().id
}

fn by(actor: &ActorUri, group: ConversationId, kind: GroupChangeKind) -> GroupChange {
    GroupChange {
        group,
        by: actor.clone(),
        at: time::OffsetDateTime::now_utc() + time::Duration::minutes(1),
        kind,
    }
}

#[tokio::test]
async fn a_removal_made_elsewhere_takes_the_member_out_here_keeping_the_group_for_them() {
    let w = world();
    let group = carols(&w).await;
    let removal = by(
        &w.carol.actor_uri,
        group,
        GroupChangeKind::Removed(w.bob.actor_uri.clone()),
    );

    for _ in 0..2 {
        receive(&w)
            .execute(w.bob.id, removal.clone())
            .await
            .unwrap();
    }

    let departure = w.store.departure(group, &w.bob.actor_uri).await.unwrap();
    assert_eq!(
        departure.map(|d| (d.left_at, d.removed_by)),
        Some((removal.at, Some(w.carol.actor_uri.clone())))
    );
    let bobs = w.store.list_for(w.bob.id, &w.bob.actor_uri).await.unwrap();
    assert!(bobs[0].removed_at.is_some(), "kept, marked, in bob's list");
    assert_eq!(
        w.notifier.sent(),
        [&w.alice, &w.bob]
            .iter()
            .map(|a| GroupNotice::MemberRemoved(
                a.id,
                group,
                w.bob.actor_uri.clone(),
                Some(w.carol.actor_uri.clone())
            ))
            .collect::<Vec<_>>(),
        "once: the second delivery is stale"
    );
}

#[tokio::test]
async fn a_change_its_maker_may_not_make_or_through_a_stranger_changes_nothing() {
    let w = world();
    let group = carols(&w).await;
    let remove_bob = GroupChangeKind::Removed(w.bob.actor_uri.clone());

    for (inbox, change) in [
        (w.alice.id, by(&dave().actor_uri, group, remove_bob.clone())),
        (
            w.alice.id,
            by(&w.alice.actor_uri, group, remove_bob.clone()),
        ),
        (w.eve.id, by(&w.carol.actor_uri, group, remove_bob.clone())),
        (
            w.alice.id,
            by(
                &w.carol.actor_uri,
                ConversationId::generate(),
                remove_bob.clone(),
            ),
        ),
        (
            w.alice.id,
            GroupChange {
                at: time::OffsetDateTime::UNIX_EPOCH,
                ..by(&w.carol.actor_uri, group, remove_bob.clone())
            },
        ),
    ] {
        receive(&w).execute(inbox, change.clone()).await.unwrap();

        assert_eq!(w.store.members(group).await.unwrap().len(), 3, "{change:?}");
    }
    assert!(w.notifier.sent().is_empty());
}

#[tokio::test]
async fn an_add_made_elsewhere_brings_the_member_in_and_tells_everyone_here() {
    let w = world();
    let group = carols(&w).await;

    receive(&w)
        .execute(
            w.alice.id,
            by(
                &w.carol.actor_uri,
                group,
                GroupChangeKind::Added(dave().actor_uri),
            ),
        )
        .await
        .unwrap();
    receive(&w)
        .execute(
            w.eve.id,
            by(
                &w.carol.actor_uri,
                group,
                GroupChangeKind::Added(w.eve.actor_uri.clone()),
            ),
        )
        .await
        .unwrap();

    assert_eq!(w.store.members(group).await.unwrap().len(), 5);
    let sent = w.notifier.sent();
    let dave_added = |to: &Account| {
        GroupNotice::MemberAdded(
            to.id,
            group,
            member(&dave().actor_uri, Role::Member),
            w.carol.actor_uri.clone(),
        )
    };
    assert!(sent.contains(&dave_added(&w.alice)) && sent.contains(&dave_added(&w.bob)));
    assert!(
        sent.contains(&GroupNotice::Joined(
            w.eve.id,
            group,
            w.carol.actor_uri.clone()
        )),
        "{sent:?}"
    );
}

#[tokio::test]
async fn a_leave_a_rename_and_a_role_made_elsewhere_are_taken() {
    let w = world();
    let group = carols(&w).await;
    let carol = w.carol.actor_uri.clone();

    for change in [
        by(
            &carol,
            group,
            GroupChangeKind::RoleChanged(w.alice.actor_uri.clone(), Role::Admin),
        ),
        by(
            &carol,
            group,
            GroupChangeKind::Renamed(GroupName::parse("new crew").unwrap()),
        ),
        by(&carol, group, GroupChangeKind::Left),
    ] {
        receive(&w).execute(w.alice.id, change).await.unwrap();
    }

    assert_eq!(
        w.store.members(group).await.unwrap(),
        vec![
            member(&w.alice.actor_uri, Role::Admin),
            member(&w.bob.actor_uri, Role::Member)
        ]
    );
    let group = w.store.find(group).await.unwrap().unwrap();
    assert_eq!(group.name.as_deref(), Some("new crew"));
    assert!(w.notifier.sent().contains(&GroupNotice::MemberRemoved(
        w.bob.id,
        group.id,
        carol.clone(),
        None
    )));
}

#[tokio::test]
async fn an_add_made_elsewhere_brings_in_no_account_here_who_does_not_admit_its_maker() {
    for kept_out in [KEPT_OUT_BY_THE_SETTING, BLOCKED] {
        let w = world();
        let group = carols(&w).await;
        w.reach.set(w.eve.id, &w.carol.actor_uri, kept_out);
        let add = by(
            &w.carol.actor_uri,
            group,
            GroupChangeKind::Added(w.eve.actor_uri.clone()),
        );

        // Through a member's inbox, and through her own.
        for inbox in [w.alice.id, w.eve.id] {
            receive(&w).execute(inbox, add.clone()).await.unwrap();
        }

        assert!(
            !w.store
                .members(group)
                .await
                .unwrap()
                .iter()
                .any(|m| m.actor_uri == w.eve.actor_uri)
        );
        assert!(w.notifier.sent().is_empty(), "{:?}", w.notifier.sent());
        assert!(lines(&w, group).await.is_empty());
    }
}

#[tokio::test]
async fn an_add_of_someone_already_in_the_group_only_moves_their_stamp() {
    let w = world();
    let group = carols(&w).await;
    let added = by(
        &w.carol.actor_uri,
        group,
        GroupChangeKind::Added(w.bob.actor_uri.clone()),
    );

    receive(&w)
        .execute(w.alice.id, added.clone())
        .await
        .unwrap();

    assert_eq!(
        membership(&w, group, &w.bob.actor_uri).await.joined_at,
        added.at
    );
    assert!(w.notifier.sent().is_empty(), "nobody joined");
}

/// What `group`'s conversation shows, oldest first: each event's kind and subject.
async fn lines(w: &World, group: ConversationId) -> Vec<(&'static str, Option<ActorUri>)> {
    use domain::messaging::{EventWindow, GroupEvents};
    let window = EventWindow {
        since: time::OffsetDateTime::UNIX_EPOCH,
        until: None,
    };
    let mut page = GroupEvents::page(&*w.store, group, None, window, 100)
        .await
        .unwrap();
    page.reverse();
    page.iter()
        .map(|e| (e.kind_name(), e.subject().cloned()))
        .collect()
}

#[tokio::test]
async fn each_change_made_here_adds_its_line_for_the_members_who_see_it() {
    let w = World {
        remote_actors: Arc::new(InMemoryRemoteActors::with([
            remote_actor("carol_k2m9x@idp.carol.test"),
            dave(),
        ])),
        ..world()
    };
    let group = create(&w)
        .execute(
            w.alice.id,
            Some(GroupName::parse("crew").unwrap()),
            vec![w.bob.actor_uri.clone(), w.carol.actor_uri.clone()],
        )
        .await
        .unwrap()
        .group
        .id;
    let dave = dave().actor_uri;

    add(&w)
        .execute(w.alice.id, group, dave.clone())
        .await
        .unwrap();
    rename(&w)
        .execute(w.alice.id, group, GroupName::parse("new crew").unwrap())
        .await
        .unwrap();
    set_role(&w)
        .execute(w.alice.id, group, dave.clone(), Role::Admin)
        .await
        .unwrap();
    remove(&w)
        .execute(w.alice.id, group, w.bob.actor_uri.clone())
        .await
        .unwrap();

    assert_eq!(
        lines(&w, group).await,
        vec![
            ("created", None),
            ("added", Some(dave.clone())),
            ("renamed", None),
            ("role_changed", Some(dave)),
            ("removed", Some(w.bob.actor_uri.clone())),
        ]
    );
    let told: Vec<(UserId, &'static str)> = w
        .notifier
        .events()
        .iter()
        .map(|(to, named)| (*to, named.event.kind_name()))
        .collect();
    assert!(
        told.contains(&(w.bob.id, "removed")) && told.contains(&(w.alice.id, "removed")),
        "the member removed sees their removal: {told:?}"
    );
    assert_eq!(told.len(), 10, "alice and bob, each line once: {told:?}");
    let (_, removal) = w.notifier.events().last().cloned().unwrap();
    assert_eq!(
        (removal.by_name.as_deref(), removal.subject_name.as_deref()),
        (Some("alice"), Some("bob"))
    );
}

#[tokio::test]
async fn a_change_from_elsewhere_adds_its_line_once_taken_and_none_when_not() {
    let w = world();
    let group = carols(&w).await;
    let removal = by(
        &w.carol.actor_uri,
        group,
        GroupChangeKind::Removed(w.bob.actor_uri.clone()),
    );

    receive(&w)
        .execute(
            w.alice.id,
            by(&dave().actor_uri, group, removal.kind.clone()),
        )
        .await
        .unwrap();
    for _ in 0..2 {
        receive(&w)
            .execute(w.alice.id, removal.clone())
            .await
            .unwrap();
    }

    receive(&w)
        .execute(
            w.alice.id,
            by(
                &w.carol.actor_uri,
                group,
                GroupChangeKind::Added(dave().actor_uri),
            ),
        )
        .await
        .unwrap();

    assert_eq!(
        lines(&w, group).await,
        vec![
            ("removed", Some(w.bob.actor_uri.clone())),
            ("added", Some(dave().actor_uri))
        ]
    );
}
