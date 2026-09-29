use std::sync::Arc;

use domain::identity::testing::{InMemoryAccounts, account, remote_actor};
use domain::identity::{Account, RemoteActor};
use domain::messaging::testing::InMemoryMessaging;
use domain::messaging::{Member, Role};
use domain::presence::AWAY_AFTER;
use domain::presence::testing::{
    InMemoryAudience, Pushed, RecordingBus, RecordingPeerStreams, RecordingPresenceNotifier,
    Relationships, Watch,
};
use time::Duration;

use super::*;

struct World {
    alice: Account,
    bob: Account,
    dave: Account,
    carol: RemoteActor,
    group: ConversationId,
    board: Arc<PresenceBoard>,
    bus: Arc<RecordingBus>,
    audience: Arc<InMemoryAudience>,
    notifier: Arc<RecordingPresenceNotifier>,
    streams: Arc<RecordingPeerStreams>,
    store: Arc<InMemoryMessaging>,
    connect: Connect,
    disconnect: Disconnect,
    heartbeat: Heartbeat,
    set: SetPresence,
    typing: StartTyping,
    sweep: SweepIdle,
    apply: ApplyPresence,
    deliver: DeliverTyping,
    read: ReadPresence,
    watch: WatchConversation,
}

fn start() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

fn member(actor: &ActorUri) -> Member {
    Member {
        actor_uri: actor.clone(),
        role: Role::Member,
    }
}

async fn world() -> World {
    let (alice, bob, dave) = (account("alice"), account("bob"), account("dave"));
    let carol = remote_actor("carol_k2m9x@idp.carol.test");
    let accounts = Arc::new(InMemoryAccounts::with([
        alice.clone(),
        bob.clone(),
        dave.clone(),
    ]));
    let store = Arc::new(InMemoryMessaging::default());
    let group = store
        .create_group(
            None,
            &[
                member(&alice.actor_uri),
                member(&bob.actor_uri),
                member(&carol.actor_uri),
            ],
        )
        .await
        .unwrap()
        .id;
    let tracker = Arc::new(ConnectionTracker::default());
    let board = Arc::new(PresenceBoard::default());
    let bus = Arc::new(RecordingBus::default());
    let audience = Arc::new(InMemoryAudience::default());
    let notifier = Arc::new(RecordingPresenceNotifier::default());
    let streams = Arc::new(RecordingPeerStreams::default());
    World {
        connect: Connect::new(accounts.clone(), tracker.clone(), bus.clone()),
        disconnect: Disconnect::new(tracker.clone(), bus.clone()),
        heartbeat: Heartbeat::new(tracker.clone(), board.clone(), bus.clone()),
        set: SetPresence::new(bus.clone()),
        typing: StartTyping::new(store.clone(), bus.clone()),
        sweep: SweepIdle::new(tracker.clone(), board.clone(), bus.clone()),
        apply: ApplyPresence::new(board.clone(), audience.clone(), notifier.clone()),
        deliver: DeliverTyping::new(accounts.clone(), store.clone(), notifier.clone()),
        read: ReadPresence::new(accounts, board.clone(), audience.clone()),
        watch: WatchConversation::new(
            InstanceOrigin::parse("http://localhost:8080").unwrap(),
            store.clone(),
            streams.clone(),
        ),
        alice,
        bob,
        dave,
        carol,
        group,
        board,
        bus,
        audience,
        notifier,
        streams,
        store,
    }
}

impl World {
    async fn session(&self, who: &Account, first: bool) -> Session {
        self.connect
            .execute(who.id, ConnectionId::generate(), first, start())
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn an_accounts_first_connection_brings_it_online_and_its_last_takes_it_offline() {
    let w = world().await;

    let first = w.session(&w.alice, true).await;
    let second = w.session(&w.alice, false).await;
    w.disconnect.execute(&second, false, start()).await.unwrap();
    w.disconnect.execute(&first, true, start()).await.unwrap();

    assert_eq!((first.user, &first.actor), (w.alice.id, &w.alice.actor_uri));
    assert_ne!(first.connection, second.connection);
    assert_eq!(
        w.bus.states(),
        vec![
            (w.alice.actor_uri.clone(), PresenceState::Online),
            (w.alice.actor_uri.clone(), PresenceState::Offline),
        ]
    );
}

#[tokio::test]
async fn a_heartbeat_brings_back_an_away_account_and_leaves_a_chosen_state() {
    let w = world().await;
    let session = w.session(&w.alice, false).await;

    w.board.set(&w.alice.actor_uri, PresenceState::Dnd);
    w.heartbeat.execute(&session, start()).await.unwrap();
    w.board.set(&w.alice.actor_uri, PresenceState::Away);
    w.heartbeat.execute(&session, start()).await.unwrap();

    assert_eq!(
        w.bus.states(),
        vec![(w.alice.actor_uri.clone(), PresenceState::Online)]
    );
}

#[tokio::test]
async fn a_heartbeat_keeps_a_connection_from_idling() {
    let w = world().await;
    let session = w.session(&w.alice, false).await;
    w.board.set(&w.alice.actor_uri, PresenceState::Online);

    w.heartbeat
        .execute(&session, start() + AWAY_AFTER)
        .await
        .unwrap();
    let swept = w
        .sweep
        .execute(start() + AWAY_AFTER + Duration::seconds(30))
        .await
        .unwrap();

    assert_eq!(swept, 0);
}

#[tokio::test]
async fn a_chosen_state_is_announced() {
    let w = world().await;
    let session = w.session(&w.alice, false).await;

    w.set
        .execute(&session, PresenceState::Dnd, start())
        .await
        .unwrap();

    assert_eq!(
        w.bus.states(),
        vec![(w.alice.actor_uri.clone(), PresenceState::Dnd)]
    );
}

#[tokio::test]
async fn typing_is_announced_for_its_conversation() {
    let w = world().await;
    let session = w.session(&w.alice, false).await;

    w.typing.execute(&session, w.group, start()).await.unwrap();

    assert_eq!(
        w.bus.published(),
        vec![Signal::Typing(TypingEvent {
            actor: w.alice.actor_uri.clone(),
            conversation: w.group,
            at: start(),
        })]
    );
}

#[tokio::test]
async fn an_idle_online_account_goes_away_and_a_chosen_state_stays() {
    let w = world().await;
    w.session(&w.alice, false).await;
    w.session(&w.bob, false).await;
    w.board.set(&w.alice.actor_uri, PresenceState::Online);
    w.board.set(&w.bob.actor_uri, PresenceState::Dnd);

    let swept = w
        .sweep
        .execute(start() + AWAY_AFTER + Duration::minutes(1))
        .await
        .unwrap();

    assert_eq!(swept, 1);
    assert_eq!(
        w.bus.states(),
        vec![(w.alice.actor_uri.clone(), PresenceState::Away)]
    );
}

#[tokio::test]
async fn a_state_heard_is_remembered_and_told_to_the_actors_friends_here() {
    let w = world().await;
    w.audience.befriend(&w.bob, &w.carol.actor_uri, true).await;
    w.audience
        .befriend(&w.dave, &w.carol.actor_uri, false)
        .await;
    let event = PresenceEvent {
        actor: w.carol.actor_uri.clone(),
        state: PresenceState::Away,
        at: start(),
    };

    w.apply.execute(&event).await.unwrap();

    assert_eq!(w.board.state(&w.carol.actor_uri), PresenceState::Away);
    assert_eq!(w.notifier.pushed(), vec![Pushed::Presence(w.bob.id, event)]);
}

#[tokio::test]
async fn typing_reaches_the_conversations_other_local_members() {
    let w = world().await;
    let event = TypingEvent {
        actor: w.alice.actor_uri.clone(),
        conversation: w.group,
        at: start(),
    };

    w.deliver.execute(&event).await.unwrap();

    assert_eq!(w.notifier.pushed(), vec![Pushed::Typing(w.bob.id, event)]);
}

#[tokio::test]
async fn presence_reads_real_only_for_the_viewer_its_friends_and_conversation_members() {
    let w = world().await;
    let stranger = remote_actor("erin_k2m9x@idp.erin.test").actor_uri;
    let friend = remote_actor("frank_k2m9x@idp.frank.test").actor_uri;
    w.audience.befriend(&w.alice, &friend, true).await;
    w.audience
        .converse(&[&w.alice.actor_uri, &w.carol.actor_uri])
        .await;
    for actor in [&w.alice.actor_uri, &w.carol.actor_uri, &friend, &stranger] {
        w.board.set(actor, PresenceState::Dnd);
    }

    let read = w
        .read
        .execute(
            w.alice.id,
            &[
                w.alice.actor_uri.clone(),
                w.carol.actor_uri.clone(),
                friend.clone(),
                stranger.clone(),
            ],
        )
        .await
        .unwrap();

    assert_eq!(
        read,
        vec![
            (w.alice.actor_uri.clone(), PresenceState::Dnd),
            (w.carol.actor_uri.clone(), PresenceState::Dnd),
            (friend, PresenceState::Dnd),
            (stranger, PresenceState::Offline),
        ]
    );
}

#[tokio::test]
async fn an_open_conversation_streams_its_remote_members_from_their_instances() {
    let w = world().await;
    let local_only = w
        .store
        .open_dm(&w.alice.actor_uri, &w.bob.actor_uri, None)
        .await
        .unwrap();

    w.watch.execute(w.group).await.unwrap();
    w.watch.execute(local_only).await.unwrap();
    w.watch.stop(w.group).await;

    let mut expected = std::collections::HashMap::new();
    expected.insert(
        w.carol.actor_uri.domain().clone(),
        vec![w.carol.actor_uri.clone()],
    );
    assert_eq!(
        w.streams.calls(),
        vec![Watch::Opened(w.group, expected), Watch::Closed(w.group)]
    );
}

#[tokio::test]
async fn typing_outside_a_conversation_is_never_announced() {
    let w = world().await;
    let outsider = w.session(&w.dave, false).await;

    let refused = w.typing.execute(&outsider, w.group, start()).await;

    assert!(
        matches!(refused, Err(PresenceError::NotAMember)),
        "{refused:?}"
    );
    assert!(w.bus.published().is_empty());
}

#[tokio::test]
async fn typing_heard_from_outside_a_conversation_reaches_nobody() {
    let w = world().await;
    let forged = TypingEvent {
        actor: remote_actor("eve_k2m9x@idp.eve.test").actor_uri,
        conversation: w.group,
        at: start(),
    };

    w.deliver.execute(&forged).await.unwrap();

    assert!(w.notifier.pushed().is_empty());
}

#[tokio::test]
async fn a_second_device_left_idle_keeps_an_active_account_online() {
    let w = world().await;
    let laptop = w.session(&w.alice, true).await;
    w.session(&w.alice, false).await;
    w.board.set(&w.alice.actor_uri, PresenceState::Online);

    w.heartbeat
        .execute(&laptop, start() + AWAY_AFTER)
        .await
        .unwrap();
    let swept = w
        .sweep
        .execute(start() + AWAY_AFTER + Duration::seconds(30))
        .await
        .unwrap();

    assert_eq!(swept, 0);
    assert_eq!(
        w.bus.states(),
        vec![(w.alice.actor_uri.clone(), PresenceState::Online)],
        "only the first connection's online"
    );
}
