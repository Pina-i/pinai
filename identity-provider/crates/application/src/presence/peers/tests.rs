use domain::ConversationId;
use domain::identity::testing::{account, remote_actor};
use domain::identity::{Account, InstanceOrigin};
use domain::presence::TypingEvent;
use domain::presence::testing::{
    InMemoryAudience, QueuedFeed, RecordingBus, Relationships, ScriptedPeers,
};

use super::*;

struct Peers {
    alice: Account,
    bob: Account,
    carol: ActorUri,
    erin: ActorUri,
    dave: ActorUri,
    board: Arc<PresenceBoard>,
    bus: Arc<RecordingBus>,
    audience: Arc<InMemoryAudience>,
    feed: Arc<QueuedFeed>,
    peers: Arc<ScriptedPeers>,
    targets: Arc<PollTargets>,
    serve: ServePeerPresence,
    open: OpenPeerStream,
    poll: PollPeers,
    receive: ReceivePeerSignal,
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

fn origin() -> InstanceOrigin {
    InstanceOrigin::parse("http://localhost:8080").unwrap()
}

fn peers() -> Peers {
    let board = Arc::new(PresenceBoard::default());
    let bus = Arc::new(RecordingBus::default());
    let audience = Arc::new(InMemoryAudience::default());
    let feed = Arc::new(QueuedFeed::default());
    let peers = Arc::new(ScriptedPeers::default());
    let targets = Arc::new(PollTargets::new(origin()));
    Peers {
        alice: account("alice"),
        bob: account("bob"),
        carol: remote_actor("carol_k2m9x@idp.carol.test").actor_uri,
        erin: remote_actor("erin_k2m9x@idp.carol.test").actor_uri,
        dave: remote_actor("dave_k2m9x@idp.dave.test").actor_uri,
        serve: ServePeerPresence::new(origin(), board.clone(), audience.clone()),
        open: OpenPeerStream::new(origin(), board.clone(), audience.clone(), feed.clone()),
        poll: PollPeers::new(
            targets.clone(),
            audience.clone(),
            peers.clone(),
            board.clone(),
            bus.clone(),
        ),
        receive: ReceivePeerSignal::new(bus.clone()),
        board,
        bus,
        audience,
        feed,
        peers,
        targets,
    }
}

fn presence(actor: &ActorUri, state: PresenceState) -> Signal {
    Signal::Presence(PresenceEvent {
        actor: actor.clone(),
        state,
        at: now(),
    })
}

fn typing(actor: &ActorUri, conversation: ConversationId) -> Signal {
    Signal::Typing(TypingEvent {
        actor: actor.clone(),
        conversation,
        at: now(),
    })
}

#[tokio::test]
async fn a_peer_reads_the_states_of_the_accounts_its_users_know() {
    let p = peers();
    p.audience.converse(&[&p.alice.actor_uri, &p.carol]).await;
    p.audience.befriend(&p.bob, &p.erin, true).await;
    p.board.set(&p.alice.actor_uri, PresenceState::Dnd);
    p.board.set(&p.bob.actor_uri, PresenceState::Online);

    let states = p
        .serve
        .execute(
            p.carol.domain(),
            &[p.alice.actor_uri.clone(), p.bob.actor_uri.clone()],
        )
        .await
        .unwrap();

    assert_eq!(
        states,
        vec![
            (p.alice.actor_uri.clone(), PresenceState::Dnd),
            (p.bob.actor_uri.clone(), PresenceState::Online),
        ]
    );
}

#[tokio::test]
async fn a_peers_stream_replays_the_states_heard_then_carries_its_accounts_signals() {
    let p = peers();
    let dm = p.audience.converse(&[&p.alice.actor_uri, &p.carol]).await;
    p.board.set(&p.alice.actor_uri, PresenceState::Away);
    for signal in [
        presence(&p.alice.actor_uri, PresenceState::Online),
        presence(&p.dave, PresenceState::Online),
        typing(&p.carol, dm),
        typing(&p.alice.actor_uri, dm),
    ] {
        p.feed.queue(signal);
    }

    let stream = p
        .open
        .execute(
            p.carol.domain(),
            &[p.alice.actor_uri.clone(), p.bob.actor_uri.clone()],
            now(),
        )
        .await
        .unwrap();
    let live: Vec<Signal> = stream.live.collect().await;

    assert_eq!(
        stream.replay,
        vec![PresenceEvent {
            actor: p.alice.actor_uri.clone(),
            state: PresenceState::Away,
            at: now(),
        }]
    );
    assert_eq!(
        live,
        vec![
            presence(&p.alice.actor_uri, PresenceState::Online),
            typing(&p.alice.actor_uri, dm),
        ]
    );
}

#[tokio::test]
async fn startup_polls_every_remote_friend_of_a_local_account() {
    let p = peers();
    p.audience.befriend(&p.alice, &p.carol, true).await;
    p.audience.befriend(&p.alice, &p.bob.actor_uri, true).await;
    p.audience.befriend(&p.bob, &p.dave, false).await;

    let polled = p.poll.prime().await.unwrap();

    assert_eq!(polled, 1);
    assert_eq!(
        p.targets.snapshot(),
        [(p.carol.domain().clone(), vec![p.carol.clone()])].into()
    );
}

#[tokio::test]
async fn a_poll_announces_only_the_states_that_changed() {
    let p = peers();
    p.targets.watch(&p.carol);
    p.targets.watch(&p.erin);
    p.board.set(&p.carol, PresenceState::Online);
    p.peers.answer(
        p.carol.domain(),
        &[
            (&p.carol, PresenceState::Online),
            (&p.erin, PresenceState::Away),
        ],
    );

    let outcome = p.poll.execute(now()).await;

    assert_eq!(outcome.changed, 1);
    assert!(outcome.failed.is_empty());
    assert_eq!(p.board.state(&p.erin), PresenceState::Away);
    assert_eq!(p.bus.states(), vec![(p.erin.clone(), PresenceState::Away)]);
    let mut asked = vec![p.carol.clone(), p.erin.clone()];
    asked.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    assert_eq!(p.peers.asked(), vec![(p.carol.domain().clone(), asked)]);
}

#[tokio::test]
async fn a_peer_that_does_not_answer_is_reported_and_the_others_are_still_heard() {
    let p = peers();
    p.targets.watch(&p.carol);
    p.targets.watch(&p.dave);
    p.peers
        .answer(p.carol.domain(), &[(&p.carol, PresenceState::Dnd)]);

    let outcome = p.poll.execute(now()).await;

    let failed: Vec<&Domain> = outcome.failed.iter().map(|(peer, _)| peer).collect();
    assert_eq!(failed, vec![p.dave.domain()]);
    assert_eq!(p.board.state(&p.carol), PresenceState::Dnd);
}

#[tokio::test]
async fn a_signal_a_peer_streams_goes_onto_the_bus() {
    let p = peers();
    let signal = presence(&p.carol, PresenceState::Away);

    p.receive.execute(p.carol.domain(), &signal).await.unwrap();

    assert_eq!(p.bus.published(), vec![signal]);
}

#[tokio::test]
async fn a_peer_reads_offline_for_accounts_none_of_its_users_knows_and_for_other_instances() {
    let p = peers();
    p.audience.converse(&[&p.alice.actor_uri, &p.carol]).await;
    p.board.set(&p.alice.actor_uri, PresenceState::Dnd);
    p.board.set(&p.bob.actor_uri, PresenceState::Online);
    p.board.set(&p.dave, PresenceState::Away);

    let states = p
        .serve
        .execute(
            p.carol.domain(),
            &[
                p.alice.actor_uri.clone(),
                p.bob.actor_uri.clone(),
                p.dave.clone(),
            ],
        )
        .await
        .unwrap();

    assert_eq!(
        states,
        vec![
            (p.alice.actor_uri.clone(), PresenceState::Dnd),
            (p.bob.actor_uri.clone(), PresenceState::Offline),
            (p.dave.clone(), PresenceState::Offline),
        ]
    );
}

#[tokio::test]
async fn a_peers_stream_leaves_out_what_none_of_its_users_may_see() {
    let p = peers();
    let dm = p.audience.converse(&[&p.alice.actor_uri, &p.carol]).await;
    let ours = p
        .audience
        .converse(&[&p.alice.actor_uri, &p.bob.actor_uri, &p.dave])
        .await;
    p.board.set(&p.bob.actor_uri, PresenceState::Online);
    p.board.set(&p.dave, PresenceState::Online);
    for signal in [
        presence(&p.bob.actor_uri, PresenceState::Away),
        presence(&p.dave, PresenceState::Away),
        typing(&p.alice.actor_uri, ours),
        typing(&p.alice.actor_uri, dm),
    ] {
        p.feed.queue(signal);
    }

    let stream = p
        .open
        .execute(
            p.carol.domain(),
            &[
                p.alice.actor_uri.clone(),
                p.bob.actor_uri.clone(),
                p.dave.clone(),
            ],
            now(),
        )
        .await
        .unwrap();
    let live: Vec<Signal> = stream.live.collect().await;

    assert!(stream.replay.is_empty(), "{:?}", stream.replay);
    assert_eq!(live, vec![typing(&p.alice.actor_uri, dm)]);
}

#[tokio::test]
async fn a_peer_telling_of_another_instances_actors_is_not_heard() {
    let p = peers();
    let dm = ConversationId::generate();

    for signal in [
        presence(&p.dave, PresenceState::Online),
        presence(&p.alice.actor_uri, PresenceState::Offline),
        typing(&p.dave, dm),
        typing(&p.erin, dm),
    ] {
        p.receive.execute(p.carol.domain(), &signal).await.unwrap();
    }

    assert_eq!(p.bus.published(), vec![typing(&p.erin, dm)]);
}

#[tokio::test]
async fn a_peers_answer_counts_only_for_the_accounts_it_was_asked_about() {
    let p = peers();
    p.targets.watch(&p.carol);
    p.peers.answer(
        p.carol.domain(),
        &[
            (&p.carol, PresenceState::Online),
            (&p.erin, PresenceState::Away),
            (&p.dave, PresenceState::Away),
            (&p.alice.actor_uri, PresenceState::Away),
        ],
    );

    let outcome = p.poll.execute(now()).await;

    assert_eq!(outcome.changed, 1);
    assert_eq!(
        p.bus.states(),
        vec![(p.carol.clone(), PresenceState::Online)]
    );
    assert_eq!(p.board.heard(&p.erin), None);
    assert_eq!(p.board.heard(&p.dave), None);
    assert_eq!(p.board.heard(&p.alice.actor_uri), None);
}

/// Answers every poll a second later: everyone asked is online.
struct SlowPeers;

#[async_trait::async_trait]
impl PeerPresence for SlowPeers {
    async fn poll(
        &self,
        _: &Domain,
        actors: &[ActorUri],
    ) -> Result<Vec<(ActorUri, PresenceState)>, PresenceError> {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        Ok(actors
            .iter()
            .map(|actor| (actor.clone(), PresenceState::Online))
            .collect())
    }
}

#[tokio::test(start_paused = true)]
async fn peers_are_polled_side_by_side_so_a_slow_one_holds_up_no_other() {
    let p = peers();
    let frank = remote_actor("frank_k2m9x@idp.frank.test").actor_uri;
    for actor in [&p.carol, &p.dave, &frank] {
        p.targets.watch(actor);
    }
    let poll = PollPeers::new(
        p.targets.clone(),
        p.audience.clone(),
        Arc::new(SlowPeers),
        p.board.clone(),
        p.bus.clone(),
    );
    let started = tokio::time::Instant::now();

    let outcome = poll.execute(now()).await;

    assert_eq!(outcome.changed, 3);
    assert_eq!(started.elapsed(), std::time::Duration::from_secs(1));
}
