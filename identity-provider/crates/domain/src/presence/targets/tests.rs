use crate::identity::testing::{account, remote_actor};

use super::*;

fn targets() -> PollTargets {
    PollTargets::new(InstanceOrigin::parse("http://localhost:8080").unwrap())
}

#[test]
fn remote_friends_are_polled_by_instance_and_local_ones_never() {
    let targets = targets();
    let (carol, dave, erin) = (
        remote_actor("carol_k2m9x@idp.carol.test").actor_uri,
        remote_actor("dave_k2m9x@idp.carol.test").actor_uri,
        remote_actor("erin_k2m9x@idp.erin.test").actor_uri,
    );
    for friend in [&carol, &dave, &erin, &carol, &account("alice").actor_uri] {
        targets.watch(friend);
    }

    let mut snapshot = targets.snapshot();
    for actors in snapshot.values_mut() {
        actors.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    }

    assert_eq!(snapshot.len(), 2);
    assert_eq!(snapshot[carol.domain()], vec![carol.clone(), dave]);
    assert_eq!(snapshot[erin.domain()], vec![erin]);
}

#[test]
fn a_released_friend_is_no_longer_polled_nor_its_emptied_instance() {
    let targets = targets();
    let (carol, erin) = (
        remote_actor("carol_k2m9x@idp.carol.test").actor_uri,
        remote_actor("erin_k2m9x@idp.erin.test").actor_uri,
    );
    targets.watch(&carol);
    targets.watch(&erin);

    targets.release(&erin);
    targets.release(&remote_actor("nobody_k2m9x@idp.nowhere.test").actor_uri);

    assert_eq!(
        targets.snapshot(),
        [(carol.domain().clone(), vec![carol])].into()
    );
}
