use domain::{SessionId, UserId};
use time::OffsetDateTime;

use super::*;

#[test]
fn a_session_ended_closes_its_sockets() {
    let hub = Arc::new(Hub::new());
    let now = OffsetDateTime::now_utc();
    let session = Session {
        id: SessionId::generate(),
        user: UserId::generate(),
        kind: domain::auth::SessionKind::Browser,
        device: None,
        created_at: now,
        last_used_at: now,
        authenticated_at: now,
        revoked_at: Some(now),
    };
    let (_, socket, _) = hub.subscribe(session.user.as_uuid(), session.id.as_uuid());

    HubSessionNotifier::new(hub.clone()).ended(&session);

    assert!(socket.ended().is_cancelled());
}
