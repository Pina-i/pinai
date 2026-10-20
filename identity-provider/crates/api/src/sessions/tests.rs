use axum::body::Body;
use axum::http::{Method, Request, header};
use domain::SessionId;
use domain::auth::RevokedReason;
use domain::identity::Account;
use domain::identity::testing::account;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::testing::TestApp;

use super::*;

struct World {
    app: TestApp,
    alice: Account,
    bob: Account,
}

fn world() -> World {
    let (alice, bob) = (account("alice"), account("bob"));
    World {
        app: TestApp::with([alice.clone(), bob.clone()], []),
        alice,
        bob,
    }
}

impl World {
    /// A request under one session of `who`'s.
    async fn as_session(
        &self,
        who: &Account,
        session: SessionId,
        method: Method,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", self.app.token_in(who.id, session)),
            )
            .header(header::CONTENT_TYPE, "application/json");
        let body = body.map_or_else(Body::empty, |body| Body::from(body.to_string()));
        self.app.send(request.body(body).unwrap()).await
    }

    /// A device of `who`'s, as its first KeyPackages name it.
    async fn device_of(&self, who: &Account) -> Uuid {
        let device = Uuid::new_v4();
        let packages = json!([{ "key_package": "AQIDBA==", "expires_at": (OffsetDateTime::now_utc() + time::Duration::days(7)).format(&time::format_description::well_known::Rfc3339).unwrap() }]);
        let (status, body) = self
            .app
            .call(
                Method::POST,
                "/api/keys/packages",
                Some(who.id),
                Some(json!({ "device_id": device, "packages": packages })),
            )
            .await;
        assert!(status.is_success(), "{status}: {body}");
        device
    }

    async fn link(&self, who: &Account, session: SessionId, device: Uuid) -> (StatusCode, Value) {
        self.as_session(
            who,
            session,
            Method::PUT,
            "/api/sessions/current/device",
            Some(json!({ "device_id": device })),
        )
        .await
    }

    async fn devices(&self, who: &Account, session: SessionId) -> Vec<Value> {
        let (_, body) = self
            .as_session(who, session, Method::GET, "/api/keys/devices", None)
            .await;
        body["devices"].as_array().unwrap().clone()
    }
}

#[tokio::test]
async fn a_session_links_its_device_which_then_lists_as_signed_in() {
    let w = world();
    let (laptop, phone) = (w.device_of(&w.alice).await, w.device_of(&w.alice).await);
    let session = w.app.sign_in.sessions.live(w.alice.id);

    let linked = w.link(&w.alice, session, laptop).await;
    let devices = w.devices(&w.alice, session).await;

    assert_eq!(linked, (StatusCode::NO_CONTENT, Value::Null));
    let row = |id: Uuid| {
        devices
            .iter()
            .find(|d| d["device_id"] == json!(id))
            .unwrap()
            .clone()
    };
    assert_eq!(row(laptop)["signed_in"], true);
    assert!(row(laptop)["last_active_at"].is_string());
    assert_eq!(
        (&row(phone)["signed_in"], &row(phone)["last_active_at"]),
        (&json!(false), &Value::Null)
    );
}

#[tokio::test]
async fn a_device_that_isnt_the_callers_or_was_revoked_is_refused() {
    let w = world();
    let bobs = w.device_of(&w.bob).await;
    let revoked = w.device_of(&w.alice).await;
    w.app
        .call(
            Method::POST,
            &format!("/api/keys/devices/{revoked}/revoke"),
            Some(w.alice.id),
            None,
        )
        .await;
    let session = w.app.sign_in.sessions.live(w.alice.id);

    for device in [bobs, revoked, Uuid::new_v4()] {
        assert_eq!(
            w.link(&w.alice, session, device).await,
            (
                StatusCode::FORBIDDEN,
                json!({
                    "error": "access_denied",
                    "error_description": "Not one of your devices, or revoked",
                })
            ),
            "{device}"
        );
    }
}

#[tokio::test]
async fn revoking_a_device_signs_it_out_at_once() {
    let w = world();
    let device = w.device_of(&w.alice).await;
    let (on_device, here) = (
        w.app.sign_in.sessions.live(w.alice.id),
        w.app.sign_in.sessions.live(w.alice.id),
    );
    w.link(&w.alice, on_device, device).await;

    let revoked = w
        .as_session(
            &w.alice,
            here,
            Method::POST,
            &format!("/api/keys/devices/{device}/revoke"),
            None,
        )
        .await;
    let (status, refused) = w
        .as_session(&w.alice, on_device, Method::GET, "/api/keys/devices", None)
        .await;

    assert_eq!(revoked.0, StatusCode::NO_CONTENT);
    assert_eq!(
        (status, refused["error_description"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("The session has ended"))
    );
    assert_eq!(
        w.app.sign_in.sessions.reason(on_device),
        Some(RevokedReason::DeviceRevoked)
    );
    assert_eq!(
        w.app.sign_in.ended.ended(),
        vec![on_device],
        "its sockets close"
    );
    let listed = w.devices(&w.alice, here).await;
    assert_eq!(listed[0]["signed_in"], false);
    assert!(listed[0]["revoked_at"].is_string());
}

#[tokio::test]
async fn signing_out_elsewhere_keeps_the_callers_session_only() {
    let w = world();
    let sessions = &w.app.sign_in.sessions;
    let (here, there, yonder) = (
        sessions.live(w.alice.id),
        sessions.live(w.alice.id),
        sessions.live(w.alice.id),
    );
    let bobs = sessions.live(w.bob.id);

    let without_keep = w
        .as_session(&w.alice, here, Method::DELETE, "/api/sessions", None)
        .await;
    let signed_out = w
        .as_session(
            &w.alice,
            here,
            Method::DELETE,
            "/api/sessions?keep=current",
            None,
        )
        .await;
    let (still, _) = w
        .as_session(&w.alice, here, Method::GET, "/api/keys/devices", None)
        .await;
    let (gone, _) = w
        .as_session(&w.alice, there, Method::GET, "/api/keys/devices", None)
        .await;

    assert_eq!(without_keep.0, StatusCode::BAD_REQUEST);
    assert_eq!(signed_out, (StatusCode::NO_CONTENT, Value::Null));
    assert_eq!((still, gone), (StatusCode::OK, StatusCode::UNAUTHORIZED));
    for ended in [there, yonder] {
        assert_eq!(
            sessions.reason(ended),
            Some(RevokedReason::SignedOutElsewhere)
        );
    }
    assert_eq!(sessions.reason(bobs), None);
}
