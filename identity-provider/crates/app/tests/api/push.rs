//! A device asking to start over, then asking a code, wakes the approved device by a push notice
//! through the relay it named — what it says, and nothing of whom.

use std::time::Duration;

use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::approvals::Device;
use crate::helpers::another_browser;
use crate::helpers::spawn_app;
use crate::key_shares::first_device;
use crate::start_over::ask_to_start_over;

/// The notices the relay has heard, once there are `count`: they are sent in the background.
async fn heard(relay: &MockServer, count: usize) -> Vec<Value> {
    for _ in 0..200 {
        let received = relay.received_requests().await.unwrap();
        if received.len() >= count {
            return received
                .iter()
                .map(|request| serde_json::from_slice(&request.body).unwrap())
                .collect();
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("the relay heard fewer than {count} notices");
}

#[tokio::test]
async fn a_device_asking_to_start_over_then_a_code_wakes_the_approved_laptop() {
    let app = spawn_app().await;
    let relay = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/send"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "data": [{ "status": "ok", "id": "ticket" }] })),
        )
        .mount(&relay)
        .await;
    let (laptop, _) = first_device(&app).await;
    let (registered, body) = app
        .send(
            Method::PUT,
            &laptop.session,
            &format!("/api/keys/devices/{}/push", laptop.id),
            json!({ "relay": format!("{}/send", relay.uri()), "token": "ExponentPushToken[laptop]" }),
        )
        .await;
    let newcomer = Device::on(&app, another_browser(&app, &laptop.session).await).await;

    let (asked, _) = ask_to_start_over(&app, &newcomer).await;
    heard(&relay, 1).await;
    let (opened, _) = app
        .send(
            Method::POST,
            &newcomer.session,
            "/api/keys/devices/approval-requests",
            Value::Null,
        )
        .await;
    let notices = heard(&relay, 2).await;

    assert_eq!(registered, StatusCode::NO_CONTENT, "{body}");
    assert_eq!((asked, opened), (StatusCode::CREATED, StatusCode::CREATED));
    assert_eq!(
        notices[0],
        json!([{
            "to": "ExponentPushToken[laptop]",
            "title": "Start your history over?",
            "body": "Someone asked to start your history over. If it wasn't you, open Pīna'i to cancel it.",
            "tag": "start_over",
            "priority": "high",
            "ttl": 3600,
            "channelId": "sign-ins",
            "data": { "kind": "start_over" },
        }])
    );
    assert_eq!(
        (&notices[1][0]["title"], &notices[1][0]["tag"]),
        (&json!("Is this you?"), &json!("device_waiting"))
    );
    let said = serde_json::to_string(&notices).unwrap();
    for whom in [
        newcomer.id.to_string(),
        laptop.id.to_string(),
        "Web client".to_owned(),
    ] {
        assert!(!said.contains(&whom), "{said}");
    }
}
