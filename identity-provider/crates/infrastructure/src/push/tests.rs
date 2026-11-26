use domain::e2ee::{PushRelay, PushToken};
use serde_json::Value;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;

/// What a development instance allows: the relay on this machine.
fn here() -> UrlPolicy {
    UrlPolicy {
        require_https: false,
        allow_private_networks: true,
    }
}

fn registration(relay: &str) -> PushRegistration {
    PushRegistration {
        relay: PushRelay::parse(relay).unwrap(),
        token: PushToken::parse("ExponentPushToken[phone]").unwrap(),
    }
}

async fn relay_answering(answer: ResponseTemplate) -> MockServer {
    let relay = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/--/api/v2/push/send"))
        .respond_with(answer)
        .mount(&relay)
        .await;
    relay
}

fn ticket(ticket: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({ "data": [ticket] }))
}

async fn send_to(relay: &MockServer, notice: PushNotice) -> anyhow::Result<Delivery> {
    ExpoRelays::new(here())
        .send(
            &registration(&format!("{}/--/api/v2/push/send", relay.uri())),
            notice,
        )
        .await
}

#[tokio::test]
async fn a_notice_goes_as_one_expo_message_with_its_fixed_words() {
    let relay = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/--/api/v2/push/send"))
        .and(header("content-type", "application/json"))
        .and(body_json(json!([{
            "to": "ExponentPushToken[phone]",
            "title": "Start your history over?",
            "body": "Someone asked to start your history over. If it wasn't you, open Pīna'i to cancel it.",
            "tag": "start_over",
            "priority": "high",
            "ttl": 3600,
            "channelId": "sign-ins",
            "data": { "kind": "start_over" },
        }])))
        .respond_with(ticket(json!({ "status": "ok", "id": "XXXX" })))
        .expect(1)
        .mount(&relay)
        .await;

    let sent = send_to(&relay, PushNotice::StartOver).await.unwrap();

    assert_eq!(sent, Delivery::Sent);
}

#[tokio::test]
async fn a_token_the_relay_no_longer_reaches_is_gone() {
    let relay = relay_answering(ticket(json!({
        "status": "error",
        "message": "\"ExponentPushToken[phone]\" is not a registered push notification recipient",
        "details": { "error": "DeviceNotRegistered" },
    })))
    .await;

    let gone = send_to(&relay, PushNotice::DeviceWaiting).await.unwrap();

    assert_eq!(gone, Delivery::Gone);
}

#[tokio::test]
async fn a_refusal_is_told_by_its_code_or_status_never_with_the_token() {
    let refusing = relay_answering(ticket(json!({
        "status": "error",
        "message": "\"ExponentPushToken[phone]\" is too big",
        "details": { "error": "MessageTooBig" },
    })))
    .await;
    let failing = relay_answering(
        ResponseTemplate::new(400)
            .set_body_string("ExponentPushToken[phone] belongs to another project"),
    )
    .await;

    let refused = send_to(&refusing, PushNotice::DeviceWaiting).await;
    let failed = send_to(&failing, PushNotice::DeviceWaiting).await;

    for error in [refused, failed] {
        let told = format!("{:#}", error.unwrap_err());
        assert!(!told.contains("ExponentPushToken"), "{told}");
        assert!(
            told.contains("MessageTooBig") || told.contains("400"),
            "{told}"
        );
    }
}

#[tokio::test]
async fn a_relay_in_private_space_is_refused_in_production() {
    let relay = relay_answering(ticket(json!({ "status": "ok" }))).await;
    let production = UrlPolicy::from_issuer("https://idp.example.org");
    let on_this_machine = registration(&format!(
        "https://127.0.0.1:{}/--/api/v2/push/send",
        relay.address().port()
    ));

    let refused = ExpoRelays::new(production)
        .send(&on_this_machine, PushNotice::DeviceWaiting)
        .await;

    assert!(refused.is_err());
    assert!(relay.received_requests().await.unwrap().is_empty());
}
