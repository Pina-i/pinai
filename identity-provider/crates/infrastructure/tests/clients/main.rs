//! `MetadataClients` against documents served by wiremock.

use domain::auth::testing::{ClientSeeds, contract};
use domain::auth::{ClientDocument, ClientId, Clients};
use federation_transport::UrlPolicy;
use infrastructure::auth::MetadataClients;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const DEVELOPMENT: UrlPolicy = UrlPolicy {
    require_https: false,
    allow_private_networks: true,
};
const PRODUCTION: UrlPolicy = UrlPolicy {
    require_https: true,
    allow_private_networks: false,
};

struct Published(MockServer);

#[async_trait::async_trait]
impl ClientSeeds for Published {
    fn origin(&self) -> String {
        self.0.uri()
    }

    async fn publish(&self, at: &str, document: &ClientDocument) {
        Mock::given(method("GET"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(200).set_body_json(document))
            .mount(&self.0)
            .await;
    }
}

async fn found(server: &MockServer, policy: UrlPolicy) -> bool {
    let id = ClientId::parse(&format!("{}/oauth-client.json", server.uri())).unwrap();
    MetadataClients::new(policy, Vec::new())
        .find(&id)
        .await
        .unwrap()
        .is_some()
}

async fn answering(answer: ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth-client.json"))
        .respond_with(answer)
        .mount(&server)
        .await;
    server
}

fn document(origin: &str) -> serde_json::Value {
    json!({
        "client_id": format!("{origin}/oauth-client.json"),
        "redirect_uris": [format!("{origin}/callback")],
    })
}

#[tokio::test]
async fn a_published_client_is_found_by_its_url() {
    let seeds = Published(MockServer::start().await);

    contract::a_published_client_is_found_by_its_url(
        &MetadataClients::new(DEVELOPMENT, Vec::new()),
        &seeds,
    )
    .await;
}

#[tokio::test]
async fn a_redirect_is_never_followed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth-client.json"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/elsewhere.json"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/elsewhere.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(document(&server.uri())))
        .expect(0)
        .mount(&server)
        .await;

    assert!(!found(&server, DEVELOPMENT).await);
}

#[tokio::test]
async fn a_document_over_5_kib_is_refused() {
    let server = MockServer::start().await;
    let mut oversized = document(&server.uri());
    oversized["padding"] = json!("x".repeat(6 * 1024));
    Mock::given(method("GET"))
        .and(path("/oauth-client.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(oversized))
        .mount(&server)
        .await;

    assert!(!found(&server, DEVELOPMENT).await);
}

#[tokio::test]
async fn a_document_breaking_a_rule_or_missing_is_refused() {
    let elsewhere = {
        let server = MockServer::start().await;
        let mut lying = document(&server.uri());
        lying["redirect_uris"] = json!(["https://evil.test/callback"]);
        Mock::given(method("GET"))
            .and(path("/oauth-client.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(lying))
            .mount(&server)
            .await;
        server
    };
    let missing = answering(ResponseTemplate::new(404)).await;
    let garbled = answering(ResponseTemplate::new(200).set_body_string("<html>")).await;

    for server in [&elsewhere, &missing, &garbled] {
        assert!(!found(server, DEVELOPMENT).await, "{}", server.uri());
    }
}

#[tokio::test]
async fn a_production_instance_never_fetches_a_private_address() {
    let id = ClientId::parse("https://127.0.0.1/oauth-client.json").unwrap();

    let client = MetadataClients::new(PRODUCTION, Vec::new())
        .find(&id)
        .await
        .unwrap();

    assert_eq!(client, None);
}

#[tokio::test]
async fn only_a_development_instance_takes_a_plain_http_client() {
    let local = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth-client.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(document(&local.uri())))
        .mount(&local)
        .await;

    assert!(found(&local, DEVELOPMENT).await);
    assert!(!found(&local, PRODUCTION).await);
}
