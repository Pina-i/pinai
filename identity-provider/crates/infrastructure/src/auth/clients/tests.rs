use domain::auth::desktop_client;
use domain::identity::InstanceOrigin;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;

const DEVELOPMENT: UrlPolicy = UrlPolicy {
    require_https: false,
    allow_private_networks: true,
};

fn id_at(server: &MockServer) -> ClientId {
    ClientId::parse(&format!("{}/oauth-client.json", server.uri())).unwrap()
}

async fn serving(answer: ResponseTemplate, requests: u64) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth-client.json"))
        .respond_with(answer)
        .expect(requests)
        .mount(&server)
        .await;
    server
}

fn document(server_uri: &str) -> serde_json::Value {
    json!({
        "client_id": format!("{server_uri}/oauth-client.json"),
        "client_name": "Pīna'i",
        "redirect_uris": [format!("{server_uri}/callback")],
    })
}

#[test]
fn a_documents_max_age_is_kept_within_bounds() {
    for (header, kept) in [
        (None, MIN_TTL),
        (Some("max-age=3600"), Duration::from_secs(3600)),
        (Some("public, max-age=3600"), Duration::from_secs(3600)),
        (Some("max-age=60"), MIN_TTL),
        (Some("max-age=9999999"), MAX_TTL),
        (Some("no-store"), MIN_TTL),
        (Some("max-age=soon"), MIN_TTL),
    ] {
        assert_eq!(ttl_of(header), kept, "{header:?}");
    }
}

#[tokio::test]
async fn a_document_is_fetched_again_only_once_its_max_age_ran_out() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth-client.json"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("cache-control", "max-age=600")
                .set_body_json(document(&server.uri())),
        )
        .expect(2)
        .mount(&server)
        .await;
    let clients = MetadataClients::new(DEVELOPMENT, Vec::new());
    let id = id_at(&server);
    let start = Instant::now();

    for later in [0, 599, 601] {
        let found = clients
            .find_at(&id, start + Duration::from_secs(later))
            .await;
        assert!(found.is_some(), "{later} s on");
    }
}

#[tokio::test]
async fn a_document_that_couldnt_be_had_is_asked_again_after_a_minute() {
    let server = serving(ResponseTemplate::new(503), 2).await;
    let clients = MetadataClients::new(DEVELOPMENT, Vec::new());
    let id = id_at(&server);
    let start = Instant::now();

    for later in [0, 59, 61] {
        let found = clients
            .find_at(&id, start + Duration::from_secs(later))
            .await;
        assert!(found.is_none(), "{later} s on");
    }
}

#[tokio::test]
async fn the_desktop_app_is_described_here_and_never_fetched() {
    let desktop = desktop_client(&InstanceOrigin::parse("https://idp.alice.test").unwrap());
    let clients = MetadataClients::new(DEVELOPMENT, vec![desktop.clone()]);

    assert_eq!(clients.find(&desktop.id).await.unwrap(), Some(desktop));
}

#[test]
fn the_cache_drops_the_soonest_to_expire_once_full() {
    let clients = MetadataClients::new(DEVELOPMENT, Vec::new());
    let now = Instant::now();
    let id = |i: usize| ClientId::parse(&format!("https://app{i}.test/client.json")).unwrap();

    for i in 0..MAX_ENTRIES + 3 {
        clients.keep(&id(i), None, now + Duration::from_secs(60 + i as u64), now);
    }

    let cache = clients.cache.lock().unwrap();
    assert_eq!(cache.len(), MAX_ENTRIES);
    assert!((0..3).all(|i| !cache.contains_key(&id(i))));
    assert!(cache.contains_key(&id(MAX_ENTRIES + 2)));
}
