use axum::body::Body;
use axum::http::{Method, Request, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use domain::e2ee::testing::plain_signature;
use domain::identity::testing::{account, remote_actor};
use domain::identity::{Account, ActorUri};
use domain::social::testing::{BLOCKED, KEPT_OUT_BY_THE_SETTING};
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;

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

fn refusal(code: &str, description: &str) -> Value {
    json!({ "error": code, "error_description": description })
}

fn in_days(days: i64) -> String {
    (OffsetDateTime::now_utc() + time::Duration::days(days))
        .format(&Rfc3339)
        .unwrap()
}

fn packages(n: u8) -> Value {
    Value::Array(
        (1..=n)
            .map(|i| json!({ "key_package": B64.encode([i; 8]), "expires_at": in_days(7) }))
            .collect(),
    )
}

fn peer() -> ActorUri {
    ActorUri::parse("https://idp.carol.test/actor").unwrap()
}

impl World {
    async fn register(&self, who: &Account, device: Uuid, key: &str) -> (StatusCode, Value) {
        self.app
            .call(
                Method::POST,
                "/api/keys/devices",
                Some(who.id),
                Some(json!({ "device_id": device, "drk_public_key": key })),
            )
            .await
    }

    async fn register_with(&self, who: &Account, body: Value) -> (StatusCode, Value) {
        self.app
            .call(Method::POST, "/api/keys/devices", Some(who.id), Some(body))
            .await
    }

    async fn devices(&self, who: &Account) -> Vec<Value> {
        let (status, body) = self
            .app
            .call(Method::GET, "/api/keys/devices", Some(who.id), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["devices"]
            .as_array()
            .expect("a list of devices")
            .clone()
    }

    async fn upload(&self, who: &Account, device: Uuid, packages: Value) -> (StatusCode, Value) {
        self.app
            .call(
                Method::POST,
                "/api/keys/packages",
                Some(who.id),
                Some(json!({ "device_id": device, "packages": packages })),
            )
            .await
    }

    async fn claim(&self, who: &Account, body: Value) -> (StatusCode, Value) {
        self.app
            .call(
                Method::POST,
                "/api/keys/packages/claim",
                Some(who.id),
                Some(body),
            )
            .await
    }
}

fn b64(value: &Value) -> Vec<u8> {
    B64.decode(value.as_str().expect("a base64 string"))
        .unwrap()
}

fn time(value: &Value) -> OffsetDateTime {
    OffsetDateTime::parse(value.as_str().expect("an RFC 3339 string"), &Rfc3339).unwrap()
}

/// Base64 of the fake verifier's signature by root key `[root; 32]` over the HPKE key
/// `[byte; 32]` of `owner`'s `device`.
fn hpke_signature(owner: &Account, device: Uuid, root: u8, byte: u8) -> String {
    let message = HpkePublicKey::parse(&[byte; 32])
        .unwrap()
        .canonical_bytes(&owner.actor_uri, device.into());
    let root = DeviceRootKey::parse(&[root; 32]).unwrap();
    B64.encode(plain_signature(&root, &message).as_bytes())
}

#[tokio::test]
async fn a_device_registers_its_root_key_and_gets_the_signed_attestation() {
    let w = world();

    let (status, body) = w
        .register(&w.alice, Uuid::new_v4(), &B64.encode([7; 32]))
        .await;

    assert_eq!(status, StatusCode::CREATED, "{body}");
    let signed_message = b64(&body["signed_message"]);
    assert_eq!(
        b64(&body["signature"]),
        signed_message.iter().rev().copied().collect::<Vec<_>>(),
        "the fake attester's signature"
    );
    assert_eq!(body["kid"], "test-key");
    assert_eq!(
        time(&body["expires_at"]) - time(&body["issued_at"]),
        time::Duration::days(365)
    );
}

#[tokio::test]
async fn a_root_key_must_be_32_bytes_of_base64() {
    let w = world();

    let not_base64 = w.register(&w.alice, Uuid::new_v4(), "not base64!").await;
    let too_short = w
        .register(&w.alice, Uuid::new_v4(), &B64.encode([7; 31]))
        .await;

    assert_eq!(
        not_base64,
        (
            StatusCode::BAD_REQUEST,
            refusal("invalid_request", "drk_public_key: must be base64")
        )
    );
    assert_eq!(
        too_short,
        (
            StatusCode::BAD_REQUEST,
            refusal(
                "invalid_request",
                "drk_public_key: must be 32 bytes (Ed25519)"
            )
        )
    );
}

#[tokio::test]
async fn the_callers_devices_are_listed_with_their_attestation_expiry() {
    let w = world();
    let (attested, unattested) = (Uuid::new_v4(), Uuid::new_v4());
    let (_, registered) = w.register(&w.alice, attested, &B64.encode([7; 32])).await;
    w.upload(&w.alice, unattested, packages(1)).await;
    w.upload(&w.bob, Uuid::new_v4(), packages(1)).await;

    let (status, body) = w
        .app
        .call(Method::GET, "/api/keys/devices", Some(w.alice.id), None)
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let devices = body["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[0]["device_id"], json!(unattested));
    for field in [
        "attestation_expires_at",
        "drk_public_key",
        "attestation_signature",
        "attestation_kid",
        "hpke_public_key",
        "hpke_key_signature",
        "history_generation",
    ] {
        assert_eq!(devices[0][field], Value::Null, "{field}");
    }
    assert_eq!(devices[1]["device_id"], json!(attested));
    assert_eq!(
        (&devices[1]["display_name"], &devices[1]["kind"]),
        (&json!("Web client"), &json!("unknown"))
    );
    assert_eq!(
        devices[1]["attestation_expires_at"], registered["expires_at"],
        "the text signed"
    );
    assert_eq!(
        (
            &devices[1]["hpke_public_key"],
            &devices[1]["hpke_key_signature"]
        ),
        (&Value::Null, &Value::Null)
    );
    assert_eq!(devices[1]["revoked_at"], Value::Null);
    time(&devices[1]["paired_at"]);
    time(&devices[1]["last_seen_at"]);
}

#[tokio::test]
async fn a_device_registers_its_hpke_key_and_the_list_shows_what_vouches_for_it() {
    let w = world();
    let device = Uuid::new_v4();
    let signature = hpke_signature(&w.alice, device, 7, 9);

    let (status, registered) = w
        .register_with(
            &w.alice,
            json!({
                "device_id": device,
                "drk_public_key": B64.encode([7; 32]),
                "hpke_public_key": B64.encode([9; 32]),
                "hpke_key_signature": signature,
            }),
        )
        .await;
    let devices = w.devices(&w.alice).await;

    assert_eq!(status, StatusCode::CREATED, "{registered}");
    let listed = &devices[0];
    assert_eq!(
        (
            &listed["device_id"],
            &listed["drk_public_key"],
            &listed["attestation_signature"],
            &listed["attestation_kid"],
            &listed["attestation_expires_at"],
        ),
        (
            &json!(device),
            &json!(B64.encode([7; 32])),
            &registered["signature"],
            &registered["kid"],
            &registered["expires_at"],
        )
    );
    assert_eq!(
        (&listed["hpke_public_key"], &listed["hpke_key_signature"]),
        (&json!(B64.encode([9; 32])), &json!(signature))
    );
}

#[tokio::test]
async fn an_hpke_key_alone_malformed_or_not_signed_by_the_root_key_is_refused() {
    let w = world();
    let device = Uuid::new_v4();
    let request = |key: Value, signature: Value| {
        json!({
            "device_id": device,
            "drk_public_key": B64.encode([7; 32]),
            "hpke_public_key": key,
            "hpke_key_signature": signature,
        })
    };
    let (key, signature) = (
        json!(B64.encode([9; 32])),
        json!(hpke_signature(&w.alice, device, 7, 9)),
    );

    for (body, description) in [
        (
            request(key.clone(), Value::Null),
            "hpke_key_signature: comes with hpke_public_key, or neither is sent",
        ),
        (
            request(Value::Null, signature.clone()),
            "hpke_key_signature: comes with hpke_public_key, or neither is sent",
        ),
        (
            request(json!("not base64!"), signature.clone()),
            "hpke_public_key: must be base64",
        ),
        (
            request(json!(B64.encode([9; 31])), signature.clone()),
            "hpke_public_key: must be 32 bytes (X25519)",
        ),
        (
            request(key.clone(), json!(B64.encode([1; 63]))),
            "hpke_key_signature: must be 64 bytes (Ed25519)",
        ),
        (
            request(key.clone(), json!(hpke_signature(&w.alice, device, 8, 9))),
            "hpke_key_signature does not verify against drk_public_key",
        ),
        (
            request(key.clone(), json!(hpke_signature(&w.bob, device, 7, 9))),
            "hpke_key_signature does not verify against drk_public_key",
        ),
    ] {
        assert_eq!(
            w.register_with(&w.alice, body).await,
            (
                StatusCode::BAD_REQUEST,
                refusal("invalid_request", description)
            )
        );
    }
    assert_eq!(
        w.devices(&w.alice).await,
        Vec::<Value>::new(),
        "nothing stored"
    );
}

#[tokio::test]
async fn a_device_is_revoked_by_its_owner_and_not_found_by_anyone_else() {
    let w = world();
    let device = Uuid::new_v4();
    w.upload(&w.alice, device, packages(1)).await;
    let uri = format!("/api/keys/devices/{device}/revoke");

    let by_bob = w.app.call(Method::POST, &uri, Some(w.bob.id), None).await;
    let revoked = w.app.call(Method::POST, &uri, Some(w.alice.id), None).await;
    let again = w.app.call(Method::POST, &uri, Some(w.alice.id), None).await;

    assert_eq!(
        by_bob,
        (
            StatusCode::NOT_FOUND,
            refusal("not_found", "Device not found")
        )
    );
    assert_eq!(revoked, (StatusCode::NO_CONTENT, Value::Null));
    assert_eq!(again, (StatusCode::NO_CONTENT, Value::Null));
}

#[tokio::test]
async fn key_packages_are_uploaded_for_a_device_named_by_its_user_agent() {
    let w = world();
    let device = Uuid::new_v4();
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/keys/packages")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", w.app.token(w.alice.id)),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::USER_AGENT,
            "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
        )
        .body(Body::from(
            json!({ "device_id": device, "packages": packages(2) }).to_string(),
        ))
        .unwrap();

    let uploaded = w.app.send(request).await;
    let again = w.upload(&w.alice, device, packages(3)).await;
    let (_, listed) = w
        .app
        .call(Method::GET, "/api/keys/devices", Some(w.alice.id), None)
        .await;

    assert_eq!(
        uploaded,
        (
            StatusCode::CREATED,
            json!({ "uploaded": 2, "available_after": 2 })
        )
    );
    assert_eq!(
        again,
        (
            StatusCode::CREATED,
            json!({ "uploaded": 3, "available_after": 5 })
        )
    );
    assert_eq!(
        (
            &listed["devices"][0]["display_name"],
            &listed["devices"][0]["kind"]
        ),
        (&json!("Firefox on Linux"), &json!("laptop"))
    );
}

#[tokio::test]
async fn an_upload_names_the_entry_it_refuses() {
    let w = world();
    let device = Uuid::new_v4();
    let bad_base64 = json!([
        { "key_package": B64.encode([1; 8]), "expires_at": in_days(7) },
        { "key_package": "%%%", "expires_at": in_days(7) },
    ]);
    let empty = json!([{ "key_package": "", "expires_at": in_days(7) }]);

    for (packages, description) in [
        (json!([]), "packages must be non-empty"),
        (bad_base64, "packages[1].key_package is not valid base64"),
        (empty, "packages[0].key_package is empty"),
    ] {
        assert_eq!(
            w.upload(&w.alice, device, packages).await,
            (
                StatusCode::BAD_REQUEST,
                refusal("invalid_request", description)
            )
        );
    }
}

#[tokio::test]
async fn a_claim_answers_the_package_and_what_is_left_of_the_stash() {
    let w = world();
    let device = Uuid::new_v4();
    w.upload(&w.alice, device, packages(3)).await;

    let (status, body) = w
        .claim(
            &w.bob,
            json!({ "actor_uri": w.alice.actor_uri.to_string() }),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(b64(&body["key_package"]), vec![1; 8]);
    assert_eq!(body["device_id"], json!(device));
    assert_eq!(
        (&body["remaining_count"], &body["needs_refill"]),
        (&json!(2), &json!(true))
    );
    time(&body["expires_at"]);
}

#[tokio::test]
async fn a_peer_signs_its_claim_for_an_account_of_this_instance() {
    let w = world();
    w.upload(&w.alice, Uuid::new_v4(), packages(1)).await;
    let elsewhere = remote_actor("dave_k2m9x@idp.dave.test").actor_uri;

    let local = w
        .app
        .call_as_peer(
            Method::POST,
            "/api/keys/packages/claim",
            &peer(),
            json!({ "actor_uri": w.alice.actor_uri.to_string() }),
        )
        .await;
    let relayed = w
        .app
        .call_as_peer(
            Method::POST,
            "/api/keys/packages/claim",
            &peer(),
            json!({ "actor_uri": elsewhere.to_string() }),
        )
        .await;
    let unsigned = w
        .app
        .call(
            Method::POST,
            "/api/keys/packages/claim",
            None,
            Some(json!({ "actor_uri": w.alice.actor_uri.to_string() })),
        )
        .await;

    assert_eq!(local.0, StatusCode::OK, "{}", local.1);
    assert_eq!(
        relayed,
        (
            StatusCode::BAD_REQUEST,
            refusal(
                "invalid_request",
                "peer-authenticated claim must target a local actor"
            )
        )
    );
    assert_eq!(
        unsigned,
        (
            StatusCode::BAD_REQUEST,
            refusal("invalid_request", "missing Signature header")
        )
    );
}

#[tokio::test]
async fn a_claim_is_refused_for_a_bad_uri_an_unknown_user_or_an_empty_stash() {
    let w = world();

    let bad_uri = w.claim(&w.alice, json!({ "actor_uri": "not a uri" })).await;
    let unknown = w
        .claim(
            &w.alice,
            json!({ "actor_uri": "http://localhost:8080/users/nobody_t3st0" }),
        )
        .await;
    let empty = w
        .claim(
            &w.alice,
            json!({ "actor_uri": w.bob.actor_uri.to_string() }),
        )
        .await;

    assert_eq!(
        bad_uri,
        (
            StatusCode::BAD_REQUEST,
            refusal("invalid_request", "`actor_uri` is not a valid URL")
        )
    );
    assert_eq!(
        unknown,
        (
            StatusCode::NOT_FOUND,
            refusal("not_found", "User not found")
        )
    );
    assert_eq!(
        empty,
        (
            StatusCode::CONFLICT,
            refusal("conflict", "no available KeyPackage")
        )
    );
}

#[tokio::test]
async fn claims_are_rate_limited_per_requester() {
    let w = world();
    let target = json!({ "actor_uri": w.bob.actor_uri.to_string() });
    for _ in 0..60 {
        w.claim(&w.alice, target.clone()).await;
    }

    let limited = w.claim(&w.alice, target.clone()).await;
    let other = w.claim(&w.bob, target).await;

    assert_eq!(
        limited,
        (
            StatusCode::TOO_MANY_REQUESTS,
            refusal("too_many_requests", "rate limit exceeded")
        )
    );
    assert_ne!(other.0, StatusCode::TOO_MANY_REQUESTS, "{}", other.1);
}

#[tokio::test]
async fn the_stash_status_reports_each_device_against_the_threshold() {
    let w = world();
    let device = Uuid::new_v4();
    w.upload(&w.alice, device, packages(3)).await;

    let status = w
        .app
        .call(
            Method::GET,
            "/api/keys/packages/status",
            Some(w.alice.id),
            None,
        )
        .await;

    assert_eq!(
        status,
        (
            StatusCode::OK,
            json!({
                "devices": [{ "device_id": device, "available": 3, "needs_refill": true }],
                "refill_threshold": 20,
                "cap": 100,
            })
        )
    );
}

impl World {
    /// A token of a session of `who`'s that named a new device of theirs, and the device.
    async fn on_a_device(&self, who: &Account) -> (String, Uuid) {
        let (session, device) = self.app.on_a_device(who.id).await;
        (self.app.token_in(who.id, session), device)
    }

    /// `who`'s history key at `generation`, set as generation after generation from `token`.
    async fn history_key_at(&self, token: &str, generation: i64) {
        for g in 1..=generation {
            let (status, body) = self
                .app
                .call_in(
                    token,
                    Method::PUT,
                    "/api/history/key",
                    Some(json!({
                        "generation": g,
                        "salt": B64.encode([1; 16]),
                        "check_value": B64.encode([2; 32]),
                        "approval_public_key": B64.encode([3; 32]),
                    })),
                )
                .await;
            assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        }
    }

    async fn hold(&self, token: &str, device: Uuid, generation: i64) -> (StatusCode, Value) {
        self.app
            .call_in(
                token,
                Method::PUT,
                &format!("/api/keys/devices/{device}/history-key"),
                Some(json!({ "generation": generation })),
            )
            .await
    }
}

#[tokio::test]
async fn a_device_says_it_holds_the_current_history_key_and_the_list_shows_it() {
    let w = world();
    let (laptops, laptop) = w.on_a_device(&w.alice).await;
    let (_, phone) = w.on_a_device(&w.alice).await;
    w.history_key_at(&laptops, 2).await;

    let held = w.hold(&laptops, laptop, 2).await;

    assert_eq!(held, (StatusCode::NO_CONTENT, Value::Null));
    let devices = w.devices(&w.alice).await;
    let generation_of = |device: Uuid| {
        devices
            .iter()
            .find(|d| d["device_id"] == json!(device))
            .expect("listed")["history_generation"]
            .clone()
    };
    assert_eq!(generation_of(laptop), json!(2));
    assert_eq!(generation_of(phone), Value::Null);
}

#[tokio::test]
async fn a_report_is_refused_with_the_documented_errors() {
    let w = world();
    let (laptops, laptop) = w.on_a_device(&w.alice).await;
    let (_, phone) = w.on_a_device(&w.alice).await;
    let unnamed = w.app.token(w.alice.id);

    let none_set = w.hold(&laptops, laptop, 1).await;
    w.history_key_at(&laptops, 2).await;
    let replaced = w.hold(&laptops, laptop, 1).await;
    let not_one = w.hold(&laptops, laptop, 0).await;
    let for_another = w.hold(&laptops, phone, 2).await;
    let from_none = w.hold(&unnamed, laptop, 2).await;

    let stale = (
        StatusCode::CONFLICT,
        refusal("stale_history_key", "Not the account's current history key"),
    );
    assert_eq!(none_set, stale);
    assert_eq!(replaced, stale);
    assert_eq!(
        not_one,
        (
            StatusCode::BAD_REQUEST,
            refusal(
                "invalid_request",
                "generation: must be from 1 to 2147483647"
            )
        )
    );
    assert_eq!(
        for_another,
        (
            StatusCode::FORBIDDEN,
            refusal("device_mismatch", "This session signed in another device")
        )
    );
    assert_eq!(
        from_none,
        (
            StatusCode::FORBIDDEN,
            refusal("device_required", "Name this session's device first")
        )
    );
    assert!(
        w.devices(&w.alice)
            .await
            .iter()
            .all(|d| d["history_generation"].is_null())
    );
}

#[tokio::test]
async fn the_key_directory_needs_a_signed_in_user() {
    let w = world();

    for (method, uri) in [
        (Method::GET, "/api/keys/devices"),
        (Method::GET, "/api/keys/packages/status"),
        (
            Method::PUT,
            "/api/keys/devices/00000000-0000-0000-0000-000000000000/history-key",
        ),
    ] {
        let (status, _) = w.app.call(method, uri, None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
    }
}

#[tokio::test]
async fn a_revoked_device_is_refused_its_renewal_and_its_uploads() {
    let w = world();
    let device = Uuid::new_v4();
    w.register(&w.alice, device, &B64.encode([7; 32])).await;
    w.app
        .call(
            Method::POST,
            &format!("/api/keys/devices/{device}/revoke"),
            Some(w.alice.id),
            None,
        )
        .await;

    let renewal = w.register(&w.alice, device, &B64.encode([7; 32])).await;
    let upload = w.upload(&w.alice, device, packages(1)).await;

    for refused in [renewal, upload] {
        assert_eq!(
            refused,
            (
                StatusCode::FORBIDDEN,
                refusal("access_denied", "Device is revoked")
            )
        );
    }
}

#[tokio::test]
async fn a_device_id_another_account_holds_is_refused_as_taken() {
    let w = world();
    let device = Uuid::new_v4();
    w.register(&w.alice, device, &B64.encode([7; 32])).await;

    let registered = w.register(&w.bob, device, &B64.encode([8; 32])).await;
    let uploaded = w.upload(&w.bob, device, packages(1)).await;

    for refused in [registered, uploaded] {
        assert_eq!(
            refused,
            (
                StatusCode::CONFLICT,
                refusal("conflict", "Device id already taken")
            )
        );
    }
}

#[tokio::test]
async fn a_claim_the_accounts_instance_cannot_answer_is_a_bad_gateway() {
    let w = world();
    let elsewhere = remote_actor("dave_k2m9x@idp.dave.test").actor_uri;

    let unanswered = w
        .claim(&w.alice, json!({ "actor_uri": elsewhere.to_string() }))
        .await;

    assert_eq!(
        unanswered,
        (
            StatusCode::BAD_GATEWAY,
            refusal("bad_gateway", "the account's instance did not answer")
        )
    );
}

#[tokio::test]
async fn a_peers_claim_whose_body_is_not_the_one_signed_is_refused() {
    let w = world();
    w.upload(&w.bob, Uuid::new_v4(), packages(1)).await;
    let signed_over = json!({ "actor_uri": w.alice.actor_uri.to_string() }).to_string();
    let swapped = json!({ "actor_uri": w.bob.actor_uri.to_string() }).to_string();

    let (status, body) = w
        .app
        .send(TestApp::signed(
            Method::POST,
            "/api/keys/packages/claim",
            &peer(),
            &swapped,
            &domain::identity::testing::TrustedSignatures::digest(signed_over.as_bytes()),
        ))
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        body["error_description"],
        "Digest does not match request body"
    );
    let (_, left) = w
        .app
        .call(
            Method::GET,
            "/api/keys/packages/status",
            Some(w.bob.id),
            None,
        )
        .await;
    assert_eq!(left["devices"][0]["available"], 1, "{left}");
}

#[tokio::test]
async fn a_claim_by_someone_the_owner_does_not_admit_is_refused_alike_whatever_the_cause() {
    let mut answers = Vec::new();
    for kept_out in [BLOCKED, KEPT_OUT_BY_THE_SETTING] {
        let w = world();
        w.upload(&w.alice, Uuid::new_v4(), packages(1)).await;
        w.app.reach.set(w.alice.id, &w.bob.actor_uri, kept_out);
        let target = json!({ "actor_uri": w.alice.actor_uri.to_string() });

        answers.push(w.claim(&w.bob, target.clone()).await);
        let (own, body) = w.claim(&w.alice, target).await;
        assert_eq!(own, StatusCode::OK, "her package is still there: {body}");
    }
    assert_eq!(
        answers,
        vec![
            (
                StatusCode::FORBIDDEN,
                refusal("access_denied", "Can't add this person")
            );
            2
        ]
    );
}

#[tokio::test]
async fn a_claim_for_each_device_answers_one_package_of_every_device_that_has_one() {
    let w = world();
    let (laptop, phone) = (Uuid::new_v4(), Uuid::new_v4());
    w.upload(&w.alice, laptop, packages(3)).await;
    w.upload(&w.alice, phone, packages(1)).await;

    let (status, body) = w
        .app
        .call(
            Method::POST,
            "/api/keys/packages/claim/devices",
            Some(w.bob.id),
            Some(json!({ "actor_uri": w.alice.actor_uri.to_string() })),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let mut devices: Vec<Value> = body["claims"]
        .as_array()
        .expect("a list of claims")
        .iter()
        .map(|claim| {
            assert_eq!(b64(&claim["key_package"]), vec![1; 8]);
            time(&claim["expires_at"]);
            claim["device_id"].clone()
        })
        .collect();
    devices.sort_by_key(|d| d.to_string());
    let mut expected = vec![json!(laptop), json!(phone)];
    expected.sort_by_key(|d| d.to_string());
    assert_eq!(devices, expected);
}
