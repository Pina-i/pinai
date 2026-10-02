use super::*;
use serde_json::json;

const BASE: &str = "https://idp.alice.com";
const HANDLE: &str = "alice-7G4K";
const ACTOR: &str = "https://idp.alice.com/users/alice-7G4K";
const PEER: &str = "https://idp.bob.com/users/bob";
const PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n";

fn json_of<T: Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).expect("should serialise")
}

// ─── Actor document ──────────────────────────────────────────────────────────
// These field names travel to other implementations, so the assertions are on
// the serialised JSON rather than on the struct.

#[test]
fn an_actor_is_addressed_under_its_handle() {
    let actor = json_of(&Actor::person(BASE, HANDLE, "Alice", PEM));

    assert_eq!(actor["id"], ACTOR);
    assert_eq!(actor["type"], "Person");
    assert_eq!(actor["preferredUsername"], HANDLE);
    assert_eq!(actor["name"], "Alice");
}

/// Every collection hangs off the actor URL; `inbox` in particular is what a
/// peer POSTs to after resolving the actor.
#[test]
fn an_actor_advertises_its_collections() {
    let actor = json_of(&Actor::person(BASE, HANDLE, "Alice", PEM));

    assert_eq!(actor["inbox"], format!("{ACTOR}/inbox"));
    assert_eq!(actor["outbox"], format!("{ACTOR}/outbox"));
    assert_eq!(actor["followers"], format!("{ACTOR}/followers"));
    assert_eq!(actor["following"], format!("{ACTOR}/following"));
}

/// An inbound signature names its key as `<actor>#main-key`; verification
/// resolves that URL and reads `publicKey.publicKeyPem` back out.
#[test]
fn an_actor_publishes_the_key_its_signatures_name() {
    let actor = json_of(&Actor::person(BASE, HANDLE, "Alice", PEM));

    assert_eq!(actor["publicKey"]["id"], format!("{ACTOR}#main-key"));
    assert_eq!(actor["publicKey"]["owner"], ACTOR);
    assert_eq!(actor["publicKey"]["publicKeyPem"], PEM);
}

#[test]
fn an_actor_document_carries_the_activitystreams_and_security_contexts() {
    let actor = json_of(&Actor::person(BASE, HANDLE, "Alice", PEM));

    assert_eq!(actor["@context"], json!([AS_CONTEXT, SECURITY_CONTEXT]));
}

#[test]
fn an_actor_omits_a_summary_it_does_not_have() {
    let actor = json_of(&Actor::person(BASE, HANDLE, "Alice", PEM));

    assert!(actor.get("summary").is_none());
    assert_eq!(actor["url"], ACTOR);
}

#[test]
fn an_actor_document_survives_a_round_trip() {
    let original = Actor::person(BASE, HANDLE, "Alice", PEM);
    let parsed: Actor = serde_json::from_value(json_of(&original)).expect("should parse back");

    assert_eq!(parsed.id, original.id);
    assert_eq!(parsed.preferred_username, original.preferred_username);
    assert_eq!(parsed.public_key.public_key_pem, PEM);
}

// ─── WebFinger ───────────────────────────────────────────────────────────────

/// `resolve_remote_actor` finds the actor URL by looking for a `self` link
/// typed `application/activity+json`. If either half drifts, resolution of our
/// users by other instances stops working.
#[test]
fn webfinger_offers_a_self_link_that_actor_resolution_can_find() {
    let wf = WebFingerResponse::for_actor("acct:alice-7G4K@idp.alice.com", ACTOR);

    let self_link = wf
        .links
        .iter()
        .find(|l| l.rel == "self" && l.mime_type.as_deref() == Some("application/activity+json"))
        .expect("a self link typed application/activity+json");

    assert_eq!(self_link.href.as_deref(), Some(ACTOR));
}

#[test]
fn webfinger_echoes_the_subject_it_was_asked_about() {
    let wf = json_of(&WebFingerResponse::for_actor(
        "acct:alice@idp.alice.com",
        ACTOR,
    ));

    assert_eq!(wf["subject"], "acct:alice@idp.alice.com");
    assert_eq!(wf["aliases"][0], ACTOR);
}

#[test]
fn a_webfinger_link_serialises_its_media_type_as_type() {
    let wf = json_of(&WebFingerResponse::for_actor(
        "acct:alice@idp.alice.com",
        ACTOR,
    ));

    assert_eq!(wf["links"][0]["type"], "application/activity+json");
}

// ─── Activities ──────────────────────────────────────────────────────────────

#[test]
fn a_follow_names_its_target_as_the_object() {
    let follow = json_of(&Activity::follow("https://idp.alice.com/f/1", ACTOR, PEER));

    assert_eq!(follow["type"], "Follow");
    assert_eq!(follow["actor"], ACTOR);
    assert_eq!(follow["object"], PEER);
    assert_eq!(follow["to"], json!([PEER]));
}

/// Accept, Reject and Undo all carry the original Follow as their object — the
/// receiving side reads `object.actor` to find which local user was followed.
#[test]
fn a_response_to_a_follow_embeds_the_follow_it_answers() {
    let follow = serde_json::to_value(Activity::follow("id-1", PEER, ACTOR)).unwrap();

    for (build, expected) in [
        (Activity::accept("id-2", ACTOR, follow.clone()), "Accept"),
        (Activity::reject("id-3", ACTOR, follow.clone()), "Reject"),
        (Activity::undo_follow("id-4", ACTOR, follow.clone()), "Undo"),
    ] {
        let value = json_of(&build);
        assert_eq!(value["type"], expected);
        assert_eq!(value["actor"], ACTOR);
        assert_eq!(
            value["object"]["actor"], PEER,
            "{expected} should embed the Follow"
        );
        assert_eq!(value["object"]["type"], "Follow");
    }
}

#[test]
fn an_activity_carries_the_activitystreams_context() {
    let follow = json_of(&Activity::follow("id-1", ACTOR, PEER));

    assert_eq!(follow["@context"], AS_CONTEXT);
}

#[test]
fn an_activity_is_timestamped_when_it_is_built() {
    let follow = json_of(&Activity::follow("id-1", ACTOR, PEER));
    let published = follow["published"]
        .as_str()
        .expect("published should be set");

    // RFC 3339, e.g. 2026-09-18T10:00:00Z — parsed rather than pattern-matched.
    assert!(
        time::OffsetDateTime::parse(published, &time::format_description::well_known::Rfc3339)
            .is_ok(),
        "not RFC 3339: {published}"
    );
}

#[test]
fn an_activity_omits_the_optional_fields_it_does_not_use() {
    let accept = json_of(&Activity::accept("id-2", ACTOR, json!({"type": "Follow"})));

    assert!(accept.get("to").is_none());
    assert!(accept.get("cc").is_none());
    assert!(accept.get("content").is_none());
}

#[test]
fn an_activity_survives_a_round_trip() {
    let original = Activity::follow("https://idp.alice.com/f/1", ACTOR, PEER);
    let parsed: Activity = serde_json::from_value(json_of(&original)).expect("should parse back");

    assert_eq!(parsed.activity_type, "Follow");
    assert_eq!(parsed.actor, ACTOR);
    assert_eq!(parsed.object, json!(PEER));
}

// ─── OrderedCollection ───────────────────────────────────────────────────────

#[test]
fn an_ordered_collection_reports_its_size_and_items() {
    let collection = json_of(&OrderedCollection::new(
        &format!("{ACTOR}/followers"),
        2,
        vec![json!(PEER), json!("https://idp.carol.com/users/carol")],
    ));

    assert_eq!(collection["type"], "OrderedCollection");
    assert_eq!(collection["id"], format!("{ACTOR}/followers"));
    assert_eq!(collection["totalItems"], 2);
    assert_eq!(collection["orderedItems"][0], PEER);
}

/// `totalItems` is the count the peer paginates against; it is not derived
/// from the page of items sent alongside it.
#[test]
fn an_ordered_collection_can_report_more_items_than_it_carries() {
    let collection = json_of(&OrderedCollection::new("id", 500, vec![json!(PEER)]));

    assert_eq!(collection["totalItems"], 500);
    assert_eq!(collection["orderedItems"].as_array().unwrap().len(), 1);
}

#[test]
fn an_empty_collection_still_lists_an_items_array() {
    let collection = json_of(&OrderedCollection::new("id", 0, vec![]));

    assert_eq!(collection["totalItems"], 0);
    assert_eq!(collection["orderedItems"], json!([]));
}

// ─── Bio and pronouns ────────────────────────────────────────────────────────

#[test]
fn a_bio_is_published_as_escaped_html_and_read_back_as_it_was() {
    let bio = "Tom & Jerry <3 \"quotes\" 'too'\nkia ora";

    let actor = Actor::person(BASE, HANDLE, "Alice", PEM).with_profile(Some(bio), Some("she"));
    let published = json_of(&actor);

    assert_eq!(
        published["summary"],
        "Tom &amp; Jerry &lt;3 &quot;quotes&quot; &#39;too&#39;<br>kia ora"
    );
    assert_eq!(published["pronouns"], "she");
    let parsed: Actor = serde_json::from_value(published).unwrap();
    assert_eq!(parsed.bio().as_deref(), Some(bio));
    assert_eq!(parsed.pronouns.as_deref(), Some("she"));
}

#[test]
fn a_peers_html_summary_is_read_as_text() {
    let summary =
        "<p>Hi <a href=\"https://x.test\">there</a>!</p><p>Second&nbsp;line &#x2764;&#65;</p>";

    assert_eq!(summary_text(summary), "Hi there!\nSecond line ❤A");
    assert_eq!(summary_text("<p></p>  "), "");
}

#[test]
fn an_actor_without_a_bio_or_pronouns_carries_neither() {
    let actor = json_of(&Actor::person(BASE, HANDLE, "Alice", PEM).with_profile(None, None));

    assert!(actor.get("summary").is_none());
    assert!(actor.get("pronouns").is_none());
}

#[test]
fn an_update_person_carries_the_whole_shown_profile() {
    let update = json_of(&Activity::update_person(
        ACTOR,
        HANDLE,
        Some("Alice"),
        Some("https://s3.test/a.png"),
        Some("a & b"),
        Some("non-binary"),
    ));
    let person = &update["object"];

    assert_eq!(person["name"], "Alice");
    assert_eq!(person["icon"]["url"], "https://s3.test/a.png");
    assert_eq!(person["summary"], "a &amp; b");
    assert_eq!(person["pronouns"], "non-binary");
    let bare = json_of(&Activity::update_person(
        ACTOR, HANDLE, None, None, None, None,
    ));
    for field in ["name", "icon", "summary", "pronouns"] {
        assert!(bare["object"].get(field).is_none(), "{field}");
    }
}
