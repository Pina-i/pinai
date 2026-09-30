use super::*;

fn frame(text: &str) -> Frame {
    Frame::from(text)
}

#[test]
fn only_the_first_connection_of_an_account_is_marked_first() {
    let hub = Arc::new(Hub::new());
    let alice = Uuid::new_v4();

    let (_, _first_handle, first) = hub.subscribe(alice);
    let (_, _second_handle, second) = hub.subscribe(alice);

    assert!(first);
    assert!(!second);
    assert_eq!(hub.connection_count(&alice), 2);
}

#[test]
fn a_frame_reaches_every_connection_of_its_account_and_no_other() {
    let hub = Arc::new(Hub::new());
    let (alice, bob) = (Uuid::new_v4(), Uuid::new_v4());
    let (mut laptop, _laptop_handle, _) = hub.subscribe(alice);
    let (mut phone, _phone_handle, _) = hub.subscribe(alice);
    let (mut bobs, _bobs_handle, _) = hub.subscribe(bob);

    hub.send_to_user(&alice, frame(r#"{"type":"heartbeat_ack"}"#));

    assert_eq!(&*laptop.try_recv().unwrap(), r#"{"type":"heartbeat_ack"}"#);
    assert_eq!(&*phone.try_recv().unwrap(), r#"{"type":"heartbeat_ack"}"#);
    assert!(bobs.try_recv().is_err());
}

#[test]
fn a_dropped_handle_leaves_the_hub() {
    let hub = Arc::new(Hub::new());
    let alice = Uuid::new_v4();
    let (_, handle, _) = hub.subscribe(alice);

    drop(handle);

    assert_eq!(hub.connection_count(&alice), 0);
    let (_, _again, first) = hub.subscribe(alice);
    assert!(first, "the account's next connection is its first again");
}

#[test]
fn a_connection_whose_reader_is_gone_is_pruned_on_the_next_send() {
    let hub = Arc::new(Hub::new());
    let alice = Uuid::new_v4();
    let (reader, _handle, _) = hub.subscribe(alice);
    drop(reader);

    hub.send_to_user(&alice, frame("{}"));

    assert_eq!(hub.connection_count(&alice), 0);
}
