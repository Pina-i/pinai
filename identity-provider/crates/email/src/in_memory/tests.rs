use super::*;

#[tokio::test]
async fn records_send_and_drains_on_take() {
    let s = InMemoryEmailSender::new();
    s.send_signup_otp("alice@example.com", "Alice", "111111")
        .await
        .unwrap();
    s.send_signup_otp("bob@example.com", "Bob", "222222")
        .await
        .unwrap();

    let drained = s.take_sent();
    assert_eq!(drained.len(), 2);
    assert_eq!(drained[0].to, "alice@example.com");
    assert_eq!(drained[0].code, "111111");
    assert_eq!(drained[1].code, "222222");

    // Buffer should be empty after take.
    assert!(s.peek_sent().is_empty());
}
