use crate::auth::world::world;

#[tokio::test]
async fn after_signing_out_a_browser_goes_back_only_to_where_a_client_lives() {
    let w = world().await;

    assert_eq!(
        w.log_out
            .execute(Some("http://localhost:5173"))
            .await
            .unwrap(),
        Some("http://localhost:5173".to_owned())
    );
    assert_eq!(
        w.log_out.execute(Some("https://evil.test")).await.unwrap(),
        None
    );
    assert_eq!(
        w.log_out
            .execute(Some("javascript:alert(1)"))
            .await
            .unwrap(),
        None
    );
    assert_eq!(w.log_out.execute(None).await.unwrap(), None);
}
