use crate::helpers::{spawn_app_with, with_storage};

const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";

#[tokio::test]
async fn an_uploaded_avatar_is_fetched_from_the_instances_own_port() {
    let app = spawn_app_with(with_storage).await;
    let alice = app.sign_up("alice").await;

    let uploaded = app
        .http
        .put(format!("{}/api/avatar", app.address))
        .bearer_auth(&alice.token)
        .header("content-type", "image/png")
        .body(PNG)
        .send()
        .await
        .unwrap();
    assert_eq!(uploaded.status(), 200);
    let (_, userinfo) = app.get(&alice, "/userinfo").await;
    let url = userinfo["avatar_url"].as_str().unwrap().to_owned();
    let fetched = app.http.get(&url).send().await.unwrap();

    assert!(
        url.starts_with(&format!("{}/avatars/", app.address)),
        "{url}"
    );
    assert_eq!(fetched.status(), 200);
    assert_eq!(fetched.headers()["content-type"], "image/png");
    assert_eq!(fetched.headers()["content-length"], PNG.len().to_string());
    assert_eq!(fetched.bytes().await.unwrap(), PNG);
    app.stop().await.unwrap();
}
