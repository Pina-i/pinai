use app::configuration::Config;
use serde_json::{Value, json};

use crate::helpers::{TestApp, admin_of, an_admin, spawn_app_with};

/// An instance its `.env` names, and its admin.
fn named(config: &mut Config) {
    an_admin(config);
    config.instance_name = Some("Aotearoa".into());
    config.instance_description = Some("Design people.".into());
}

async fn node_metadata(app: &TestApp) -> Value {
    let document: Value = app
        .http
        .get(format!("{}/nodeinfo/2.1", app.address))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    document["metadata"].clone()
}

#[tokio::test]
async fn an_admins_text_takes_over_from_the_variables_and_outlives_a_restart() {
    let app = spawn_app_with(named).await;
    let admin = admin_of(&app).await;

    let (status, saved) = app
        .send(
            reqwest::Method::PUT,
            &admin,
            "/api/admin/intro",
            json!({ "name": "Kāinga", "description": null }),
        )
        .await;
    assert_eq!(status, 200, "{saved}");
    assert_eq!(node_metadata(&app).await, json!({ "nodeName": "Kāinga" }));

    let app = app.restart_with(named).await;

    assert_eq!(
        node_metadata(&app).await,
        json!({ "nodeName": "Kāinga" }),
        "the saved text whole: INSTANCE_DESCRIPTION is not used either"
    );
    let (_, shown) = app.get(&admin_of(&app).await, "/api/admin/intro").await;
    assert_eq!(shown, json!({ "name": "Kāinga", "description": null }));
    app.stop().await.unwrap();
}

#[tokio::test]
async fn until_an_admin_saves_the_variables_are_used_as_each_start_reads_them() {
    let app = spawn_app_with(named).await;
    let (_, shown) = app.get(&admin_of(&app).await, "/api/admin/intro").await;

    assert_eq!(
        node_metadata(&app).await,
        json!({ "nodeName": "Aotearoa", "nodeDescription": "Design people." })
    );
    assert_eq!(
        shown,
        json!({ "name": "Aotearoa", "description": "Design people." })
    );

    let app = app
        .restart_with(|config| {
            named(config);
            config.instance_name = Some("Kāinga".into());
        })
        .await;

    assert_eq!(
        node_metadata(&app).await,
        json!({ "nodeName": "Kāinga", "nodeDescription": "Design people." })
    );
    app.stop().await.unwrap();
}
