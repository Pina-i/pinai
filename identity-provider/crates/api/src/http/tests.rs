use axum::http::Uri;

use super::*;

#[test]
fn a_logged_uri_never_carries_its_query() {
    for (uri, logged) in [
        ("/ws?token=eyJhbGciOiJFZERTQSJ9.e30.sig", "/ws"),
        (
            "/api/attachments/5f1c/blob?token=abc.def.123.mac",
            "/api/attachments/5f1c/blob",
        ),
        ("/api/dm/7a2b", "/api/dm/7a2b"),
    ] {
        assert_eq!(logged_uri(&uri.parse::<Uri>().unwrap()), logged);
    }
}

mod logging {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;
    use tracing::{Event, Level, Subscriber};
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

    use crate::ApiError;
    use crate::http::trace;

    #[derive(Clone, Default)]
    struct Errors(Arc<AtomicUsize>);

    impl<S: Subscriber> Layer<S> for Errors {
        fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
            if *event.metadata().level() == Level::ERROR {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    #[tokio::test]
    async fn a_server_error_is_logged_once() {
        let errors = Errors::default();
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(errors.clone()));
        let app = Router::new()
            .route(
                "/boom",
                get(|| async {
                    Err::<(), _>(ApiError::internal(anyhow::anyhow!("the store is down")))
                }),
            )
            .layer(trace());

        let response = app
            .oneshot(Request::get("/boom").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(errors.0.load(Ordering::SeqCst), 1);
    }
}
