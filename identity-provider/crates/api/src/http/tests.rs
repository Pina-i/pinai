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

#[test]
fn a_logged_uri_never_carries_an_invitations_token() {
    let token = "q7Yp0aZk3mW8xRt2LbN5vHc9JdE4sF6uG1iO0pQ-_wA";
    for (uri, logged) in [
        (format!("/i/{token}"), "/i/…"),
        (format!("/i/{token}/sign-up"), "/i/…/sign-up"),
    ] {
        assert_eq!(logged_uri(&uri.parse::<Uri>().unwrap()), logged);
    }
}

#[test]
fn a_logged_uri_never_carries_a_reset_links_token() {
    let token = "q7Yp0aZk3mW8xRt2LbN5vHc9JdE4sF6uG1iO0pQ-_wA";

    assert_eq!(
        logged_uri(&format!("/r/{token}").parse::<Uri>().unwrap()),
        "/r/…"
    );
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

    /// How many events were logged at error and at warn level.
    #[derive(Clone, Default)]
    struct Loud {
        errors: Arc<AtomicUsize>,
        warnings: Arc<AtomicUsize>,
    }

    impl<S: Subscriber> Layer<S> for Loud {
        fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
            match *event.metadata().level() {
                Level::ERROR => self.errors.fetch_add(1, Ordering::SeqCst),
                Level::WARN => self.warnings.fetch_add(1, Ordering::SeqCst),
                _ => 0,
            };
        }
    }

    /// The status `error` is answered with, and how many error and warn lines it logged.
    async fn logged(error: fn() -> ApiError) -> (StatusCode, usize, usize) {
        let loud = Loud::default();
        // tracing-core's callsite registry: with one dispatcher alone, a callsite another test
        // thread registers first is asked of that thread's default and cached as never enabled;
        // with two, of every dispatcher.
        let _second_dispatcher =
            tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        let _guard =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(loud.clone()));
        let app = Router::new()
            .route("/boom", get(move || async move { Err::<(), _>(error()) }))
            .layer(trace());

        let response = app
            .oneshot(Request::get("/boom").body(Body::empty()).unwrap())
            .await
            .unwrap();

        (
            response.status(),
            loud.errors.load(Ordering::SeqCst),
            loud.warnings.load(Ordering::SeqCst),
        )
    }

    #[tokio::test]
    async fn a_server_error_is_logged_once() {
        let logged = logged(|| ApiError::internal(anyhow::anyhow!("the store is down"))).await;

        assert_eq!(logged, (StatusCode::INTERNAL_SERVER_ERROR, 1, 0));
    }

    #[tokio::test]
    async fn a_peers_failure_is_logged_once_as_a_warning() {
        let logged = logged(|| ApiError::upstream(anyhow::anyhow!("connection refused"))).await;

        assert_eq!(logged, (StatusCode::BAD_GATEWAY, 0, 1));
    }

    const PRIVATE: &str = "peer URL resolves into private address space (10.0.0.5)";

    #[tokio::test]
    async fn the_reason_of_a_refusal_anyone_can_cause_is_never_logged_loud() {
        let refusals: [(fn() -> ApiError, StatusCode); 3] = [
            (
                || ApiError::upstream_not_allowed(PRIVATE.to_owned()),
                StatusCode::BAD_GATEWAY,
            ),
            (
                || ApiError::peer_not_allowed(PRIVATE.to_owned()),
                StatusCode::FORBIDDEN,
            ),
            (
                || {
                    ApiError::from(domain::identity::SignatureError::KeyUnavailable(
                        PRIVATE.to_owned(),
                    ))
                },
                StatusCode::UNAUTHORIZED,
            ),
        ];

        for (refusal, status) in refusals {
            assert_eq!(logged(refusal).await, (status, 0, 0));
        }
    }
}

mod cors {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode, header};
    use axum::routing::get;
    use tower::ServiceExt;

    use crate::http::cors;

    fn app() -> Router {
        Router::new()
            .route("/api/thing", get(|| async { "ok" }))
            .layer(cors())
    }

    #[tokio::test]
    async fn a_page_on_any_origin_may_read_an_answer() {
        for origin in ["https://chat.bob.example", "app://pinai"] {
            let response = app()
                .oneshot(
                    Request::get("/api/thing")
                        .header(header::ORIGIN, origin)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
            assert_eq!(
                response.headers()[header::ACCESS_CONTROL_EXPOSE_HEADERS],
                "www-authenticate"
            );
        }
    }

    #[tokio::test]
    async fn any_origin_may_send_a_bearer_token_but_never_credentials() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/api/thing")
                    .header(header::ORIGIN, "app://pinai")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                    .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let headers = response.headers();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert!(
            headers[header::ACCESS_CONTROL_ALLOW_HEADERS]
                .to_str()
                .unwrap()
                .contains("authorization")
        );
        assert!(!headers.contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS));
    }
}

mod hsts {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Method, Request, header};
    use axum::middleware::map_response;
    use axum::routing::get;
    use tower::ServiceExt;

    use crate::http::strict_transport_security;
    use crate::testing::TestApp;

    /// A page, an API answer, a refusal, a route unknown, an avatar not found, a CORS preflight.
    fn requests() -> Vec<Request<Body>> {
        let get = |uri: &str| Request::get(uri).body(Body::empty()).unwrap();
        vec![
            get("/health"),
            get("/login"),
            get("/userinfo"),
            get("/nowhere"),
            get("/avatars/alice.png"),
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/api/profile")
                .header(header::ORIGIN, "https://app.example")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PATCH")
                .body(Body::empty())
                .unwrap(),
        ]
    }

    #[tokio::test]
    async fn production_sends_hsts_on_every_answer() {
        let app = TestApp::in_production();

        for request in requests() {
            let uri = request.uri().clone();
            let response = app.respond(request).await;

            assert_eq!(
                response.headers()[header::STRICT_TRANSPORT_SECURITY],
                "max-age=31536000",
                "{uri} ({})",
                response.status()
            );
        }
    }

    #[tokio::test]
    async fn development_sends_no_hsts() {
        let app = TestApp::with([], []);

        for request in requests() {
            let uri = request.uri().clone();
            let response = app.respond(request).await;

            assert!(
                !response
                    .headers()
                    .contains_key(header::STRICT_TRANSPORT_SECURITY),
                "{uri}"
            );
        }
    }

    #[tokio::test]
    async fn a_handlers_own_hsts_is_kept() {
        let router = Router::new()
            .route(
                "/",
                get(|| async { ([(header::STRICT_TRANSPORT_SECURITY, "max-age=60")], "") }),
            )
            .layer(map_response(strict_transport_security));

        let response = router
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(
            response.headers()[header::STRICT_TRANSPORT_SECURITY],
            "max-age=60"
        );
    }
}
