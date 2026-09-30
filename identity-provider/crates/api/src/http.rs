//! The layers every route goes through: CORS for the web client, and one span per request.

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Method, Request, Uri};
use tower_http::classify::{ServerErrorsAsFailures, SharedClassifier};
use tower_http::cors::CorsLayer;
use tower_http::trace::{
    DefaultOnBodyChunk, DefaultOnEos, DefaultOnRequest, DefaultOnResponse, MakeSpan, TraceLayer,
};
use tracing::{Level, Span};

pub fn cors(origins: &[String]) -> CorsLayer {
    let origins: Vec<HeaderValue> = origins.iter().filter_map(|o| o.parse().ok()).collect();
    // Listed, not `*`: Firefox reads `Access-Control-Allow-Headers: *` as not covering
    // `Authorization`, which would drop the bearer token on every cross-origin request.
    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::OPTIONS,
        ])
        .allow_headers([
            HeaderName::from_static("authorization"),
            HeaderName::from_static("content-type"),
            HeaderName::from_static("accept"),
            HeaderName::from_static("x-requested-with"),
        ])
        .allow_credentials(false)
}

#[derive(Clone)]
pub struct RequestSpan;

impl MakeSpan<Body> for RequestSpan {
    fn make_span(&mut self, request: &Request<Body>) -> Span {
        tracing::info_span!(
            "request",
            method = %request.method(),
            uri = %logged_uri(request.uri()),
            version = ?request.version(),
        )
    }
}

type Trace = TraceLayer<
    SharedClassifier<ServerErrorsAsFailures>,
    RequestSpan,
    DefaultOnRequest,
    DefaultOnResponse,
    DefaultOnBodyChunk,
    DefaultOnEos,
    (),
>;

/// No `on_failure`: a server error is logged once, by `ApiError`, with its cause.
pub fn trace() -> Trace {
    TraceLayer::new_for_http()
        .make_span_with(RequestSpan)
        .on_response(DefaultOnResponse::new().level(Level::INFO))
        .on_failure(())
}

/// A request's URI as logged: the path only — a query can carry a credential (`/ws?token=`, a
/// blob URL's token).
fn logged_uri(uri: &Uri) -> String {
    uri.path().to_owned()
}

#[cfg(test)]
mod tests;
