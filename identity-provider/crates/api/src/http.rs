//! The layers every route goes through: CORS for any client, and one span per request.

use axum::body::Body;
use axum::http::{HeaderName, Method, Request, Uri, header};
use tower_http::classify::{ServerErrorsAsFailures, SharedClassifier};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::{
    DefaultOnBodyChunk, DefaultOnEos, DefaultOnRequest, DefaultOnResponse, MakeSpan, TraceLayer,
};
use tracing::{Level, Span};

pub fn cors() -> CorsLayer {
    CorsLayer::new()
        // Every origin, for other instances' web clients and the desktop app. Safe: the API is
        // authorised by bearer tokens, and under `*` a browser never exposes a credentialed response.
        .allow_origin(Any)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::OPTIONS,
        ])
        // Listed, not `*`: Firefox reads `Access-Control-Allow-Headers: *` as not covering
        // `Authorization`, which would drop the bearer token on every cross-origin request.
        .allow_headers([
            HeaderName::from_static("authorization"),
            HeaderName::from_static("content-type"),
            HeaderName::from_static("accept"),
            HeaderName::from_static("x-requested-with"),
        ])
        // The challenge of a 401 tells a token to renew from a password to type again.
        .expose_headers([header::WWW_AUTHENTICATE])
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
/// blob URL's token) — and without the token of a link — an invitation's, a password reset's —
/// which its pages' paths carry.
fn logged_uri(uri: &Uri) -> String {
    let path = uri.path();
    for link in ["/i/", domain::auth::RESET_PATH_PREFIX] {
        if let Some(rest) = path.strip_prefix(link) {
            return match rest.split_once('/') {
                Some((_, after)) => format!("{link}…/{after}"),
                None => format!("{link}…"),
            };
        }
    }
    path.to_owned()
}

#[cfg(test)]
mod tests;
