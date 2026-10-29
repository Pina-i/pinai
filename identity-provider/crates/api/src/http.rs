//! The layers every route goes through: CORS for any client, one span per request, and HSTS in
//! production; and the streamed answer the routes that relay a file share.

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Method, Request, Uri, header, response};
use axum::response::Response;
use domain::messaging::ByteStream;
use tower_http::classify::{ServerErrorsAsFailures, SharedClassifier};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::{
    DefaultOnBodyChunk, DefaultOnEos, DefaultOnRequest, DefaultOnResponse, MakeSpan, TraceLayer,
};
use tracing::{Level, Span};

use crate::ApiError;

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

/// Browsers keep to HTTPS for a year, unless the handler said otherwise. Production only: in
/// development, plain HTTP on loopback, it would pin `localhost`.
pub async fn strict_transport_security(mut response: Response) -> Response {
    response
        .headers_mut()
        .entry(header::STRICT_TRANSPORT_SECURITY)
        .or_insert(HeaderValue::from_static("max-age=31536000"));
    response
}

/// The bytes as they come from their source, with `Content-Length` when it told it.
pub fn streamed(response: response::Builder, bytes: ByteStream) -> Result<Response, ApiError> {
    let response = match bytes.length {
        Some(length) => response.header(header::CONTENT_LENGTH, length),
        None => response,
    };
    response
        .body(Body::from_stream(bytes.chunks))
        .map_err(|e| ApiError::internal(e.into()))
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
