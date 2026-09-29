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
