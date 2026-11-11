//! Layers around every route: request logs, compression and security headers.
//!
//! Security headers are only added when a handler did not set its own, so a route can relax one
//! when it must. Request logging is the outermost layer, so the logged status and duration are
//! those the client sees. Responses with a strong `ETag` (badges, [`crate::badges`]) are not
//! compressed: a strong tag names the exact bytes sent, which compression would change.

use std::time::Instant;

use axum::{
    Router,
    extract::Request,
    http::{Extensions, HeaderMap, HeaderName, HeaderValue, StatusCode, Version, header},
    middleware::{self, Next},
    response::Response,
};
use tower_http::{
    compression::{
        CompressionLayer,
        predicate::{DefaultPredicate, Predicate},
    },
    set_header::SetResponseHeaderLayer,
};

/// Wraps the router in the layers shared by every route.
pub fn layers(router: Router) -> Router {
    router
        .layer(security_header(header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .layer(security_header(header::REFERRER_POLICY, "same-origin"))
        .layer(security_header(header::X_FRAME_OPTIONS, "DENY"))
        // Only `frame-ancestors`: scripts are left alone, the interface inlines a few.
        .layer(security_header(
            header::CONTENT_SECURITY_POLICY,
            "frame-ancestors 'none'",
        ))
        .layer(middleware::from_fn(no_store_pages))
        .layer(
            CompressionLayer::new().compress_when(DefaultPredicate::new().and(without_strong_tag)),
        )
        .layer(middleware::from_fn(log_request))
}

/// Whether a response has no strong `ETag`; weak tags, as the read API sends, survive
/// compression.
fn without_strong_tag(_: StatusCode, _: Version, headers: &HeaderMap, _: &Extensions) -> bool {
    headers
        .get(header::ETAG)
        .is_none_or(|tag| tag.as_bytes().starts_with(b"W/"))
}

/// Interface pages carry what only their viewer may see, such as a project's upload token for its
/// admins: no browser or proxy cache keeps them after sign-out, unless the route set its own
/// caching (the report, badges).
async fn no_store_pages(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let html = response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|value| value.as_bytes().starts_with(b"text/html"));
    if html && !response.headers().contains_key(header::CACHE_CONTROL) {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

fn security_header(name: HeaderName, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::if_not_present(name, HeaderValue::from_static(value))
}

/// Logs each request once it is answered. The query string is left out: it can carry search
/// terms and messages. Probes, metrics scrapes, badges and assets are logged at debug level.
async fn log_request(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = logged_path(request.uri().path());
    let started = Instant::now();
    let response = next.run(request).await;
    let status = response.status().as_u16();
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if is_routine(&path) {
        tracing::debug!(%method, path, status, duration_ms, "request");
    } else {
        tracing::info!(%method, path, status, duration_ms, "request");
    }
    response
}

/// The path as logged: a badge's key is its only authorization, so it is left out.
fn logged_path(path: &str) -> String {
    if path.starts_with("/badges/") {
        "/badges/…".to_owned()
    } else {
        path.to_owned()
    }
}

fn is_routine(path: &str) -> bool {
    path == "/healthz"
        || path == "/metrics"
        || path.starts_with("/badges/")
        || path.starts_with("/pkg/")
        || path.starts_with("/fonts/")
        || path == "/favicon.svg"
}

#[cfg(test)]
mod tests {
    use super::{is_routine, logged_path};

    #[test]
    fn assets_are_routine() {
        for path in [
            "/pkg/nanobom.css",
            "/favicon.svg",
            "/fonts/inter-latin-wght-normal.woff2",
        ] {
            assert!(is_routine(path), "{path}");
        }
        assert!(!is_routine("/organizations"));
        assert!(!is_routine("/fonts"));
    }

    #[test]
    fn badge_keys_are_not_logged() {
        let path = "/badges/0123456789abcdef0123456789abcdef.svg";
        assert!(is_routine(path));
        assert_eq!(logged_path(path), "/badges/…");
        assert_eq!(logged_path("/organizations"), "/organizations");
    }
}
