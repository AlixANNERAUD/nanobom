//! Layers around every route: request logs, compression and security headers.

use std::time::Instant;

use axum::{
    Router,
    extract::Request,
    http::{HeaderName, HeaderValue, header},
    middleware::{self, Next},
    response::Response,
};
use tower_http::{compression::CompressionLayer, set_header::SetResponseHeaderLayer};

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
        .layer(CompressionLayer::new())
        .layer(middleware::from_fn(log_request))
}

fn security_header(name: HeaderName, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::if_not_present(name, HeaderValue::from_static(value))
}

/// Logs each request once it is answered. The query string is left out: it can carry search
/// terms and messages. Probes, metrics scrapes and assets are logged at debug level.
async fn log_request(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
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

fn is_routine(path: &str) -> bool {
    path == "/healthz" || path == "/metrics" || path.starts_with("/pkg/") || path == "/favicon.svg"
}
