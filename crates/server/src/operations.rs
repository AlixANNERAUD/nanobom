//! Health and metrics endpoints.
//!
//! Both are unauthenticated, for probes and scrapers. They reveal no organization data:
//! metrics are instance-wide counts (see [`crate::metrics`]). Restrict `/metrics` at the reverse
//! proxy if even those should stay private.

use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use serde_json::json;

use crate::state::AppState;

/// The `/healthz` and `/metrics` routes.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(health))
        .route("/metrics", get(metrics))
}

/// `GET /healthz`: 200 when the database answers, 503 otherwise.
async fn health(State(state): State<AppState>) -> impl IntoResponse {
    match state.database.ping().await {
        Ok(()) => (StatusCode::OK, Json(json!({"status": "ok"}))),
        Err(error) => {
            tracing::error!(%error, "health check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"status": "unavailable"})),
            )
        }
    }
}

/// `GET /metrics`: Prometheus text format.
async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        crate::metrics::render(&state.database, state.options.stale_after_days).await,
    )
}
