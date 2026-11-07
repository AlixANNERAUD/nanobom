//! The HTTP API used by CI, authenticated with upload tokens.

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::put,
};
use nanobom_domain::{
    evaluation::{Scope, Trigger},
    inventory::{self, UploadOutcome, UploadSource},
    tokens,
};
use serde::{Deserialize, Serialize};

use crate::{runner::RunRequest, state::AppState};

/// An API error, returned as `{"error": "message"}`.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "a valid upload token is required in the Authorization header (Bearer)",
        )
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(ErrorBody {
                error: &self.message,
            }),
        )
            .into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, "Bearer".parse().expect("valid"));
        }
        response
    }
}

impl From<nanobom_domain::Error> for ApiError {
    fn from(error: nanobom_domain::Error) -> Self {
        use nanobom_domain::Error;
        match error {
            Error::NotFound => Self::new(StatusCode::NOT_FOUND, "not found"),
            Error::Forbidden => Self::new(
                StatusCode::FORBIDDEN,
                "this token does not allow uploads to this project",
            ),
            Error::Invalid(message) => Self::new(StatusCode::UNPROCESSABLE_ENTITY, message),
            Error::Conflict(message) => Self::new(StatusCode::CONFLICT, message),
            Error::Database(error) => {
                tracing::error!(%error, "database error");
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        }
    }
}

pub fn router(state: &AppState) -> Router<AppState> {
    let maximum_size = state.options.maximum_sbom_size.saturating_mul(1024 * 1024);
    Router::new().route(
        "/api/organizations/{organization}/projects/{project}/sbom",
        put(upload_sbom).layer(DefaultBodyLimit::max(maximum_size)),
    )
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token.trim())
}

#[derive(Debug, Default, Deserialize)]
pub struct UploadParameters {
    /// The commit the SBOM was built from.
    source_commit: Option<String>,
    /// The container image tag the SBOM describes.
    image_tag: Option<String>,
}

/// `PUT /api/organizations/{organization}/projects/{project}/sbom`: replaces the project's
/// components with those of a CycloneDX JSON document.
async fn upload_sbom(
    State(state): State<AppState>,
    Path((organization, project)): Path<(String, String)>,
    Query(parameters): Query<UploadParameters>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<UploadOutcome>), ApiError> {
    let secret = bearer_token(&headers).ok_or_else(ApiError::unauthorized)?;
    let token = tokens::authenticate(&state.database, secret)
        .await?
        .ok_or_else(ApiError::unauthorized)?;

    let sbom = {
        let _permit = state
            .sbom_parsing
            .acquire()
            .await
            .expect("the semaphore is never closed");
        tokio::task::spawn_blocking(move || inventory::parse(&body))
            .await
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))??
    };
    let outcome = inventory::ingest(
        &state.database,
        &token,
        &organization,
        &project,
        sbom,
        UploadSource {
            source_commit: parameters.source_commit,
            image_tag: parameters.image_tag,
        },
    )
    .await?;
    if state.options.run_after_upload {
        state.runner.request(RunRequest {
            trigger: Trigger::Upload,
            scope: Scope::Project(outcome.project_id),
            triggered_by: None,
        });
    }
    let status = if outcome.project_created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(outcome)))
}
