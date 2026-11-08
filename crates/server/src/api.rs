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
    evaluation::{RunOutcome, Scope, Trigger},
    findings::{self, Finding},
    inventory::{self, UploadOutcome, UploadSource},
    notifications, tokens,
};
use nanobom_osv::Severity;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::time::Duration;

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
            // The API speaks English: CI logs are read by whoever maintains the pipeline.
            Error::Invalid(problem) => {
                Self::new(StatusCode::UNPROCESSABLE_ENTITY, problem.to_string())
            }
            Error::Conflict(problem) => Self::new(StatusCode::CONFLICT, problem.to_string()),
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
    /// `true` to wait for the project's evaluation and return it.
    wait: Option<String>,
    /// Answer with an error status when open findings reach this threshold; implies `wait`.
    fail_on: Option<String>,
}

fn parse_wait(value: Option<&str>) -> Result<bool, ApiError> {
    match value.map(str::trim) {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "wait must be true or false",
        )),
    }
}

/// What fails an upload with `fail_on`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Threshold {
    /// An open finding at or above this severity.
    Severity(Severity),
    /// An open known exploited finding.
    Exploited,
}

impl Threshold {
    fn parse(value: &str) -> Result<Self, ApiError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "critical" => Ok(Self::Severity(Severity::Critical)),
            "high" => Ok(Self::Severity(Severity::High)),
            "medium" => Ok(Self::Severity(Severity::Medium)),
            "low" => Ok(Self::Severity(Severity::Low)),
            "exploited" => Ok(Self::Exploited),
            _ => Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "fail_on must be critical, high, medium, low or exploited",
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Severity(severity) => severity.as_str(),
            Self::Exploited => "exploited",
        }
    }

    fn reached_by(self, finding: &Finding) -> bool {
        match self {
            Self::Severity(minimum) => finding.severity >= minimum,
            Self::Exploited => finding.exploitation.known_exploited,
        }
    }
}

/// At most this many findings are listed in an upload's evaluation; all are counted.
const MAXIMUM_LISTED_FINDINGS: usize = 100;

/// The response to an upload: its outcome, with the evaluation when the upload waited for it.
#[derive(Debug, Serialize)]
pub struct UploadResponse {
    /// Why an upload with `fail_on` fails.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(flatten)]
    outcome: UploadOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    evaluation: Option<Evaluation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum EvaluationStatus {
    Succeeded,
    Failed,
    TimedOut,
}

/// The project's evaluation after an upload, for CI.
#[derive(Debug, Serialize)]
struct Evaluation {
    status: EvaluationStatus,
    run_id: Option<i64>,
    open: OpenCounts,
    known_exploited: usize,
    /// The open findings, most severe first, at most `MAXIMUM_LISTED_FINDINGS`.
    findings: Vec<EvaluationFinding>,
}

#[derive(Debug, Default, Serialize)]
struct OpenCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    unknown: usize,
}

#[derive(Debug, Serialize)]
struct EvaluationFinding {
    vulnerability: String,
    component: String,
    severity: Severity,
    known_exploited: bool,
    url: String,
}

/// The evaluation of a run (`None` when it did not finish in time) and the project's open
/// findings, most severe first.
fn evaluation(run: Option<&RunOutcome>, findings: &[Finding], public_url: &Url) -> Evaluation {
    let mut open = OpenCounts::default();
    for finding in findings {
        *match finding.severity {
            Severity::Critical => &mut open.critical,
            Severity::High => &mut open.high,
            Severity::Medium => &mut open.medium,
            Severity::Low => &mut open.low,
            Severity::Unknown => &mut open.unknown,
        } += 1;
    }
    Evaluation {
        status: match run {
            None => EvaluationStatus::TimedOut,
            Some(run) if run.succeeded() => EvaluationStatus::Succeeded,
            Some(_) => EvaluationStatus::Failed,
        },
        run_id: run.map(|run| run.run_id),
        open,
        known_exploited: findings
            .iter()
            .filter(|finding| finding.exploitation.known_exploited)
            .count(),
        findings: findings
            .iter()
            .take(MAXIMUM_LISTED_FINDINGS)
            .map(|finding| EvaluationFinding {
                vulnerability: finding.vulnerability_id.clone(),
                component: finding.purl.clone(),
                severity: finding.severity,
                known_exploited: finding.exploitation.known_exploited,
                url: notifications::link(public_url, &format!("findings/{}", finding.id)),
            })
            .collect(),
    }
}

/// `PUT /api/organizations/{organization}/projects/{project}/sbom`: replaces the project's
/// components with those of a CycloneDX JSON document. With `wait` or `fail_on`, waits for the
/// project's evaluation and returns it.
async fn upload_sbom(
    State(state): State<AppState>,
    Path((organization, project)): Path<(String, String)>,
    Query(parameters): Query<UploadParameters>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<UploadResponse>), ApiError> {
    let secret = bearer_token(&headers).ok_or_else(ApiError::unauthorized)?;
    let token = tokens::authenticate(&state.database, secret)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    let threshold = parameters
        .fail_on
        .as_deref()
        .map(Threshold::parse)
        .transpose()?;
    let wait = parse_wait(parameters.wait.as_deref())? || threshold.is_some();

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
    let request = RunRequest {
        trigger: Trigger::Upload,
        scope: Scope::Project(outcome.project_id),
        triggered_by: None,
    };
    let mut status = if outcome.project_created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let mut response = UploadResponse {
        error: None,
        evaluation: None,
        outcome,
    };
    if wait {
        // Waiting runs the project even when runs after uploads are disabled.
        let timeout = Duration::from_secs(state.options.upload_wait_seconds);
        let run = state.runner.request_and_wait(request, timeout).await;
        let findings =
            findings::open_for_upload_token(&state.database, &token, response.outcome.project_id)
                .await?;
        if let Some(threshold) = threshold {
            // Without a finished run the findings are not up to date: that fails first.
            if !run.as_ref().is_some_and(RunOutcome::succeeded) {
                status = StatusCode::SERVICE_UNAVAILABLE;
                response.error = Some("the evaluation did not complete".to_owned());
            } else {
                let reached = findings
                    .iter()
                    .filter(|finding| threshold.reached_by(finding))
                    .count();
                if reached > 0 {
                    status = StatusCode::CONFLICT;
                    response.error = Some(format!(
                        "{reached} open findings at or above {}",
                        threshold.as_str()
                    ));
                }
            }
        }
        response.evaluation = Some(evaluation(
            run.as_ref(),
            &findings,
            &state.options.public_url,
        ));
    } else if state.options.run_after_upload {
        state.runner.request(request);
    }
    Ok((status, Json(response)))
}
