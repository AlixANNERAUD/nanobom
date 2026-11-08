//! The HTTP API used by CI, authenticated with upload tokens.
//!
//! One route: `PUT /api/organizations/{organization}/projects/{project}/sbom`. The token is
//! checked before the body is parsed, so an anonymous client cannot make the server parse
//! anything; the token's reach (its organization, or one project) is then enforced by
//! [`inventory::ingest`]. Parsing runs on the blocking thread pool, a few SBOMs at a time
//! ([`AppState::sbom_parsing`](crate::state::AppState::sbom_parsing)), and the body size is capped
//! by `--maximum-sbom-size`. Errors are English JSON (`{"error": "…"}`), meant for CI logs.
//!
//! # The upload gate
//!
//! Without `wait` or `fail_on`, the upload answers at once and queues a run of the project
//! (unless runs after uploads are disabled). With them, it waits for a run of the project that
//! starts after the upload
//! ([`Runner::request_and_wait`](crate::runner::Runner::request_and_wait)), at most
//! `--upload-wait-seconds`, and returns the project's open findings. `fail_on` then turns the
//! result into a status CI can act on:
//!
//! - `409 Conflict` when open findings reach the threshold (a severity, or `exploited`);
//! - `503 Service Unavailable` when the run did not complete in time or failed, since the
//!   findings would be out of date: an incomplete evaluation never passes the gate.
//!
//! For `fail_on=exploited`, the run worker refreshes the exploitation data before answering
//! waiters, so CVEs first seen in this run count. If that refresh fails or times out, the gate
//! decides on the data already stored. The threshold is refused when exploitation data is
//! disabled, since it could then never fail.

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
    findings::{self, Finding},
    inventory::{self, ParsedSbom, UploadOutcome, UploadSource},
    notifications, tokens,
};
use nanobom_osv::Severity;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::{
    runner::{RunRequest, Waited},
    state::AppState,
};

/// An API error, returned as `{"error": "message"}`.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    /// An error with this status and message; `401` also gets a `WWW-Authenticate: Bearer`
    /// header.
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

/// The upload route, with the body limit of `--maximum-sbom-size`.
pub fn router(state: &AppState) -> Router<AppState> {
    Router::new().route(
        "/api/organizations/{organization}/projects/{project}/sbom",
        put(upload_sbom).layer(DefaultBodyLimit::max(maximum_sbom_bytes(state))),
    )
}

/// `--maximum-sbom-size`, in bytes.
pub(crate) fn maximum_sbom_bytes(state: &AppState) -> usize {
    state.options.maximum_sbom_size.saturating_mul(1024 * 1024)
}

/// Parses an SBOM on the blocking thread pool, a few at a time
/// ([`AppState::sbom_parsing`](crate::state::AppState::sbom_parsing)). The outer error is a
/// parsing task that panicked.
pub(crate) async fn parse_sbom(
    state: &AppState,
    document: Bytes,
) -> Result<nanobom_domain::Result<ParsedSbom>, tokio::task::JoinError> {
    let _permit = state
        .sbom_parsing
        .acquire()
        .await
        .expect("the semaphore is never closed");
    tokio::task::spawn_blocking(move || inventory::parse(&document)).await
}

/// The run that evaluates a project after an upload.
pub(crate) fn upload_run(project_id: i64) -> RunRequest {
    RunRequest {
        trigger: Trigger::Upload,
        scope: Scope::Project(project_id),
        triggered_by: None,
    }
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

    fn reached_by(self, finding: &Finding) -> bool {
        match self {
            Self::Severity(minimum) => finding.severity >= minimum,
            Self::Exploited => finding.exploitation.known_exploited,
        }
    }

    /// Why an upload fails when `reached` (at least one) open findings reach the threshold.
    fn failure(self, reached: usize) -> String {
        let findings = if reached == 1 {
            "open finding"
        } else {
            "open findings"
        };
        match self {
            Self::Severity(minimum) => {
                format!("{reached} {findings} at or above {}", minimum.as_str())
            }
            Self::Exploited => {
                let verb = if reached == 1 { "is" } else { "are" };
                format!("{reached} {findings} {verb} known exploited")
            }
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
    /// The names of the project's direct dependencies that lead to the component; empty when
    /// the SBOM's dependency graph does not say.
    introduced_via: Vec<String>,
    url: String,
}

/// The evaluation of a run and the project's open findings, most severe first.
fn evaluation(run: &Waited, findings: &[Finding], public_url: &Url) -> Evaluation {
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
            Waited::Finished(run) if run.succeeded() => EvaluationStatus::Succeeded,
            Waited::Finished(_) | Waited::NotCompleted => EvaluationStatus::Failed,
            Waited::TimedOut => EvaluationStatus::TimedOut,
        },
        run_id: match run {
            Waited::Finished(run) => Some(run.run_id),
            Waited::NotCompleted | Waited::TimedOut => None,
        },
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
                introduced_via: {
                    let mut names: Vec<String> = finding
                        .introduced_via
                        .iter()
                        .map(|component| component.name.clone())
                        .collect();
                    names.dedup();
                    names
                },
                url: notifications::link(public_url, &format!("findings/{}", finding.id)),
            })
            .collect(),
    }
}

/// `PUT /api/organizations/{organization}/projects/{project}/sbom`: replaces the project's
/// components with those of a CycloneDX or SPDX JSON document. With `wait` or `fail_on`, waits
/// for the project's evaluation and returns it.
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
    // Without exploitation data no finding is known exploited: the gate would always pass.
    if threshold == Some(Threshold::Exploited) && !state.options.exploitation_data {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "fail_on=exploited needs exploitation data (NANOBOM_EXPLOITATION_DATA)",
        ));
    }
    let wait = parse_wait(parameters.wait.as_deref())? || threshold.is_some();

    let sbom = parse_sbom(&state, body)
        .await
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))??;
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
    let request = upload_run(outcome.project_id);
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
            if !matches!(&run, Waited::Finished(outcome) if outcome.succeeded()) {
                status = StatusCode::SERVICE_UNAVAILABLE;
                response.error = Some("the evaluation did not complete".to_owned());
            } else {
                let reached = findings
                    .iter()
                    .filter(|finding| threshold.reached_by(finding))
                    .count();
                if reached > 0 {
                    status = StatusCode::CONFLICT;
                    response.error = Some(threshold.failure(reached));
                }
            }
        }
        response.evaluation = Some(evaluation(&run, &findings, &state.options.public_url));
    } else if state.options.run_after_upload {
        state.runner.request(request);
    }
    Ok((status, Json(response)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_failures_are_counted_in_words() {
        let high = Threshold::Severity(Severity::High);
        assert_eq!(high.failure(1), "1 open finding at or above high");
        assert_eq!(high.failure(2), "2 open findings at or above high");
        assert_eq!(
            Threshold::Exploited.failure(1),
            "1 open finding is known exploited"
        );
        assert_eq!(
            Threshold::Exploited.failure(3),
            "3 open findings are known exploited"
        );
    }
}
