//! The HTTP API used by CI, authenticated with upload tokens.
//!
//! One route: `PUT /api/organizations/{organization}/projects/{project}/sbom`, with an optional
//! `version` (the project version the SBOM describes, never read from the SBOM itself) and
//! `latest` ([`nanobom_domain::versions`]). The token is
//! checked before the body is parsed, so an anonymous client, or one with a read token, cannot
//! make the server parse anything; the token's reach (its organization, or one project) is then enforced by
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
//! `--upload-wait-seconds`, and returns the open findings of the version uploaded (the run
//! covers every version of the project, the gate only this one). `fail_on` then turns the
//! result into a status CI can act on:
//!
//! - `409 Conflict` when open findings reach a threshold (a severity, or `exploited`), or, with
//!   `license`, when a component has a license the organization's policy forbids
//!   ([`nanobom_domain::licenses`]);
//! - `503 Service Unavailable` when the run did not complete in time or failed, since the
//!   findings would be out of date: an incomplete evaluation never passes the gate.
//!
//! `fail_on` takes one threshold or several, separated by commas (`high,license`); the upload
//! fails when any of them is reached. Licenses do not depend on the run, so `fail_on=license`
//! alone still waits, to return the evaluation, but does not fail when the run does not
//! complete.
//!
//! At most `--max-waiting-uploads` uploads wait at once; another one is refused with `503` and
//! `Retry-After` before its body is parsed, so nothing is stored. The token is checked again
//! once the wait is over: one revoked meanwhile gets `401`, as an invalid token would, and its
//! SBOM, accepted while the token was valid, stays stored.
//!
//! VEX statements in the SBOM's `vulnerabilities` ([`nanobom_domain::vex`]) are imported with
//! the upload's token: after the run and before the gate when the upload waits, so they cover
//! the findings this run opened and the gate does not count them; at once otherwise.
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
    licenses::{self, Action, Violations},
    notifications, tokens, versions, vex,
};
use nanobom_entity::upload_tokens;
use nanobom_osv::Severity;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::OwnedSemaphorePermit;

use crate::{
    runner::{RunRequest, Waited},
    state::AppState,
};

/// An API error, returned as `{"error": "message"}`.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
    /// Seconds after which the client may try again, sent as `Retry-After`.
    retry_after: Option<u64>,
}

impl ApiError {
    /// An error with this status and message; `401` also gets a `WWW-Authenticate: Bearer`
    /// header.
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            retry_after: None,
        }
    }

    pub(crate) fn unauthorized() -> Self {
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
        if let Some(seconds) = self.retry_after {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, seconds.into());
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
    parse_document(state, document, inventory::parse).await
}

/// Parses a CycloneDX document with `parse` on the blocking thread pool, sharing the limit of
/// SBOM parsing. The outer error is a parsing task that panicked.
pub(crate) async fn parse_document<T: Send + 'static>(
    state: &AppState,
    document: Bytes,
    parse: fn(&[u8]) -> nanobom_domain::Result<T>,
) -> Result<nanobom_domain::Result<T>, tokio::task::JoinError> {
    let _permit = state
        .sbom_parsing
        .acquire()
        .await
        .expect("the semaphore is never closed");
    tokio::task::spawn_blocking(move || parse(&document)).await
}

/// The active token of the `Authorization` header, if it may upload: anything else is `401`,
/// and a read token `403`, before the body is parsed.
pub(crate) async fn upload_token(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<upload_tokens::Model, ApiError> {
    let token = authenticated_token(state, headers).await?;
    match tokens::Scope::of(&token) {
        tokens::Scope::Upload => Ok(token),
        tokens::Scope::Read => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "this token is read-only: uploads need a token with the upload scope",
        )),
    }
}

/// The active token of the `Authorization` header, of any scope; anything else is `401`.
async fn authenticated_token(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<upload_tokens::Model, ApiError> {
    let secret = bearer_token(headers).ok_or_else(ApiError::unauthorized)?;
    tokens::authenticate(&state.database, secret)
        .await?
        .ok_or_else(ApiError::unauthorized)
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
    /// The project version the SBOM describes; the unnamed version when absent.
    version: Option<String>,
    /// `true` makes the version the latest; `false` keeps a version this upload creates from
    /// becoming the latest.
    latest: Option<String>,
    /// `true` to wait for the project's evaluation and return it.
    wait: Option<String>,
    /// Answer with an error status when one of these thresholds is reached (comma-separated);
    /// implies `wait`.
    fail_on: Option<String>,
}

fn parse_wait(value: Option<&str>) -> Result<bool, ApiError> {
    Ok(parse_flag("wait", value)?.unwrap_or(false))
}

/// A `true` or `false` parameter; `None` when absent.
fn parse_flag(name: &str, value: Option<&str>) -> Result<Option<bool>, ApiError> {
    match value.map(str::trim) {
        None => Ok(None),
        Some("false") => Ok(Some(false)),
        Some("true") => Ok(Some(true)),
        Some(_) => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{name} must be true or false"),
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
    /// A component whose license the organization's policy forbids.
    License,
}

impl Threshold {
    fn parse(value: &str) -> Result<Self, ApiError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "critical" => Ok(Self::Severity(Severity::Critical)),
            "high" => Ok(Self::Severity(Severity::High)),
            "medium" => Ok(Self::Severity(Severity::Medium)),
            "low" => Ok(Self::Severity(Severity::Low)),
            "exploited" => Ok(Self::Exploited),
            "license" => Ok(Self::License),
            _ => Err(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "fail_on must be critical, high, medium, low, exploited or license, or several \
                 of them separated by commas",
            )),
        }
    }

    /// Parses `fail_on`: one threshold or several, separated by commas, each kept once.
    fn parse_list(value: &str) -> Result<Vec<Self>, ApiError> {
        let mut thresholds = Vec::new();
        for value in value.split(',') {
            let threshold = Self::parse(value)?;
            if !thresholds.contains(&threshold) {
                thresholds.push(threshold);
            }
        }
        Ok(thresholds)
    }

    /// Whether the threshold judges findings, which only a completed run brings up to date.
    fn needs_run(self) -> bool {
        !matches!(self, Self::License)
    }

    fn reached_by(self, finding: &Finding) -> bool {
        match self {
            Self::Severity(minimum) => finding.severity >= minimum,
            Self::Exploited => finding.exploitation.known_exploited,
            Self::License => false,
        }
    }

    /// Why an upload fails when `reached` (at least one) open findings, or components for
    /// [`Threshold::License`], reach the threshold.
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
            Self::License => {
                if reached == 1 {
                    "1 component has a forbidden license".to_owned()
                } else {
                    format!("{reached} components have forbidden licenses")
                }
            }
        }
    }
}

/// The `Retry-After` of an upload refused because `--max-waiting-uploads` uploads already wait.
/// A guess: slots free up as runs finish, which takes seconds to minutes.
const WAITING_UPLOADS_RETRY_AFTER_SECONDS: u64 = 30;

/// A slot among the uploads allowed to wait at once, or `503` when none is free.
///
/// Taken before the body is parsed, so that a refused upload stores nothing and the client can
/// send it again unchanged.
fn waiting_slot(state: &AppState) -> Result<OwnedSemaphorePermit, ApiError> {
    // The semaphore is never closed, so the only failure is that no permit is left.
    std::sync::Arc::clone(&state.waiting_uploads)
        .try_acquire_owned()
        .map_err(|_| ApiError {
            retry_after: Some(WAITING_UPLOADS_RETRY_AFTER_SECONDS),
            ..ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "too many uploads are waiting for their evaluation (at most {}, \
                     NANOBOM_MAX_WAITING_UPLOADS): nothing was stored, retry later",
                    state.options.max_waiting_uploads
                ),
            )
        })
}

/// At most this many findings are listed in an upload's evaluation; all are counted.
const MAXIMUM_LISTED_FINDINGS: usize = 100;

/// At most this many license violations are listed in an upload's evaluation; all are counted.
const MAXIMUM_LISTED_VIOLATIONS: usize = 20;

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
    /// What the SBOM's VEX statements (its analysed `vulnerabilities`) did, when it has some.
    #[serde(skip_serializing_if = "Option::is_none")]
    vex: Option<vex::ImportOutcome>,
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
    /// The components breaking the organization's license policy, when it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    licenses: Option<LicenseEvaluation>,
}

/// License violations after an upload: every one counted, the first ones listed.
#[derive(Debug, Serialize)]
struct LicenseEvaluation {
    forbidden: u64,
    warned: u64,
    /// Forbidden first, then warned, each by name; at most `MAXIMUM_LISTED_VIOLATIONS`.
    violations: Vec<LicenseViolation>,
}

#[derive(Debug, Serialize)]
struct LicenseViolation {
    component: String,
    name: String,
    version: Option<String>,
    /// The license as read from the SBOM.
    license: Option<String>,
    verdict: Action,
    /// The identifiers that lead to the verdict; empty when the action for unknown licenses
    /// alone gives it.
    licenses: Vec<String>,
}

impl LicenseEvaluation {
    /// `None` when the organization has no active policy.
    fn new(violations: Violations) -> Option<Self> {
        violations.active.then(|| Self {
            forbidden: violations.counts.forbidden,
            warned: violations.counts.warned,
            violations: violations
                .items
                .into_iter()
                .map(|violation| LicenseViolation {
                    component: violation.purl,
                    name: violation.name,
                    version: violation.version,
                    license: violation.license,
                    verdict: violation.verdict,
                    licenses: violation.licenses,
                })
                .collect(),
        })
    }
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

/// The evaluation of a run and the uploaded version's open findings, most severe first.
fn evaluation(
    run: &Waited,
    findings: &[Finding],
    licenses: Option<LicenseEvaluation>,
    public_url: &Url,
) -> Evaluation {
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
        licenses,
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
    let token = upload_token(&state, &headers).await?;
    let thresholds = parameters
        .fail_on
        .as_deref()
        .map(Threshold::parse_list)
        .transpose()?
        .unwrap_or_default();
    // Without exploitation data no finding is known exploited: the gate would always pass.
    if thresholds.contains(&Threshold::Exploited) && !state.options.exploitation_data {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "fail_on=exploited needs exploitation data (NANOBOM_EXPLOITATION_DATA)",
        ));
    }
    // Checked before the body is parsed: a mistyped version stores nothing.
    let version = parameters
        .version
        .as_deref()
        .map(versions::validate_name)
        .transpose()?;
    let latest = parse_flag("latest", parameters.latest.as_deref())?;
    let wait = parse_wait(parameters.wait.as_deref())? || !thresholds.is_empty();
    // Held through the wait, until the handler returns.
    let _waiting_slot = wait.then(|| waiting_slot(&state)).transpose()?;

    let mut sbom = parse_sbom(&state, body)
        .await
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))??;
    let statements = std::mem::take(&mut sbom.vex);
    let outcome = inventory::ingest(
        &state.database,
        &token,
        &organization,
        &project,
        sbom,
        UploadSource {
            source_commit: parameters.source_commit,
            image_tag: parameters.image_tag,
            version,
            latest,
        },
    )
    .await?;
    let request = upload_run(outcome.project_id);
    let mut status = if outcome.project_created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let project_id = outcome.project_id;
    let version = outcome.version.clone();
    let mut response = UploadResponse {
        error: None,
        evaluation: None,
        vex: None,
        outcome,
    };
    if wait {
        // Waiting runs the project even when runs after uploads are disabled.
        let timeout = Duration::from_secs(state.options.upload_wait_seconds);
        let run = state.runner.request_and_wait(request, timeout).await;
        // The wait can last minutes: a token revoked meanwhile gets neither the evaluation nor
        // its VEX statements imported. The SBOM stays, accepted while the token was valid.
        if !tokens::is_active(&state.database, token.id).await? {
            return Err(ApiError::unauthorized());
        }
        // After the run, so that the statements also reach the findings it opened, and before
        // the gate, which then counts only what the SBOM does not say is unaffected.
        if !statements.is_empty() {
            response.vex = Some(
                vex::import_into_project(
                    &state.database,
                    &token,
                    project_id,
                    &version,
                    &statements,
                )
                .await?,
            );
        }
        // The gate judges the version uploaded: other versions have their own uploads.
        let findings =
            findings::open_for_upload_token(&state.database, &token, project_id, &version).await?;
        // Counted by the database and listed from the first components: cheap enough to
        // return whether the gate checks licenses or not.
        let violations = licenses::violations_in_version(
            &state.database,
            &token,
            project_id,
            Some(&version),
            0,
            MAXIMUM_LISTED_VIOLATIONS,
        )
        .await?;
        let completed = matches!(&run, Waited::Finished(outcome) if outcome.succeeded());
        let mut failures = Vec::new();
        for threshold in &thresholds {
            let reached = match threshold {
                Threshold::License => {
                    usize::try_from(violations.counts.forbidden).unwrap_or(usize::MAX)
                }
                // Judged below, once, if the findings are up to date.
                _ if !completed => 0,
                _ => findings
                    .iter()
                    .filter(|finding| threshold.reached_by(finding))
                    .count(),
            };
            if reached > 0 {
                failures.push(threshold.failure(reached));
            }
        }
        // Without a finished run the findings are not up to date: that fails first.
        if !completed && thresholds.iter().any(|threshold| threshold.needs_run()) {
            status = StatusCode::SERVICE_UNAVAILABLE;
            failures.insert(0, "the evaluation did not complete".to_owned());
        } else if !failures.is_empty() {
            status = StatusCode::CONFLICT;
        }
        if !failures.is_empty() {
            response.error = Some(failures.join("; "));
        }
        response.evaluation = Some(evaluation(
            &run,
            &findings,
            LicenseEvaluation::new(violations),
            &state.options.public_url,
        ));
    } else {
        // Without waiting, only the findings of earlier runs can be matched: the run that
        // follows may open findings the statements cover, which the next upload then ignores.
        if !statements.is_empty() {
            response.vex = Some(
                vex::import_into_project(
                    &state.database,
                    &token,
                    project_id,
                    &version,
                    &statements,
                )
                .await?,
            );
        }
        if state.options.run_after_upload {
            state.runner.request(request);
        }
    }
    Ok((status, Json(response)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_on_takes_a_list() {
        assert_eq!(
            Threshold::parse_list("high").unwrap(),
            vec![Threshold::Severity(Severity::High)]
        );
        assert_eq!(
            Threshold::parse_list(" High , license,high").unwrap(),
            vec![Threshold::Severity(Severity::High), Threshold::License]
        );
        for invalid in ["", "high,", "licence", "high;license"] {
            assert!(Threshold::parse_list(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn gate_failures_are_counted_in_words() {
        assert_eq!(
            Threshold::License.failure(1),
            "1 component has a forbidden license"
        );
        assert_eq!(
            Threshold::License.failure(2),
            "2 components have forbidden licenses"
        );
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
