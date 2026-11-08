//! The part of Dependency-Track's API that CI clients use to upload SBOMs, so that pipelines
//! written for Dependency-Track (gh-upload-sbom, the Jenkins plugin, the Maven plugin, scripts)
//! upload to nanobom unchanged.
//!
//! Routes, as in Dependency-Track 4.x and 5.x:
//!
//! - `PUT /api/v1/bom`: a JSON body with the SBOM base64-encoded in `bom`;
//! - `POST /api/v1/bom`: a multipart form with the SBOM in the `bom` part;
//! - `GET /api/v1/bom/token/{uuid}` and `GET /api/v1/event/token/{uuid}`: whether the upload
//!   with this token is still being processed (`{"processing": true}`).
//!
//! The upload token travels in `X-Api-Key` (a bearer `Authorization` header works too) and gives
//! the organization. `projectName` is the project slug, normalized like the native endpoint;
//! `projectVersion` is recorded as the upload's image tag. A project UUID (`project`) means
//! nothing to nanobom and is refused unless `projectName` comes with it. Other fields (tags,
//! parent, `isLatest`, `isActive`) are accepted and ignored. The SBOM goes through the same
//! parsing, ingestion and run after upload as [`crate::api`], with the same size limit, applied to
//! the decoded SBOM.
//!
//! Responses follow Dependency-Track's shapes, which its clients parse: `200` with
//! `{"token": "<uuid>"}`, plain-text error messages, and an RFC 9457 problem
//! (`application/problem+json`) for an invalid SBOM.
//!
//! # Processing tokens
//!
//! A token is processing from the upload until the run of the project it queued has finished
//! (stage 3 of the [`runner`](crate::runner), so the exploitation data is fresh), at most
//! `--upload-wait-seconds`. Tokens live in memory only and are forgotten once done: like
//! Dependency-Track, an unknown token reads as not processing, which also covers tokens issued
//! before a restart, tokens of other organizations, and uploads when runs after uploads are
//! disabled.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use base64::Engine;
use nanobom_domain::{
    inventory::{self, UploadSource},
    names,
    problem::Field,
    tokens,
};
use nanobom_entity::upload_tokens;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{api, state::AppState};

/// The routes, with body limits leaving room for the encoding around the SBOM. The SBOM itself
/// is then held to `--maximum-sbom-size`.
pub fn router(state: &AppState) -> Router<AppState> {
    let maximum = api::maximum_sbom_bytes(state);
    let envelope = 64 * 1024;
    Router::new()
        .route(
            "/api/v1/bom",
            put(upload_json)
                .layer(DefaultBodyLimit::max(
                    json_body_limit(maximum).saturating_add(envelope),
                ))
                .merge(
                    post(upload_form)
                        .layer(DefaultBodyLimit::max(maximum.saturating_add(envelope))),
                ),
        )
        .route("/api/v1/bom/token/{token}", get(processing_status))
        .route("/api/v1/event/token/{token}", get(processing_status))
}

/// The largest JSON body, without its envelope, that carries an SBOM of `maximum` bytes: base64
/// makes it a third larger, and the line breaks of wrapped base64 (a `\r\n` every 76
/// characters, which JSON escapes as 4 bytes, the worst case) add another 1/19.
fn json_body_limit(maximum: usize) -> usize {
    let encoded = maximum.div_ceil(3).saturating_mul(4);
    encoded.saturating_add(encoded / 19 + 4)
}

/// The tokens of uploads whose run has not finished yet, with their organization.
#[derive(Clone, Default)]
pub struct ProcessingTokens {
    tokens: Arc<Mutex<HashMap<Uuid, i64>>>,
}

impl ProcessingTokens {
    fn start(&self, organization_id: i64) -> Uuid {
        let token = Uuid::new_v4();
        self.tokens
            .lock()
            .expect("not poisoned")
            .insert(token, organization_id);
        token
    }

    fn finish(&self, token: Uuid) {
        self.tokens.lock().expect("not poisoned").remove(&token);
    }

    fn is_processing(&self, token: Uuid, organization_id: i64) -> bool {
        self.tokens.lock().expect("not poisoned").get(&token) == Some(&organization_id)
    }
}

/// An error, in the shapes Dependency-Track answers with.
#[derive(Debug)]
pub struct Error {
    status: StatusCode,
    message: String,
    /// An RFC 9457 problem with this title, instead of plain text.
    problem_title: Option<&'static str>,
}

impl Error {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            problem_title: None,
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    fn invalid_sbom(detail: String) -> Self {
        Self {
            problem_title: Some("The uploaded BOM is invalid"),
            ..Self::bad_request(detail)
        }
    }

    fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "a valid nanobom upload token is required in the X-Api-Key header",
        )
    }

    fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}

#[derive(Serialize)]
struct ProblemBody<'a> {
    status: u16,
    title: &'a str,
    detail: &'a str,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self.problem_title {
            Some(title) => (
                self.status,
                [(header::CONTENT_TYPE, "application/problem+json")],
                Json(ProblemBody {
                    status: self.status.as_u16(),
                    title,
                    detail: &self.message,
                }),
            )
                .into_response(),
            None => (self.status, self.message).into_response(),
        }
    }
}

impl From<nanobom_domain::Error> for Error {
    fn from(error: nanobom_domain::Error) -> Self {
        use nanobom_domain::Error as E;
        match error {
            E::NotFound => Self::new(StatusCode::NOT_FOUND, "The project could not be found."),
            E::Forbidden => Self::new(
                StatusCode::FORBIDDEN,
                "Access to the specified project is forbidden",
            ),
            E::Invalid(problem) => Self::bad_request(problem.to_string()),
            E::Conflict(problem) => Self::new(StatusCode::CONFLICT, problem.to_string()),
            E::Database(error) => {
                tracing::error!(%error, "database error");
                Self::internal()
            }
        }
    }
}

/// Authenticates the upload token in `X-Api-Key`, or in a bearer `Authorization` header.
async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<upload_tokens::Model, Error> {
    let api_key = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim);
    let bearer = || {
        let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
        let (scheme, token) = value.split_once(' ')?;
        scheme
            .eq_ignore_ascii_case("bearer")
            .then_some(token.trim())
    };
    let secret = api_key.or_else(bearer).ok_or_else(Error::unauthorized)?;
    tokens::authenticate(&state.database, secret)
        .await?
        .ok_or_else(Error::unauthorized)
}

/// The body of `PUT /api/v1/bom` (Dependency-Track's `BomSubmitRequest`); other fields are
/// ignored.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubmitRequest {
    project: Option<String>,
    project_name: Option<String>,
    project_version: Option<String>,
    /// A boolean, or a string as Dependency-Track's JSON parser also accepts.
    #[serde(default)]
    auto_create: Value,
    bom: Option<String>,
}

/// An upload, whichever way it was sent.
struct Submission {
    project: Option<String>,
    project_name: Option<String>,
    project_version: Option<String>,
    auto_create: bool,
    bom: Bytes,
}

#[derive(Debug, Serialize)]
struct UploadResponse {
    token: Uuid,
}

/// `PUT /api/v1/bom`.
async fn upload_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<UploadResponse>, Error> {
    let token = authenticate(&state, &headers).await?;
    let (request, bom) = decode_request(body)?;
    let auto_create = match &request.auto_create {
        Value::Bool(value) => *value,
        Value::String(value) => value.trim().eq_ignore_ascii_case("true"),
        _ => false,
    };
    submit(
        &state,
        &token,
        Submission {
            project: request.project,
            project_name: request.project_name,
            project_version: request.project_version,
            auto_create,
            bom,
        },
    )
    .await
}

/// Reads the request and decodes its SBOM. Takes the raw body by value so that it is freed before
/// the caller waits for a parsing slot and parses: the body is a third larger than the SBOM, and
/// holding it (and the base64 text) through the parse would triple the memory of an upload.
fn decode_request(body: Bytes) -> Result<(SubmitRequest, Bytes), Error> {
    // Parsed by hand rather than with `Json`: scripts do not always send a JSON content type.
    let mut request: SubmitRequest = serde_json::from_slice(&body)
        .map_err(|error| Error::bad_request(format!("invalid upload request: {error}")))?;
    drop(body);
    let mut encoded = request.bom.take().unwrap_or_default();
    // Wrapped base64, as `base64` prints by default, is accepted too. Dependency-Track's own
    // check is stricter: it refuses line breaks, and unpadded text.
    encoded.retain(|character| !character.is_ascii_whitespace());
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .map_err(|_| Error::bad_request("The BOM must be Base64 encoded"))?;
    Ok((request, Bytes::from(decoded)))
}

/// `POST /api/v1/bom`. The token is checked before the form is read.
async fn upload_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut form: Multipart,
) -> Result<Json<UploadResponse>, Error> {
    let token = authenticate(&state, &headers).await?;
    let mut submission = Submission {
        project: None,
        project_name: None,
        project_version: None,
        auto_create: false,
        bom: Bytes::new(),
    };
    let mut bom = None;
    let read_error = |error: axum::extract::multipart::MultipartError| {
        Error::new(error.status(), error.body_text())
    };
    while let Some(field) = form.next_field().await.map_err(read_error)? {
        let name = field.name().unwrap_or_default().to_owned();
        // Like Dependency-Track, only the first `bom` part counts.
        if name == "bom" {
            if bom.is_none() {
                bom = Some(field.bytes().await.map_err(read_error)?);
            }
            continue;
        }
        let value = field.text().await.map_err(read_error)?;
        match name.as_str() {
            "project" => submission.project = Some(value),
            "projectName" => submission.project_name = Some(value),
            "projectVersion" => submission.project_version = Some(value),
            "autoCreate" => submission.auto_create = value.trim().eq_ignore_ascii_case("true"),
            _ => {}
        }
    }
    submission.bom = bom.ok_or_else(|| Error::bad_request("No BOM file provided."))?;
    submit(&state, &token, submission).await
}

/// Stores an upload and queues the project's run, like the native endpoint without `wait`.
async fn submit(
    state: &AppState,
    token: &upload_tokens::Model,
    submission: Submission,
) -> Result<Json<UploadResponse>, Error> {
    let project_slug = match nonblank(submission.project_name) {
        Some(name) => names::slug(Field::ProjectSlug, &name).map_err(|_| {
            Error::bad_request(format!(
                "projectName \"{}\" cannot be a nanobom project slug: use 1 to {} \
                 letters, digits, '.', '_' or '-', starting with a letter or a digit",
                truncated(&name, 80),
                names::MAXIMUM_LENGTH
            ))
        })?,
        None if nonblank(submission.project).is_some() => {
            return Err(Error::bad_request(
                "nanobom cannot find projects by UUID: send projectName (the nanobom project \
                 slug) instead of project",
            ));
        }
        None => return Err(Error::bad_request("projectName is required")),
    };
    let sbom = sbom_document(submission.bom);
    if sbom.is_empty() {
        return Err(Error::bad_request("No BOM file provided."));
    }
    if sbom.len() > api::maximum_sbom_bytes(state) {
        return Err(Error::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "the SBOM is larger than the server's maximum SBOM size",
        ));
    }
    let sbom = match api::parse_sbom(state, sbom).await {
        Ok(Ok(sbom)) => sbom,
        Ok(Err(nanobom_domain::Error::Invalid(problem))) => {
            return Err(Error::invalid_sbom(problem.to_string()));
        }
        Ok(Err(error)) => return Err(error.into()),
        Err(_) => return Err(Error::internal()),
    };
    let outcome = inventory::ingest_into_token_organization(
        &state.database,
        token,
        &project_slug,
        sbom,
        UploadSource {
            source_commit: None,
            image_tag: submission.project_version,
        },
        submission.auto_create,
    )
    .await?;

    let request = api::upload_run(outcome.project_id);
    if !state.options.run_after_upload {
        return Ok(Json(UploadResponse {
            token: Uuid::new_v4(),
        }));
    }
    let upload_token = state.processing_tokens.start(token.organization_id);
    let processing_tokens = state.processing_tokens.clone();
    let runner = state.runner.clone();
    let timeout = Duration::from_secs(state.options.upload_wait_seconds);
    tokio::spawn(async move {
        runner.request_and_wait(request, timeout).await;
        processing_tokens.finish(upload_token);
    });
    Ok(Json(UploadResponse {
        token: upload_token,
    }))
}

/// At most `limit` characters of `text`, with an ellipsis when it is cut: the name comes from
/// the client and is echoed in an error.
fn truncated(text: &str, limit: usize) -> String {
    match text.char_indices().nth(limit) {
        Some((end, _)) => format!("{}...", &text[..end]),
        None => text.to_owned(),
    }
}

fn nonblank(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// The SBOM without a UTF-8 byte order mark, which Dependency-Track strips and JSON forbids.
fn sbom_document(bom: Bytes) -> Bytes {
    match bom.strip_prefix(b"\xEF\xBB\xBF") {
        Some(_) => bom.slice(3..),
        None => bom,
    }
}

#[derive(Debug, Serialize)]
struct ProcessingStatus {
    processing: bool,
}

/// `GET /api/v1/bom/token/{token}` and `GET /api/v1/event/token/{token}`.
async fn processing_status(
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ProcessingStatus>, Error> {
    let upload_token = authenticate(&state, &headers).await?;
    let token = Uuid::try_parse(token.trim())
        .map_err(|_| Error::bad_request("the token must be a UUID"))?;
    Ok(Json(ProcessingStatus {
        processing: state
            .processing_tokens
            .is_processing(token, upload_token.organization_id),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_order_marks_are_removed() {
        assert_eq!(
            sbom_document(Bytes::from_static(b"\xEF\xBB\xBF{}")),
            Bytes::from_static(b"{}")
        );
        assert_eq!(
            sbom_document(Bytes::from_static(b"{}")),
            Bytes::from_static(b"{}")
        );
    }

    #[test]
    fn long_names_are_cut_for_messages() {
        assert_eq!(truncated("web", 80), "web");
        assert_eq!(truncated("éééé", 4), "éééé");
        assert_eq!(truncated("ééééé", 4), "éééé...");
    }

    #[test]
    fn the_body_limit_covers_base64_with_line_breaks() {
        for maximum in [1024_usize, 1024 * 1024, 5 * 1024 * 1024 + 1] {
            let encoded = maximum.div_ceil(3) * 4;
            // One `\r\n` per 76 characters, as 4 bytes in JSON.
            let wrapped = encoded + encoded.div_ceil(76) * 4;
            assert!(json_body_limit(maximum) >= wrapped, "{maximum}");
        }
    }

    #[test]
    fn tokens_are_processing_for_their_organization_until_finished() {
        let tokens = ProcessingTokens::default();
        let token = tokens.start(1);
        assert!(tokens.is_processing(token, 1));
        assert!(!tokens.is_processing(token, 2));
        tokens.finish(token);
        assert!(!tokens.is_processing(token, 1));
    }
}
