//! The read API: what nanobom knows about organizations, projects, findings, components and
//! runs, as JSON, for scripts, dashboards and integrations. Every route is a `GET`.
//!
//! # Callers
//!
//! A request is authenticated by a token, in `Authorization: Bearer` or, as on the
//! Dependency-Track routes, in `X-Api-Key`; without either, by the interface's session cookie,
//! so pages can call the API too. A token of either scope reads what it reaches, as a viewer;
//! a session reads what the user sees in the interface. Both go through the domain's
//! [`Reader`] checks, so anything out of reach is `404`, like something missing.
//!
//! The routes sit behind the session layer (see [`crate::serve::router`]). They change
//! nothing, so the cross-site request check has nothing to protect here.
//!
//! # Shapes
//!
//! Lists are objects with an `items` array; paginated lists add `total`, `limit` and `offset`
//! (`limit` defaults to [`DEFAULT_LIMIT`], at most [`MAXIMUM_LIMIT`]). Invalid query
//! parameters are `422`, and every error is `{"error": "…"}` in English, as on the upload API.
//! Responses carry a weak `ETag`, and a matching `If-None-Match` is answered `304`. Every
//! response is `Cache-Control: private, no-cache` and varies on the credentials:
//! the same URL answers differently per caller, so a shared cache must never serve one caller's
//! response to another.
//!
//! The paths are unversioned, like the upload API's. The OpenAPI description
//! (`/api/openapi.json`, [`OPENAPI`]) is written by hand and checked against the responses
//! by the server's tests.
//!
//! Server functions of the interface are served as `/api/{name}` too: none may be named like a
//! path of this API (`organizations`, `findings`, `components`, `openapi.json`).

use std::collections::HashMap;

use axum::{
    Router,
    extract::{FromRequestParts, Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, FixedOffset, NaiveDate};
use nanobom_authentication::AuthenticationSession;
use nanobom_domain::{
    access::{Actor, Reader, Role},
    dependencies::{ComponentRef, DependencyPaths},
    evaluation::{self, RunSummary},
    exploitation::Exploitation,
    findings::{self, EventKind, Filter, Finding, FindingDetail, Justification, Status},
    inventory, notifications, organizations, projects, tokens,
};
use nanobom_osv::Severity;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::{api::ApiError, state::AppState};

/// The OpenAPI 3.1 description of the read API, served at `/api/openapi.json`.
pub const OPENAPI: &str = include_str!("openapi.json");

/// Items per page when the request does not say.
pub const DEFAULT_LIMIT: usize = 100;
/// The largest page.
pub const MAXIMUM_LIMIT: usize = 500;
/// Runs listed when the request does not say.
const DEFAULT_RUNS: u64 = 20;
/// The most runs listed.
const MAXIMUM_RUNS: u64 = 100;

/// Every path of the read API, as routed and as described in [`OPENAPI`].
pub const PATHS: [&str; 8] = [
    "/api/openapi.json",
    "/api/organizations",
    "/api/organizations/{organization}/projects",
    "/api/organizations/{organization}/projects/{project}/findings",
    "/api/organizations/{organization}/projects/{project}/components",
    "/api/organizations/{organization}/runs",
    "/api/findings/{finding}",
    "/api/components",
];

pub fn router() -> Router<AppState> {
    Router::new()
        .route(PATHS[0], get(openapi))
        .route(PATHS[1], get(list_organizations))
        .route(PATHS[2], get(list_projects))
        .route(PATHS[3], get(list_findings))
        .route(PATHS[4], get(list_components))
        .route(PATHS[5], get(list_runs))
        .route(PATHS[6], get(finding))
        .route(PATHS[7], get(search_components))
        .layer(middleware::map_response(private_response))
}

/// Marks a response as private to its caller: stored by the caller's own cache only, and
/// revalidated before reuse. Without it, a shared proxy could keep the JSON a session cookie
/// obtained and serve it to anyone asking for the same URL. `Vary` names every credential
/// that changes the answer. The VEX export, which the same callers read, sets it too.
pub(crate) fn private(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-cache"),
    );
    headers.insert(
        header::VARY,
        HeaderValue::from_static("Cookie, Authorization, X-Api-Key"),
    );
}

async fn private_response(mut response: Response) -> Response {
    private(&mut response);
    response
}

/// [`Path`] whose rejection (a segment that is not valid percent-encoded UTF-8) is a JSON
/// error like every other, not axum's plain text.
pub(crate) struct ApiPath<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned + Send> FromRequestParts<S> for ApiPath<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(value)| Self(value))
            .map_err(|rejection| ApiError::new(rejection.status(), rejection.body_text()))
    }
}

/// The reader of a request: the token in `Authorization: Bearer` or `X-Api-Key` when one is
/// sent (an invalid one is `401`, without falling back to the session), else the signed-in
/// user.
pub async fn reader(
    state: &AppState,
    headers: &HeaderMap,
    session: &AuthenticationSession,
) -> Result<Reader, ApiError> {
    let unauthorized = || {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "sign in, or send a token in the Authorization header (Bearer) or in X-Api-Key",
        )
    };
    if headers.contains_key(header::AUTHORIZATION) || headers.contains_key(X_API_KEY) {
        let secret = token_secret(headers).ok_or_else(unauthorized)?;
        let token = tokens::authenticate(&state.database, secret)
            .await?
            .ok_or_else(unauthorized)?;
        return Ok(Reader::from(&token));
    }
    let user = session.user.as_ref().ok_or_else(unauthorized)?;
    // A disabled or deleted user's session no longer reads anything.
    let actor = Actor::load(&state.database, user.id)
        .await
        .map_err(|_| unauthorized())?;
    Ok(Reader::User(actor))
}

const X_API_KEY: &str = "x-api-key";

/// The token of `X-Api-Key`, or of a bearer `Authorization` header.
pub(crate) fn token_secret(headers: &HeaderMap) -> Option<&str> {
    if let Some(value) = headers.get(X_API_KEY) {
        return value
            .to_str()
            .ok()
            .map(str::trim)
            .filter(|value| !value.is_empty());
    }
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token.trim())
}

/// A JSON response with a weak `ETag` of its body, or `304` when `If-None-Match` matches it.
/// Computed from the body, it changes whenever the data does, at the cost of building the
/// response every time. `If-None-Match` uses the weak comparison (RFC 9110, 13.1.2), which
/// ignores the `W/` prefix on either side: proxies and clients may drop it.
fn respond(headers: &HeaderMap, value: &impl Serialize) -> Response {
    let body = match serde_json::to_vec(value) {
        Ok(body) => body,
        Err(error) => {
            tracing::error!(%error, "cannot serialize a response");
            return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                .into_response();
        }
    };
    let digest = Sha256::digest(&body);
    let tag: String = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let etag = format!("W/\"{tag}\"");
    let matches = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|candidate| {
                let candidate = candidate.trim();
                candidate == "*" || opaque_tag(candidate) == opaque_tag(&etag)
            })
        });
    let etag_value = HeaderValue::from_str(&etag).expect("hexadecimal digits");
    if matches {
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag_value)]).into_response();
    }
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (header::ETAG, etag_value),
        ],
        body,
    )
        .into_response()
}

/// An entity tag without its weak prefix.
fn opaque_tag(tag: &str) -> &str {
    tag.strip_prefix("W/").unwrap_or(tag)
}

fn invalid(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, message)
}

/// A query string that does not deserialize (a parameter given twice), as JSON.
fn query_error(rejection: QueryRejection) -> ApiError {
    invalid(rejection.body_text())
}

/// A list without pagination.
#[derive(Serialize)]
struct Items<T> {
    items: Vec<T>,
}

/// A search: the matches, and whether more were found than returned.
#[derive(Serialize)]
struct Matches<T> {
    items: Vec<T>,
    truncated: bool,
}

/// One page of a list.
#[derive(Serialize)]
struct Page<T> {
    items: Vec<T>,
    /// Items in the whole list, across pages.
    total: usize,
    limit: usize,
    offset: usize,
}

/// `limit` and `offset`, as sent.
#[derive(Debug, Default, Deserialize)]
struct Pagination {
    limit: Option<String>,
    offset: Option<String>,
}

impl Pagination {
    fn page<T>(&self, items: Vec<T>) -> Result<Page<T>, ApiError> {
        let limit = match self.limit.as_deref().map(str::trim) {
            None => DEFAULT_LIMIT,
            Some(value) => value
                .parse::<usize>()
                .ok()
                .filter(|limit| (1..=MAXIMUM_LIMIT).contains(limit))
                .ok_or_else(|| {
                    invalid(format!("limit must be a number from 1 to {MAXIMUM_LIMIT}"))
                })?,
        };
        let offset = match self.offset.as_deref().map(str::trim) {
            None => 0,
            Some(value) => value
                .parse::<usize>()
                .map_err(|_| invalid("offset must be a number from 0"))?,
        };
        let total = items.len();
        let items = items.into_iter().skip(offset).take(limit).collect();
        Ok(Page {
            items,
            total,
            limit,
            offset,
        })
    }
}

/// Parses a comma-separated list, each value with `parse`.
fn list_parameter<T>(
    value: Option<&str>,
    parse: impl Fn(&str) -> Option<T>,
    error: &str,
) -> Result<Vec<T>, ApiError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| parse(value).ok_or_else(|| invalid(error)))
        .collect()
}

/// `GET /api/openapi.json`, public: it describes the API, not data.
async fn openapi() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        OPENAPI,
    )
        .into_response()
}

#[derive(Serialize)]
struct OrganizationBody {
    slug: String,
    name: String,
    /// The caller's role; tokens read as viewers.
    role: Role,
}

/// `GET /api/organizations`: the organizations the caller sees, by name.
async fn list_organizations(
    State(state): State<AppState>,
    headers: HeaderMap,
    session: AuthenticationSession,
) -> Result<Response, ApiError> {
    let reader = reader(&state, &headers, &session).await?;
    let items = organizations::list(&state.database, reader)
        .await?
        .into_iter()
        .map(|organization| OrganizationBody {
            slug: organization.slug,
            name: organization.name,
            role: organization.role,
        })
        .collect();
    Ok(respond(&headers, &Items { items }))
}

#[derive(Serialize)]
struct SeverityCountsBody {
    critical: u64,
    high: u64,
    medium: u64,
    low: u64,
    unknown: u64,
}

#[derive(Serialize)]
struct ProjectBody {
    slug: String,
    name: String,
    last_upload_at: Option<DateTime<FixedOffset>>,
    stale: bool,
    open: SeverityCountsBody,
    ignored: u64,
    known_exploited: i64,
    url: String,
}

/// `GET /api/organizations/{organization}/projects`: the projects with their open findings
/// by severity, by slug.
async fn list_projects(
    State(state): State<AppState>,
    ApiPath(organization): ApiPath<String>,
    headers: HeaderMap,
    session: AuthenticationSession,
) -> Result<Response, ApiError> {
    let reader = reader(&state, &headers, &session).await?;
    let organization = organizations::find(&state.database, reader, &organization).await?;
    let items = findings::overview(
        &state.database,
        reader,
        organization.id,
        state.options.stale_after_days,
    )
    .await?
    .into_iter()
    .map(|project| ProjectBody {
        url: notifications::link(
            &state.options.public_url,
            &format!(
                "organizations/{}/projects/{}",
                organization.slug, project.slug
            ),
        ),
        slug: project.slug,
        name: project.name,
        last_upload_at: project.last_upload_at,
        stale: project.stale,
        open: SeverityCountsBody {
            critical: project.open.critical,
            high: project.open.high,
            medium: project.open.medium,
            low: project.open.low,
            unknown: project.open.unknown,
        },
        ignored: project.ignored,
        known_exploited: project.known_exploited,
    })
    .collect();
    Ok(respond(&headers, &Items { items }))
}

#[derive(Serialize)]
struct ComponentBody {
    purl: String,
    name: String,
    version: Option<String>,
    ecosystem: String,
    license: Option<String>,
}

#[derive(Serialize)]
struct ComponentRefBody {
    purl: String,
    name: String,
    version: Option<String>,
}

impl From<ComponentRef> for ComponentRefBody {
    fn from(component: ComponentRef) -> Self {
        Self {
            purl: component.purl,
            name: component.name,
            version: component.version,
        }
    }
}

#[derive(Serialize)]
struct ExploitationBody {
    known_exploited: bool,
    kev_date_added: Option<NaiveDate>,
    kev_due_date: Option<NaiveDate>,
    kev_ransomware: bool,
    epss_score: Option<f64>,
    epss_percentile: Option<f64>,
    epss_date: Option<NaiveDate>,
}

impl From<Exploitation> for ExploitationBody {
    fn from(exploitation: Exploitation) -> Self {
        Self {
            known_exploited: exploitation.known_exploited,
            kev_date_added: exploitation.kev_date_added,
            kev_due_date: exploitation.kev_due_date,
            kev_ransomware: exploitation.kev_ransomware,
            epss_score: exploitation.epss_score,
            epss_percentile: exploitation.epss_percentile,
            epss_date: exploitation.epss_date,
        }
    }
}

/// Why an ignored finding is ignored; `null` unless the finding is ignored.
#[derive(Serialize)]
struct IgnoreBody {
    reason: Option<String>,
    justification: Option<Justification>,
    expires_at: Option<DateTime<FixedOffset>>,
}

#[derive(Serialize)]
struct FindingBody {
    id: i64,
    project: String,
    vulnerability_id: String,
    aliases: Vec<String>,
    summary: Option<String>,
    component: ComponentBody,
    severity: Severity,
    cvss_score: Option<f64>,
    status: Status,
    exploitation: ExploitationBody,
    introduced_via: Vec<ComponentRefBody>,
    first_seen_at: DateTime<FixedOffset>,
    last_seen_at: DateTime<FixedOffset>,
    fixed_at: Option<DateTime<FixedOffset>>,
    ignore: Option<IgnoreBody>,
    url: String,
}

fn finding_body(state: &AppState, finding: Finding) -> FindingBody {
    // The ignore columns keep the latest ignore after a restore: only an ignored finding has
    // a current one.
    let ignore = (finding.status == Status::Ignored).then_some(IgnoreBody {
        reason: finding.ignore_reason,
        justification: finding.ignore_justification,
        expires_at: finding.ignore_expires_at,
    });
    FindingBody {
        url: notifications::link(
            &state.options.public_url,
            &format!("findings/{}", finding.id),
        ),
        id: finding.id,
        project: finding.project_slug,
        vulnerability_id: finding.vulnerability_id,
        aliases: finding.aliases,
        summary: finding.summary,
        component: ComponentBody {
            purl: finding.purl,
            name: finding.component_name,
            version: finding.component_version,
            ecosystem: finding.ecosystem,
            license: finding.license,
        },
        severity: finding.severity,
        cvss_score: finding.cvss_score,
        status: finding.status,
        exploitation: finding.exploitation.into(),
        introduced_via: finding
            .introduced_via
            .into_iter()
            .map(ComponentRefBody::from)
            .collect(),
        first_seen_at: finding.first_seen_at,
        last_seen_at: finding.last_seen_at,
        fixed_at: finding.fixed_at,
        ignore,
    }
}

#[derive(Debug, Default, Deserialize)]
struct FindingParameters {
    status: Option<String>,
    severity: Option<String>,
    exploited: Option<String>,
    ecosystem: Option<String>,
    #[serde(flatten)]
    pagination: Pagination,
}

impl FindingParameters {
    /// The domain filter; without `status`, open and ignored findings, as on the project page.
    fn filter(&self) -> Result<Filter, ApiError> {
        let statuses = match self.status.as_deref().map(str::trim) {
            None => vec![Status::Open, Status::Ignored],
            Some("all") => Vec::new(),
            Some(value) => list_parameter(
                Some(value),
                |value| value.parse().ok(),
                "status must be all, or a comma-separated list of open, ignored and fixed",
            )?,
        };
        let severities = list_parameter(
            self.severity.as_deref(),
            |value| value.parse().ok(),
            "severity must be a comma-separated list of critical, high, medium, low and unknown",
        )?;
        let exploited_only = match self.exploited.as_deref().map(str::trim) {
            None | Some("false") => false,
            Some("true") => true,
            Some(_) => return Err(invalid("exploited must be true or false")),
        };
        Ok(Filter {
            severities,
            statuses,
            ecosystem: self
                .ecosystem
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
            exploited_only,
        })
    }
}

/// The project a path names, if the reader sees it.
async fn project(
    state: &AppState,
    reader: Reader,
    organization: &str,
    project: &str,
) -> Result<nanobom_entity::projects::Model, ApiError> {
    let organization = organizations::find(&state.database, reader, organization).await?;
    Ok(projects::find(&state.database, reader, organization.id, project).await?)
}

/// `GET /api/organizations/{organization}/projects/{project}/findings`: the project's
/// findings, filtered, in the project page's order.
async fn list_findings(
    State(state): State<AppState>,
    ApiPath((organization, project_slug)): ApiPath<(String, String)>,
    parameters: Result<Query<FindingParameters>, QueryRejection>,
    headers: HeaderMap,
    session: AuthenticationSession,
) -> Result<Response, ApiError> {
    let Query(parameters) = parameters.map_err(query_error)?;
    let filter = parameters.filter()?;
    let reader = reader(&state, &headers, &session).await?;
    let project = project(&state, reader, &organization, &project_slug).await?;
    let findings = findings::list(&state.database, reader, project.id, &filter).await?;
    let page = parameters.pagination.page(findings)?;
    let page = Page {
        items: page
            .items
            .into_iter()
            .map(|finding| finding_body(&state, finding))
            .collect(),
        total: page.total,
        limit: page.limit,
        offset: page.offset,
    };
    Ok(respond(&headers, &page))
}

#[derive(Serialize)]
struct ReferenceBody {
    #[serde(rename = "type")]
    kind: String,
    url: String,
}

#[derive(Serialize)]
struct EventBody {
    created_at: DateTime<FixedOffset>,
    kind: EventKind,
    /// The username of the member who acted.
    user: Option<String>,
    /// The name of the token that imported a VEX statement.
    token: Option<String>,
    reason: Option<String>,
    justification: Option<Justification>,
    run_id: Option<i64>,
}

#[derive(Serialize)]
struct DependencyPathsBody {
    paths: Vec<Vec<ComponentRefBody>>,
    more: usize,
    partial: bool,
}

impl From<DependencyPaths> for DependencyPathsBody {
    fn from(paths: DependencyPaths) -> Self {
        Self {
            paths: paths
                .paths
                .into_iter()
                .map(|path| path.into_iter().map(ComponentRefBody::from).collect())
                .collect(),
            more: paths.more,
            partial: paths.partial,
        }
    }
}

#[derive(Serialize)]
struct AffectedComponentBody {
    finding_id: i64,
    organization: String,
    project: String,
    purl: String,
    status: Status,
}

#[derive(Serialize)]
struct FindingDetailBody {
    #[serde(flatten)]
    finding: FindingBody,
    organization: String,
    details: Option<String>,
    published: Option<DateTime<FixedOffset>>,
    modified: DateTime<FixedOffset>,
    cvss_version: Option<String>,
    cvss_vector: Option<String>,
    fixed_versions: Vec<String>,
    references: Vec<ReferenceBody>,
    /// Who ignored the finding, while it is ignored.
    ignored_by: Option<String>,
    ignored_by_token: Option<String>,
    events: Vec<EventBody>,
    dependency_paths: Option<DependencyPathsBody>,
    affected_components: Vec<AffectedComponentBody>,
}

fn finding_detail_body(state: &AppState, detail: FindingDetail) -> FindingDetailBody {
    let ignored = detail.finding.status == Status::Ignored;
    FindingDetailBody {
        finding: finding_body(state, detail.finding),
        organization: detail.organization_slug,
        details: detail.details,
        published: detail.published,
        modified: detail.modified,
        cvss_version: detail.cvss_version,
        cvss_vector: detail.cvss_vector,
        fixed_versions: detail.fixed_versions,
        references: detail
            .references
            .into_iter()
            .map(|reference| ReferenceBody {
                kind: reference.kind,
                url: reference.url,
            })
            .collect(),
        ignored_by: detail.ignored_by.filter(|_| ignored),
        ignored_by_token: detail.ignored_by_token.filter(|_| ignored),
        events: detail
            .events
            .into_iter()
            .map(|event| EventBody {
                created_at: event.created_at,
                kind: event.kind,
                user: event.actor,
                token: event.token,
                reason: event.reason,
                justification: event.justification,
                run_id: event.run_id,
            })
            .collect(),
        dependency_paths: detail.dependency_paths.map(DependencyPathsBody::from),
        affected_components: detail
            .affected_components
            .into_iter()
            .map(|component| AffectedComponentBody {
                finding_id: component.finding_id,
                organization: component.organization_slug,
                project: component.project_slug,
                purl: component.purl,
                status: component.status,
            })
            .collect(),
    }
}

/// `GET /api/findings/{finding}`: one finding with its vulnerability, history and dependency
/// paths.
async fn finding(
    State(state): State<AppState>,
    ApiPath(finding): ApiPath<String>,
    headers: HeaderMap,
    session: AuthenticationSession,
) -> Result<Response, ApiError> {
    let reader = reader(&state, &headers, &session).await?;
    // Not a number: no such finding, answered like any other.
    let finding: i64 = finding
        .parse()
        .map_err(|_| ApiError::from(nanobom_domain::Error::NotFound))?;
    let detail = findings::detail(&state.database, reader, finding).await?;
    Ok(respond(&headers, &finding_detail_body(&state, detail)))
}

/// `GET /api/organizations/{organization}/projects/{project}/components`: the project's
/// current components, by package URL.
async fn list_components(
    State(state): State<AppState>,
    ApiPath((organization, project_slug)): ApiPath<(String, String)>,
    pagination: Result<Query<Pagination>, QueryRejection>,
    headers: HeaderMap,
    session: AuthenticationSession,
) -> Result<Response, ApiError> {
    let Query(pagination) = pagination.map_err(query_error)?;
    let reader = reader(&state, &headers, &session).await?;
    let project = project(&state, reader, &organization, &project_slug).await?;
    let components = inventory::components(&state.database, reader, project.id)
        .await?
        .into_iter()
        .map(|component| ComponentBody {
            purl: component.purl,
            name: component.name,
            version: component.version,
            ecosystem: component.ecosystem,
            license: component.license,
        })
        .collect();
    Ok(respond(&headers, &pagination.page(components)?))
}

#[derive(Serialize)]
struct ComponentMatchBody {
    organization: String,
    project: String,
    purl: String,
    name: String,
    version: Option<String>,
    ecosystem: String,
    license: Option<String>,
}

/// `GET /api/components?q=…&license=…`: components by name (and version prefix), license or
/// both across the projects the caller sees, at most [`inventory::MAXIMUM_SEARCH_RESULTS`].
async fn search_components(
    State(state): State<AppState>,
    parameters: Result<Query<HashMap<String, String>>, QueryRejection>,
    headers: HeaderMap,
    session: AuthenticationSession,
) -> Result<Response, ApiError> {
    let Query(parameters) = parameters.map_err(query_error)?;
    let text = |name: &str| parameters.get(name).map_or("", |value| value.trim());
    let (query, license) = (text("q"), text("license"));
    if query.is_empty() && license.is_empty() {
        return Err(invalid(
            "q, the name to search for, or license, the license to search for, is required",
        ));
    }
    let reader = reader(&state, &headers, &session).await?;
    let found = inventory::search_by_license(&state.database, reader, query, license).await?;
    let items = found
        .matches
        .into_iter()
        .map(|component| ComponentMatchBody {
            organization: component.organization_slug,
            project: component.project_slug,
            purl: component.purl,
            name: component.name,
            version: component.version,
            ecosystem: component.ecosystem,
            license: component.license,
        })
        .collect();
    Ok(respond(
        &headers,
        &Matches {
            items,
            truncated: found.truncated,
        },
    ))
}

#[derive(Serialize)]
struct RunBody {
    id: i64,
    trigger: String,
    scope: String,
    status: String,
    started_at: DateTime<FixedOffset>,
    finished_at: Option<DateTime<FixedOffset>>,
    error: Option<String>,
    /// `null` for a whole-instance run, unless the caller is an instance administrator.
    new_findings: Option<i64>,
    fixed_findings: Option<i64>,
}

impl From<RunSummary> for RunBody {
    fn from(run: RunSummary) -> Self {
        Self {
            id: run.id,
            trigger: run.trigger,
            scope: run.scope,
            status: run.status,
            started_at: run.started_at,
            finished_at: run.finished_at,
            error: run.error,
            new_findings: run.new_findings,
            fixed_findings: run.fixed_findings,
        }
    }
}

/// `GET /api/organizations/{organization}/runs`: the latest runs that covered the
/// organization, newest first.
async fn list_runs(
    State(state): State<AppState>,
    ApiPath(organization): ApiPath<String>,
    parameters: Result<Query<Pagination>, QueryRejection>,
    headers: HeaderMap,
    session: AuthenticationSession,
) -> Result<Response, ApiError> {
    let Query(parameters) = parameters.map_err(query_error)?;
    // The list is short and has no total: refusing is better than ignoring a parameter that
    // would make a client loop forever on the same page.
    if parameters.offset.is_some() {
        return Err(invalid(
            "offset is not supported on runs: use limit, up to 100",
        ));
    }
    let limit = match parameters.limit.as_deref().map(str::trim) {
        None => DEFAULT_RUNS,
        Some(value) => value
            .parse::<u64>()
            .ok()
            .filter(|limit| (1..=MAXIMUM_RUNS).contains(limit))
            .ok_or_else(|| invalid(format!("limit must be a number from 1 to {MAXIMUM_RUNS}")))?,
    };
    let reader = reader(&state, &headers, &session).await?;
    let organization = organizations::find(&state.database, reader, &organization).await?;
    let items = evaluation::recent_runs(&state.database, reader, organization.id, limit)
        .await?
        .into_iter()
        .map(RunBody::from)
        .collect();
    Ok(respond(&headers, &Items { items }))
}
