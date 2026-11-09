//! VEX documents of a project ([`nanobom_domain::vex`]), on
//! `/api/organizations/{organization}/projects/{project}/vex`:
//!
//! - `GET` exports the findings of a project version as a CycloneDX 1.6 VEX document. It accepts
//!   the callers of the read API ([`read_api::reader`]): a token of either scope, or the session
//!   cookie, so the project page can link to it.
//! - `PUT` imports a CycloneDX VEX document into a project version, with an upload token only
//!   (read tokens are `403`): the ignores it makes are recorded as made by the token. The body
//!   is limited like an SBOM (`--maximum-sbom-size`).
//!
//! Both take `?version=`, the latest version when absent; an unknown version is `404`.
//!
//! The routes sit behind the session layer, unlike [`crate::api`], so that the export can read
//! the session; the cross-site request check lets requests with an `Authorization` header
//! through. Errors are English JSON, as in [`crate::api`].

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use nanobom_authentication::AuthenticationSession;
use nanobom_domain::vex;

use crate::{
    api::{self, ApiError},
    read_api::{self, ApiPath, VersionParameter},
    state::AppState,
};

/// The media type of CycloneDX JSON documents.
const MEDIA_TYPE: &str = "application/vnd.cyclonedx+json";

pub fn router(state: &AppState) -> Router<AppState> {
    Router::new().route(
        "/api/organizations/{organization}/projects/{project}/vex",
        get(export)
            .put(import)
            .layer(DefaultBodyLimit::max(api::maximum_sbom_bytes(state))),
    )
}

/// `GET …/vex`: the project's findings as a CycloneDX VEX document, as a download. Like the
/// read API's, the response is private to its caller ([`read_api::private`]), errors included.
async fn export(
    state: State<AppState>,
    path: ApiPath<(String, String)>,
    parameters: Result<Query<VersionParameter>, QueryRejection>,
    headers: HeaderMap,
    session: AuthenticationSession,
) -> Response {
    let mut response = export_document(state, path, parameters, headers, session)
        .await
        .into_response();
    read_api::private(&mut response);
    response
}

async fn export_document(
    State(state): State<AppState>,
    ApiPath((organization, project)): ApiPath<(String, String)>,
    parameters: Result<Query<VersionParameter>, QueryRejection>,
    headers: HeaderMap,
    session: AuthenticationSession,
) -> Result<Response, ApiError> {
    let Query(parameters) = parameters.map_err(read_api::query_error)?;
    let reader = read_api::reader(&state, &headers, &session).await?;
    let document = vex::export(
        &state.database,
        reader,
        &organization,
        &project,
        parameters.version(),
    )
    .await?;
    // The project's reference is `organization/project`, both slugs, then the version, whose
    // characters are safe in a file name once its slashes are replaced too.
    let mut file_name = document
        .metadata
        .component
        .bom_ref
        .as_deref()
        .unwrap_or("project")
        .to_owned();
    if let Some(version) = &document.metadata.component.version {
        file_name = format!("{file_name}-{version}");
    }
    let file_name = format!("{}.vex.cdx.json", file_name.replace('/', "-"));
    let mut response = Json(document).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
    // Slugs are lower-case letters, digits and hyphens: the name needs no quoting rules.
    if let Ok(value) = HeaderValue::from_str(&format!("attachment; filename=\"{file_name}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
    Ok(response)
}

/// `PUT …/vex`: applies a CycloneDX VEX document to the open findings of a project version.
async fn import(
    State(state): State<AppState>,
    Path((organization, project)): Path<(String, String)>,
    parameters: Result<Query<VersionParameter>, QueryRejection>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<vex::ImportOutcome>, ApiError> {
    let Query(parameters) = parameters.map_err(read_api::query_error)?;
    let token = api::upload_token(&state, &headers).await?;
    let statements = api::parse_document(&state, body, vex::parse)
        .await
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))??;
    let outcome = vex::import(
        &state.database,
        &token,
        &organization,
        &project,
        parameters.version(),
        &statements,
    )
    .await?;
    Ok(Json(outcome))
}
