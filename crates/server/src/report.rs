//! The vulnerability report of a project version as an HTML document
//! ([`nanobom_domain::report`]), on `GET /api/organizations/{organization}/projects/{project}/report`,
//! so that a release workflow can archive the report of each release next to its artifacts.
//!
//! It accepts the callers of the read API ([`read_api::reader`]): a token of either scope, or the
//! session cookie. It takes `?version=`, the latest version when absent; an unknown version is
//! `404`. The document is the interface's report page without the interface around it
//! ([`nanobom_app::pages::report::document`]), in the language of `Accept-Language` (English by
//! default), with the stylesheet inlined so an archived copy shows the same without the server.
//! Errors are English JSON, as in the rest of the API.

use axum::{
    Router,
    extract::{Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
    routing::get,
};
use nanobom_authentication::AuthenticationSession;
use nanobom_domain::report;

use crate::{
    api::ApiError,
    read_api::{self, ApiPath, VersionParameter},
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/api/organizations/{organization}/projects/{project}/report",
        get(document),
    )
}

/// `GET …/report`. Like the read API's, the response is private to its caller
/// ([`read_api::private`]), errors included.
async fn document(
    state: State<AppState>,
    path: ApiPath<(String, String)>,
    parameters: Result<Query<VersionParameter>, QueryRejection>,
    headers: HeaderMap,
    session: AuthenticationSession,
) -> Response {
    let mut response = render(state, path, parameters, headers, session)
        .await
        .into_response();
    read_api::private(&mut response);
    // The language follows Accept-Language, so a cache must key on it too.
    response.headers_mut().insert(
        header::VARY,
        HeaderValue::from_static("Cookie, Authorization, X-Api-Key, Accept-Language"),
    );
    response
}

async fn render(
    State(state): State<AppState>,
    ApiPath((organization, project)): ApiPath<(String, String)>,
    parameters: Result<Query<VersionParameter>, QueryRejection>,
    headers: HeaderMap,
    session: AuthenticationSession,
) -> Result<Response, ApiError> {
    let Query(parameters) = parameters.map_err(read_api::query_error)?;
    let reader = read_api::reader(&state, &headers, &session).await?;
    let report = report::build(
        &state.database,
        reader,
        &organization,
        &project,
        parameters.version(),
        state.options.stale_after_days,
    )
    .await?;
    let accept_language = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|value| value.to_str().ok());
    let stylesheet = stylesheet(&state).await;
    let report = nanobom_app::server::report(report, &state.options.public_url);
    let html = nanobom_app::pages::report::document(report, accept_language, stylesheet.as_deref());
    Ok((
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        html,
    )
        .into_response())
}

/// The interface's stylesheet, as built into the site's package directory; `None` when it is
/// missing, as in tests, and the document is then unstyled. Public pages inline it too.
pub(crate) async fn stylesheet(state: &AppState) -> Option<String> {
    let options = &state.leptos_options;
    let path = std::path::Path::new(options.site_root.as_ref())
        .join(options.site_pkg_dir.as_ref())
        .join(format!("{}.css", options.output_name));
    tokio::fs::read_to_string(path).await.ok()
}
