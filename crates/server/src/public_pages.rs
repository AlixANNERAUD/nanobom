//! Public pages of projects ([`nanobom_domain::public_pages`]): `GET /public/{key}`, the HTML
//! page, and `GET /public/{key}/vex.json`, its CycloneDX VEX document, both with an optional
//! `?version=` (the latest version when absent).
//!
//! The key in the path is the only authorization. The routes sit outside the session layer, like
//! the badges ([`crate::badges`]): the page never reads cookies, so being signed in changes
//! nothing, and a cached copy can never hold what only a member may see. Anything that does not
//! resolve (an unknown or replaced key, a page turned off, an unknown version, a malformed
//! query) is the same empty `404`, so a caller cannot tell which part was wrong.
//!
//! The page is the report's layout ([`nanobom_app::pages::public::document`]) with the
//! stylesheet inlined and no script, in the language of `Accept-Language`. Responses are
//! `Cache-Control: public, max-age=300`, like badges, and carry:
//!
//! - `Referrer-Policy: no-referrer`: advisory links leave for osv.dev, and the `Referer` header
//!   would hand them the page's address, key included;
//! - `X-Robots-Tag: noindex`: the address is shared on purpose, but a search engine that finds
//!   it should not list it;
//! - a Content Security Policy that allows no script, the inline stylesheet and the
//!   interface's fonts.

use axum::{
    Json, Router,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use nanobom_domain::{Error, public_pages};
use serde::Deserialize;

use crate::state::AppState;

/// The media type of CycloneDX JSON documents.
const VEX_MEDIA_TYPE: &str = "application/vnd.cyclonedx+json";

/// No script, nothing loaded from elsewhere: the stylesheet is inline, the fonts are the
/// interface's own.
const PAGE_POLICY: &str = "default-src 'none'; style-src 'unsafe-inline'; font-src 'self'; \
                           base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
/// A JSON document needs nothing at all.
const DOCUMENT_POLICY: &str = "default-src 'none'; frame-ancestors 'none'";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/public/{key}", get(page))
        .route("/public/{key}/vex.json", get(vex))
}

#[derive(Debug, Default, Deserialize)]
struct Parameters {
    version: Option<String>,
}

/// The version asked for: as in the read API, an empty value names the unnamed version.
fn version(parameters: &Parameters) -> Option<&str> {
    parameters.version.as_deref().map(str::trim)
}

/// `GET /public/{key}`.
async fn page(
    State(state): State<AppState>,
    Path(key): Path<String>,
    parameters: Result<Query<Parameters>, QueryRejection>,
    headers: HeaderMap,
) -> Response {
    let Ok(Query(parameters)) = parameters else {
        return not_found();
    };
    let page = match public_pages::page(
        &state.database,
        &key,
        version(&parameters),
        state.options.stale_after_days,
    )
    .await
    {
        Ok(page) => page,
        Err(Error::NotFound) => return not_found(),
        Err(error) => {
            tracing::error!(%error, "cannot read a public page");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let mut vex = format!("public/{key}/vex.json");
    if !page.latest {
        vex = nanobom_app::server::with_query(&vex, &[("version", &page.version)]);
    }
    let vex_url = nanobom_domain::notifications::link(&state.options.public_url, &vex);
    let accept_language = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|value| value.to_str().ok());
    let stylesheet = crate::report::stylesheet(&state).await;
    let page = nanobom_app::server::public_page(page, vex_url, &state.options.public_url);
    let html = nanobom_app::pages::public::document(page, accept_language, stylesheet.as_deref());
    let mut response = (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        html,
    )
        .into_response();
    public_headers(&mut response, PAGE_POLICY);
    // The language follows Accept-Language, so a cache must key on it too.
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Accept-Language"));
    response
}

/// `GET /public/{key}/vex.json`.
async fn vex(
    State(state): State<AppState>,
    Path(key): Path<String>,
    parameters: Result<Query<Parameters>, QueryRejection>,
) -> Response {
    let Ok(Query(parameters)) = parameters else {
        return not_found();
    };
    let document = match public_pages::vex(&state.database, &key, version(&parameters)).await {
        Ok(document) => document,
        Err(Error::NotFound) => return not_found(),
        Err(error) => {
            tracing::error!(%error, "cannot read the VEX document of a public page");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let mut response = Json(document).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(VEX_MEDIA_TYPE),
    );
    public_headers(&mut response, DOCUMENT_POLICY);
    response
}

/// The headers of every public response, explained in the module documentation.
fn public_headers(response: &mut Response, content_security_policy: &'static str) {
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("x-robots-tag"),
        HeaderValue::from_static("noindex"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(content_security_policy),
    );
}

/// Not stored by caches, so a page turned back on is served at once rather than a remembered
/// 404 (RFC 9110 lets caches keep a 404 heuristically).
fn not_found() -> Response {
    (StatusCode::NOT_FOUND, [(header::CACHE_CONTROL, "no-store")]).into_response()
}
