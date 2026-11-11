//! Server-side helpers for server functions: the request context, the signed-in user, error
//! mapping, redirects with messages, and conversions from domain types.
//!
//! Compiled with the `ssr` feature only. A server function typically starts with [`actor`],
//! which redirects to the sign-in page when nobody is signed in, calls a domain function with
//! that actor (the domain checks permissions), and ends with [`finish`], which sends the browser
//! back to the form's page with a translated notice or error.
//!
//! Redirects go to paths: [`back`] uses the `Referer` only when its host is the request's own,
//! and keeps its path alone, checked like the sign-in `next` parameter so that a path such as
//! `//other.example` (read by browsers as another site) falls back to the default page.

use std::sync::Arc;

use axum::http::{StatusCode, request::Parts};
use leptos::prelude::*;
use leptos_axum::ResponseOptions;
use nanobom_authentication::{AuthenticationSession, redirect::local_path};
use nanobom_domain::{
    access::Actor,
    evaluation::{Scope, Trigger},
};
use sea_orm::DatabaseConnection;

use crate::{model, t};

/// What the server provides to the interface, as a Leptos context on every request. The
/// interface depends on this rather than on the server crate, which depends on it.
#[derive(Clone)]
pub struct InterfaceContext {
    pub database: DatabaseConnection,
    pub settings: InterfaceSettings,
    /// Queues a run; returns false when a request for the same scope was already waiting and
    /// absorbed this one. It does not check permissions: call
    /// `nanobom_domain::evaluation::authorize` first.
    pub request_run: Arc<dyn Fn(Trigger, Scope, Option<i64>) -> bool + Send + Sync>,
    /// Sends test emails; `None` when no SMTP server is configured, and email is off.
    pub mailer: Option<nanobom_domain::email::Mailer>,
}

/// The part of the server's configuration the interface shows or enforces.
#[derive(Debug, Clone)]
pub struct InterfaceSettings {
    pub local_accounts: bool,
    /// Label of the single sign-on button; `None` when OpenID Connect is not configured.
    pub openid_button: Option<String>,
    pub password_minimum_length: usize,
    pub personal_organizations: bool,
    /// Days without an SBOM after which a project is stale (0: never).
    pub stale_after_days: u32,
    /// The address users reach nanobom at, for the links of test emails.
    pub public_url: nanobom_domain::Url,
}

/// The [`InterfaceContext`] of the current request; an error outside a request.
pub fn context() -> Result<InterfaceContext, ServerFnError> {
    use_context::<InterfaceContext>()
        .ok_or_else(|| ServerFnError::new("the interface context is missing"))
}

/// The authentication session of the current request, with no user when nobody is signed in.
/// Prefer [`actor`] for anything done on the user's behalf: it sends anonymous visitors to the
/// sign-in page.
pub async fn session() -> Result<AuthenticationSession, ServerFnError> {
    leptos_axum::extract::<AuthenticationSession>()
        .await
        .map_err(|error| ServerFnError::new(error.to_string()))
}

fn request_path() -> String {
    use_context::<Parts>()
        .map(|parts| {
            parts
                .uri
                .path_and_query()
                .map(ToString::to_string)
                .unwrap_or_else(|| "/".to_owned())
        })
        .unwrap_or_else(|| "/".to_owned())
}

/// The signed-in actor, freshly loaded. Without one, the response redirects to the sign-in page
/// and the error is [`model::SIGN_IN_REQUIRED`]. The page to come back to is the current page,
/// or for a form post (under `/api/`) the page the form was on.
pub async fn actor() -> Result<Actor, ServerFnError> {
    let context = context()?;
    let user = session().await?.user;
    if let Some(user) = user
        && let Ok(actor) = Actor::load(&context.database, user.id).await
    {
        return Ok(actor);
    }
    let next = request_path();
    let next = if next.starts_with("/api/") {
        referer_path().unwrap_or_else(|| "/".to_owned())
    } else {
        next
    };
    let location = with_query("/login", &[("next", &next)]);
    leptos_axum::redirect(&location);
    Err(ServerFnError::new(model::SIGN_IN_REQUIRED))
}

/// Builds `path?key=value…` with percent-encoded values (`/` is kept, so paths stay readable).
pub fn with_query(path: &str, pairs: &[(&str, &str)]) -> String {
    let query: Vec<String> = pairs
        .iter()
        .map(|(key, value)| format!("{key}={}", encode(value)))
        .collect();
    if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{}", query.join("&"))
    }
}

fn encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                encoded.push(char::from(byte));
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

/// The message shown for a domain error, in the request's language.
pub fn message(error: nanobom_domain::Error) -> String {
    use nanobom_domain::Error;
    match error {
        Error::NotFound => t!("errors.not_found").to_owned(),
        Error::Forbidden => t!("errors.forbidden").to_owned(),
        Error::Invalid(problem) | Error::Conflict(problem) => {
            sentence(&problem.message(crate::i18n::locale()))
        }
        Error::Database(database) => {
            tracing::error!(%database, "database error");
            t!("errors.unexpected").to_owned()
        }
    }
}

/// Problems are written as clauses (`the name is taken`); shown alone, they start with a
/// capital letter and end with a period.
fn sentence(clause: &str) -> String {
    let mut characters = clause.chars();
    let Some(first) = characters.next() else {
        return String::new();
    };
    let mut sentence: String = first.to_uppercase().chain(characters).collect();
    if !sentence.ends_with(['.', '!', '?']) {
        sentence.push('.');
    }
    sentence
}

/// Turns a domain error into a server function error, setting the response status.
pub fn failure(error: nanobom_domain::Error) -> ServerFnError {
    use nanobom_domain::Error;
    let status = match &error {
        Error::NotFound => StatusCode::NOT_FOUND,
        Error::Forbidden => StatusCode::FORBIDDEN,
        Error::Invalid(_) | Error::Conflict(_) => StatusCode::UNPROCESSABLE_ENTITY,
        Error::Database(database) => {
            tracing::error!(%database, "database error");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    if let Some(response) = use_context::<ResponseOptions>() {
        response.set_status(status);
    }
    ServerFnError::new(message(error))
}

/// The path of the page the form was sent from, if it is on this site: the `Referer`'s host
/// must equal the request's `Host`, so a forged `Referer` cannot redirect elsewhere.
fn referer_path() -> Option<String> {
    let parts = use_context::<Parts>()?;
    let referer = parts
        .headers
        .get(axum::http::header::REFERER)?
        .to_str()
        .ok()?;
    let host = parts.headers.get(axum::http::header::HOST)?.to_str().ok()?;
    local_referer_path(referer, host)
}

/// The path (and query) of `referer` when its authority is `host` and the path is a local one.
/// The path is what follows the host verbatim, so `https://host//evil.example/x` yields
/// `//evil.example/x`, which [`local_path`] refuses.
fn local_referer_path(referer: &str, host: &str) -> Option<String> {
    let after_scheme = referer.split_once("://")?.1;
    let (authority, path) = after_scheme.split_once('/').unwrap_or((after_scheme, ""));
    if authority != host {
        return None;
    }
    local_path(&format!("/{path}")).map(str::to_owned)
}

/// Sends the browser back to the page the form came from, with a notice or an error message
/// in the query string, or to `fallback` when the page is unknown.
pub fn back(outcome: Result<&str, String>, fallback: &str) {
    let target = referer_path().unwrap_or_else(|| fallback.to_owned());
    redirect_with(&target, outcome);
}

/// Sends the browser back to the page the form came from, dropping any earlier message.
pub fn back_quietly(fallback: &str) {
    let target = referer_path().unwrap_or_else(|| fallback.to_owned());
    redirect_to(&target, None);
}

/// Redirects to `target` with a notice or an error message, replacing any `notice` or `error`
/// already in its query string. A fragment (`#section`) stays at the end, where it belongs.
pub fn redirect_with(target: &str, outcome: Result<&str, String>) {
    redirect_to(target, Some(outcome));
}

fn redirect_to(target: &str, outcome: Option<Result<&str, String>>) {
    let (target, fragment) = match target.split_once('#') {
        Some((target, fragment)) => (target, format!("#{fragment}")),
        None => (target, String::new()),
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter(|pair| !pair.starts_with("notice=") && !pair.starts_with("error="))
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (key.to_owned(), value.to_owned())
        })
        .collect();
    match outcome {
        Some(Ok(notice)) => pairs.push(("notice".to_owned(), encode(notice))),
        Some(Err(error)) => pairs.push(("error".to_owned(), encode(&error))),
        None => {}
    }
    let query: Vec<String> = pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    if query.is_empty() {
        leptos_axum::redirect(&format!("{path}{fragment}"));
    } else {
        leptos_axum::redirect(&format!("{path}?{}{fragment}", query.join("&")));
    }
}

/// Redirects back with the outcome of a mutation: the notice on success, the translated error
/// otherwise (see [`message`]).
pub fn finish(result: Result<String, nanobom_domain::Error>, fallback: &str) {
    match result {
        Ok(notice) => back(Ok(&notice), fallback),
        Err(error) => back(Err(message(error)), fallback),
    }
}

// The interface keeps its own copies of domain enumerations (see `model`); these convert.

pub fn severity(value: nanobom_osv::Severity) -> model::Severity {
    use nanobom_osv::Severity;
    match value {
        Severity::Unknown => model::Severity::Unknown,
        Severity::Low => model::Severity::Low,
        Severity::Medium => model::Severity::Medium,
        Severity::High => model::Severity::High,
        Severity::Critical => model::Severity::Critical,
    }
}

pub fn domain_severity(value: model::Severity) -> nanobom_osv::Severity {
    use nanobom_osv::Severity;
    match value {
        model::Severity::Unknown => Severity::Unknown,
        model::Severity::Low => Severity::Low,
        model::Severity::Medium => Severity::Medium,
        model::Severity::High => Severity::High,
        model::Severity::Critical => Severity::Critical,
    }
}

pub fn delivery_state(value: nanobom_domain::deliveries::State) -> model::DeliveryState {
    use nanobom_domain::deliveries::State;
    match value {
        State::Sending => model::DeliveryState::Sending,
        State::Pending => model::DeliveryState::Pending,
        State::Delivered => model::DeliveryState::Delivered,
        State::Failed => model::DeliveryState::Failed,
        State::Cancelled => model::DeliveryState::Cancelled,
    }
}

pub fn role(value: nanobom_domain::access::Role) -> model::Role {
    use nanobom_domain::access::Role;
    match value {
        Role::Viewer => model::Role::Viewer,
        Role::Member => model::Role::Member,
        Role::Admin => model::Role::Admin,
        Role::Owner => model::Role::Owner,
    }
}

pub fn status(value: nanobom_domain::findings::Status) -> model::Status {
    use nanobom_domain::findings::Status;
    match value {
        Status::Open => model::Status::Open,
        Status::Ignored => model::Status::Ignored,
        Status::Fixed => model::Status::Fixed,
    }
}

pub fn organization(value: nanobom_domain::organizations::Organization) -> model::Organization {
    model::Organization {
        slug: value.slug,
        name: value.name,
        is_personal: value.is_personal,
        role: role(value.role),
    }
}

pub fn finding(value: nanobom_domain::findings::Finding) -> model::FindingRow {
    model::FindingRow {
        id: value.id,
        version: value.version,
        component_name: value.component_name,
        component_version: value.component_version,
        license: value.license,
        ecosystem: value.ecosystem,
        purl: value.purl,
        vulnerability_id: value.vulnerability_id,
        aliases: value.aliases,
        summary: value.summary,
        severity: severity(value.severity),
        cvss_score: value.cvss_score,
        status: status(value.status),
        first_seen_at: value.first_seen_at,
        fixed_at: value.fixed_at,
        ignore_reason: value.ignore_reason,
        ignore_expires_at: value.ignore_expires_at,
        ignore_justification: value
            .ignore_justification
            .map(|justification| justification.as_str().to_owned()),
        exploitation: model::Exploitation {
            known_exploited: value.exploitation.known_exploited,
            kev_date_added: value.exploitation.kev_date_added,
            kev_due_date: value.exploitation.kev_due_date,
            kev_ransomware: value.exploitation.kev_ransomware,
            epss_score: value.exploitation.epss_score,
            epss_percentile: value.exploitation.epss_percentile,
            epss_date: value.exploitation.epss_date,
        },
        introduced_via: value
            .introduced_via
            .into_iter()
            .map(dependency_component)
            .collect(),
    }
}

pub fn dependency_component(
    value: nanobom_domain::dependencies::ComponentRef,
) -> model::DependencyComponent {
    model::DependencyComponent {
        purl: value.purl,
        name: value.name,
        version: value.version,
    }
}

pub fn counts(value: nanobom_domain::findings::SeverityCounts) -> model::SeverityCounts {
    model::SeverityCounts {
        critical: value.critical,
        high: value.high,
        medium: value.medium,
        low: value.low,
        unknown: value.unknown,
    }
}

pub fn license_action(value: nanobom_domain::licenses::Action) -> model::LicenseAction {
    use nanobom_domain::licenses::Action;
    match value {
        Action::Allow => model::LicenseAction::Allow,
        Action::Warn => model::LicenseAction::Warn,
        Action::Forbid => model::LicenseAction::Forbid,
    }
}

pub fn license_counts(value: nanobom_domain::licenses::ViolationCounts) -> model::LicenseCounts {
    model::LicenseCounts {
        forbidden: value.forbidden,
        warned: value.warned,
    }
}

/// A report for the interface. `public_url` is the instance's address, which the report names
/// and links the VEX export from.
pub fn report(
    value: nanobom_domain::report::Report,
    public_url: &nanobom_domain::Url,
) -> model::ReportData {
    use nanobom_domain::report::Licenses;
    let mut vex = format!(
        "api/organizations/{}/projects/{}/vex",
        value.organization_slug, value.project_slug
    );
    if !value.latest {
        vex = with_query(&vex, &[("version", &value.version)]);
    }
    let vex_url = public_url
        .join(&vex)
        .map(|url| url.to_string())
        .unwrap_or(vex);
    model::ReportData {
        generated_at: value.generated_at,
        nanobom_version: env!("CARGO_PKG_VERSION").to_owned(),
        host: public_url.host_str().unwrap_or_default().to_owned(),
        vex_url,
        upload: value.upload.map(|upload| model::Upload {
            version: value.version.clone(),
            uploaded_at: upload.uploaded_at,
            specification_version: upload.specification_version,
            source_commit: upload.source_commit,
            image_tag: upload.image_tag,
            component_count: upload.component_count,
            components_without_purl: upload.components_without_purl,
        }),
        organization_slug: value.organization_slug,
        organization_name: value.organization_name,
        project_slug: value.project_slug,
        project_name: value.project_name,
        version: value.version,
        latest: value.latest,
        active: value.active,
        component_count: value.component_count,
        stale: value.stale,
        project_last_upload_at: value.project_last_upload_at,
        project_created_at: value.project_created_at,
        last_evaluation: value.last_evaluation,
        kev_checked_at: value.kev_checked_at,
        epss_checked_at: value.epss_checked_at,
        counts: counts(value.summary.open),
        known_exploited: value.summary.known_exploited,
        ignored: value.summary.ignored,
        fixed_recently: value.summary.fixed_recently,
        open: value
            .open
            .into_iter()
            .map(|open| model::ReportFinding {
                finding: finding(open.finding),
                fixed_versions: open.fixed_versions,
            })
            .collect(),
        assessed: value
            .assessed
            .into_iter()
            .map(|assessed| model::AssessedFinding {
                finding: finding(assessed.finding),
                ignored_at: assessed.ignored_at,
                ignored_by: assessed.ignored_by,
                ignored_by_token: assessed.ignored_by_token,
            })
            .collect(),
        licenses: match value.licenses {
            Licenses::Policy(violations) => {
                model::ReportLicenses::Policy(license_violations(violations))
            }
            Licenses::Counts(counts) => model::ReportLicenses::Counts {
                groups: counts.groups,
                other: counts.other,
                without: counts.without,
            },
        },
    }
}

pub fn license_violations(value: nanobom_domain::licenses::Violations) -> model::LicenseViolations {
    model::LicenseViolations {
        counts: license_counts(value.counts),
        items: value
            .items
            .into_iter()
            .map(|violation| model::LicenseViolation {
                purl: violation.purl,
                name: violation.name,
                version: violation.version,
                license: violation.license,
                verdict: license_action(violation.verdict),
                licenses: violation.licenses,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::local_referer_path;

    const HOST: &str = "nanobom.example";

    #[test]
    fn keeps_a_local_path_with_its_query_string() {
        assert_eq!(
            local_referer_path("https://nanobom.example/projects/3?tab=findings", HOST),
            Some("/projects/3?tab=findings".to_owned())
        );
        assert_eq!(
            local_referer_path("https://nanobom.example", HOST),
            Some("/".to_owned())
        );
    }

    #[test]
    fn refuses_a_protocol_relative_path() {
        assert_eq!(
            local_referer_path("https://nanobom.example//evil.example/x", HOST),
            None
        );
    }

    #[test]
    fn refuses_a_backslash_after_the_slash() {
        assert_eq!(
            local_referer_path("https://nanobom.example/\\evil.example", HOST),
            None
        );
    }

    #[test]
    fn refuses_a_control_character() {
        assert_eq!(
            local_referer_path("https://nanobom.example/a\tb", HOST),
            None
        );
    }

    #[test]
    fn refuses_another_host() {
        assert_eq!(local_referer_path("https://evil.example/x", HOST), None);
    }
}
