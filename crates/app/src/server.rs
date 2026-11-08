//! Server-side helpers for server functions: the request context, the signed-in user, error
//! mapping, redirects with messages, and conversions from domain types.

use std::sync::Arc;

use axum::http::{StatusCode, request::Parts};
use leptos::prelude::*;
use leptos_axum::ResponseOptions;
use nanobom_authentication::AuthenticationSession;
use nanobom_domain::{
    access::Actor,
    evaluation::{Scope, Trigger},
};
use sea_orm::DatabaseConnection;

use crate::{model, t};

/// What the server provides to the interface.
#[derive(Clone)]
pub struct InterfaceContext {
    pub database: DatabaseConnection,
    pub settings: InterfaceSettings,
    /// Queues a run; returns false when an identical request is already waiting.
    pub request_run: Arc<dyn Fn(Trigger, Scope, Option<i64>) -> bool + Send + Sync>,
}

#[derive(Debug, Clone)]
pub struct InterfaceSettings {
    pub local_accounts: bool,
    pub openid_button: Option<String>,
    pub password_minimum_length: usize,
    pub personal_organizations: bool,
    /// Days without an SBOM after which a project is stale (0: never).
    pub stale_after_days: u32,
}

pub fn context() -> Result<InterfaceContext, ServerFnError> {
    use_context::<InterfaceContext>()
        .ok_or_else(|| ServerFnError::new("the interface context is missing"))
}

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

/// The signed-in actor, freshly loaded. Without one, the response redirects to the sign-in page.
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

/// Builds `path?key=value…` with percent-encoded values.
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

/// The path of the page the form was sent from, if it is on this site.
fn referer_path() -> Option<String> {
    let parts = use_context::<Parts>()?;
    let referer = parts
        .headers
        .get(axum::http::header::REFERER)?
        .to_str()
        .ok()?;
    let host = parts.headers.get(axum::http::header::HOST)?.to_str().ok()?;
    let after_scheme = referer.split_once("://")?.1;
    let (authority, path) = after_scheme.split_once('/').unwrap_or((after_scheme, ""));
    (authority == host).then(|| format!("/{path}"))
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

/// Redirects to `target` with a notice or an error message.
pub fn redirect_with(target: &str, outcome: Result<&str, String>) {
    redirect_to(target, Some(outcome));
}

fn redirect_to(target: &str, outcome: Option<Result<&str, String>>) {
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
        leptos_axum::redirect(path);
    } else {
        leptos_axum::redirect(&format!("{path}?{}", query.join("&")));
    }
}

/// Runs a mutation and redirects back with its outcome.
pub fn finish(result: Result<String, nanobom_domain::Error>, fallback: &str) {
    match result {
        Ok(notice) => back(Ok(&notice), fallback),
        Err(error) => back(Err(message(error)), fallback),
    }
}

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
        component_name: value.component_name,
        component_version: value.component_version,
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
        exploitation: model::Exploitation {
            known_exploited: value.exploitation.known_exploited,
            kev_date_added: value.exploitation.kev_date_added,
            kev_due_date: value.exploitation.kev_due_date,
            kev_ransomware: value.exploitation.kev_ransomware,
            epss_score: value.exploitation.epss_score,
            epss_percentile: value.exploitation.epss_percentile,
            epss_date: value.exploitation.epss_date,
        },
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
