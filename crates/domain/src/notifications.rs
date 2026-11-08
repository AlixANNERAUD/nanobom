//! Webhooks: each organization can send its new findings to a URL as JSON, grouped per run,
//! and the instance can report failed runs to another URL.
//!
//! Payloads (documented in the README):
//!
//! - `findings.new`: new and reopened findings of one organization, at or above the webhook's
//!   minimum severity, and open findings that became known exploited since the last run
//!   (whatever their severity);
//! - `run.failed`: a run that could not complete, sent to the instance's failure webhook.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    time::Duration,
};

use chrono::{DateTime, FixedOffset, NaiveDate, Utc};
use nanobom_entity::{findings, organization_webhooks, organizations, projects, vulnerabilities};
use nanobom_osv::Severity;
use reqwest::Url;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, ModelTrait,
    QueryFilter,
};
use serde::{Deserialize, Serialize};

use crate::{
    access::{Actor, Permission},
    error::{Error, Result},
    evaluation::{RunOutcome, Scope},
    exploitation::{self, Exploitation},
    problem::Problem,
};

/// Identifiers per database query, below SQLite's limit on bound variables.
const QUERY_CHUNK: usize = 500;

/// An organization's webhook settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Webhook {
    pub url: String,
    pub minimum_severity: Severity,
    pub enabled: bool,
    pub last_delivery_at: Option<DateTime<FixedOffset>>,
    pub last_delivery_status: Option<String>,
    /// Deliver only known exploited findings.
    pub exploited_only: bool,
}

fn view(model: organization_webhooks::Model) -> Webhook {
    Webhook {
        url: model.url,
        minimum_severity: model.minimum_severity.parse().unwrap_or(Severity::Unknown),
        enabled: model.enabled,
        last_delivery_at: model.last_delivery_at,
        last_delivery_status: model.last_delivery_status,
        exploited_only: model.exploited_only,
    }
}

/// Validates a webhook address: an absolute `http` or `https` URL.
pub fn validate_url(value: &str) -> Result<Url> {
    let url: Url = value
        .trim()
        .parse()
        .map_err(|_| Error::invalid(Problem::InvalidWebhookUrl))?;
    if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
        return Err(Error::invalid(Problem::WebhookScheme));
    }
    Ok(url)
}

/// The webhook of an organization, if configured.
pub async fn get(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
) -> Result<Option<Webhook>> {
    actor
        .authorize(database, organization_id, Permission::ManageWebhook)
        .await?;
    Ok(organization_webhooks::Entity::find_by_id(organization_id)
        .one(database)
        .await?
        .map(view))
}

/// Creates or replaces the webhook of an organization.
pub async fn set(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
    url: &str,
    minimum_severity: Severity,
    enabled: bool,
    exploited_only: bool,
) -> Result<Webhook> {
    actor
        .authorize(database, organization_id, Permission::ManageWebhook)
        .await?;
    let url = validate_url(url)?;
    let existing = organization_webhooks::Entity::find_by_id(organization_id)
        .one(database)
        .await?;
    let model = match existing {
        Some(model) => {
            let mut active: organization_webhooks::ActiveModel = model.into();
            active.url = Set(url.to_string());
            active.minimum_severity = Set(minimum_severity.as_str().to_owned());
            active.enabled = Set(enabled);
            active.exploited_only = Set(exploited_only);
            active.update(database).await?
        }
        None => {
            organization_webhooks::ActiveModel {
                organization_id: Set(organization_id),
                url: Set(url.to_string()),
                minimum_severity: Set(minimum_severity.as_str().to_owned()),
                enabled: Set(enabled),
                last_delivery_at: Set(None),
                last_delivery_status: Set(None),
                exploited_only: Set(exploited_only),
            }
            .insert(database)
            .await?
        }
    };
    Ok(view(model))
}

/// Removes the webhook of an organization.
pub async fn delete(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
) -> Result<()> {
    actor
        .authorize(database, organization_id, Permission::ManageWebhook)
        .await?;
    if let Some(model) = organization_webhooks::Entity::find_by_id(organization_id)
        .one(database)
        .await?
    {
        model.delete(database).await?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayloadOrganization {
    pub slug: String,
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayloadRun {
    pub id: i64,
    pub trigger: String,
    pub started_at: DateTime<FixedOffset>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayloadFinding {
    pub project: String,
    pub component: String,
    pub vulnerability: String,
    pub aliases: Vec<String>,
    pub severity: Severity,
    pub cvss_score: Option<f64>,
    pub summary: Option<String>,
    /// True when the finding was fixed before and came back.
    pub reopened: bool,
    /// Why the finding is delivered: `new`, `reopened` or `exploited` (an open finding that
    /// became known exploited).
    pub reason: String,
    pub known_exploited: bool,
    pub kev_due_date: Option<NaiveDate>,
    pub epss: Option<f64>,
    pub epss_percentile: Option<f64>,
    pub url: String,
}

/// `findings.new`: new findings of one organization in one run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NewFindingsPayload {
    pub event: String,
    pub organization: PayloadOrganization,
    pub run: PayloadRun,
    pub count: usize,
    pub highest_severity: Severity,
    pub known_exploited_count: usize,
    pub findings: Vec<PayloadFinding>,
}

/// `run.failed`: a run that could not complete.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunFailedPayload {
    pub event: String,
    pub instance_url: String,
    pub run: PayloadRun,
    pub scope: String,
    pub error: String,
}

fn run(outcome: &RunOutcome) -> PayloadRun {
    PayloadRun {
        id: outcome.run_id,
        trigger: outcome.trigger.as_str().to_owned(),
        started_at: outcome.started_at,
    }
}

fn link(public_url: &Url, path: &str) -> String {
    public_url
        .join(path)
        .map_or_else(|_| public_url.to_string(), |url| url.to_string())
}

/// A webhook delivery to make.
#[derive(Debug, Clone)]
pub struct Delivery<T> {
    pub organization_id: i64,
    pub url: String,
    pub payload: T,
}

/// A finding to deliver, with why and what is known about its exploitation.
struct Entry {
    finding_id: i64,
    organization_id: i64,
    project_slug: String,
    purl: String,
    vulnerability_id: String,
    aliases: Vec<String>,
    summary: Option<String>,
    severity: Severity,
    cvss_score: Option<f64>,
    reason: &'static str,
    exploitation: Exploitation,
}

/// What an open finding needs to be notified.
struct Candidate {
    finding: findings::Model,
    organization_id: i64,
    project_slug: String,
    aliases: Vec<String>,
    summary: Option<String>,
    cvss_score: Option<f64>,
}

fn aliases_of(vulnerability: &vulnerabilities::Model) -> Vec<String> {
    serde_json::from_str(&vulnerability.aliases).unwrap_or_default()
}

/// The open findings of a run's scope that were never notified as known exploited.
async fn unnotified_open_findings(
    database: &impl ConnectionTrait,
    scope: Scope,
) -> Result<Vec<Candidate>> {
    let mut query = findings::Entity::find()
        .filter(findings::Column::Status.eq("open"))
        .filter(findings::Column::ExploitedNotifiedAt.is_null());
    let mut project_query = projects::Entity::find();
    match scope {
        Scope::All => {}
        Scope::Project(id) => {
            query = query.filter(findings::Column::ProjectId.eq(id));
            project_query = project_query.filter(projects::Column::Id.eq(id));
        }
        Scope::Organization(id) => {
            project_query = project_query.filter(projects::Column::OrganizationId.eq(id));
            let ids: Vec<i64> = project_query
                .clone()
                .all(database)
                .await?
                .into_iter()
                .map(|project| project.id)
                .collect();
            query = query.filter(findings::Column::ProjectId.is_in(ids));
        }
    }
    let projects: HashMap<i64, projects::Model> = project_query
        .all(database)
        .await?
        .into_iter()
        .map(|project| (project.id, project))
        .collect();
    let open = query.all(database).await?;
    let identifiers: BTreeSet<String> = open
        .iter()
        .map(|finding| finding.vulnerability_id.clone())
        .collect();
    let identifiers: Vec<String> = identifiers.into_iter().collect();
    let mut records: HashMap<String, vulnerabilities::Model> = HashMap::new();
    for chunk in identifiers.chunks(QUERY_CHUNK) {
        for record in vulnerabilities::Entity::find()
            .filter(vulnerabilities::Column::Id.is_in(chunk.to_vec()))
            .all(database)
            .await?
        {
            records.insert(record.id.clone(), record);
        }
    }
    Ok(open
        .into_iter()
        .filter_map(|finding| {
            let project = projects.get(&finding.project_id)?;
            let record = records.get(&finding.vulnerability_id);
            Some(Candidate {
                organization_id: project.organization_id,
                project_slug: project.slug.clone(),
                aliases: record.map(aliases_of).unwrap_or_default(),
                summary: record.and_then(|record| record.summary.clone()),
                cvss_score: record.and_then(|record| record.cvss_score),
                finding,
            })
        })
        .collect())
}

/// Records that findings were notified as known exploited.
async fn mark_notified(database: &impl ConnectionTrait, ids: &[i64]) -> Result<()> {
    let now = Utc::now().fixed_offset();
    for chunk in ids.chunks(QUERY_CHUNK) {
        findings::Entity::update_many()
            .col_expr(
                findings::Column::ExploitedNotifiedAt,
                sea_orm::sea_query::Expr::value(now),
            )
            .filter(findings::Column::Id.is_in(chunk.to_vec()))
            .exec(database)
            .await?;
    }
    Ok(())
}

/// The `findings.new` deliveries a successful run calls for: one per organization with an
/// enabled webhook and findings to report, which are
///
/// - the findings the run opened or reopened, at or above the webhook's minimum severity
///   (known exploited ones whatever their severity);
/// - the open findings of the run's scope that are known exploited and were never notified as
///   such (`exploited` reason), once.
///
/// With `exploited_only`, only known exploited findings are delivered. Every known exploited
/// open finding of the scope is then marked as notified, with or without a webhook, so that
/// enabling a webhook later does not replay old findings.
pub async fn new_findings_deliveries(
    database: &impl ConnectionTrait,
    outcome: &RunOutcome,
    public_url: &Url,
) -> Result<Vec<Delivery<NewFindingsPayload>>> {
    let opened: BTreeSet<i64> = outcome
        .new_findings
        .iter()
        .map(|finding| finding.finding_id)
        .collect();
    let candidates = unnotified_open_findings(database, outcome.scope).await?;

    // Entries are keyed by position, since a finding id is not unique among outcomes built
    // by hand.
    let keyed: Vec<(i64, Vec<String>)> = outcome
        .new_findings
        .iter()
        .map(|finding| exploitation::cve_ids(&finding.vulnerability_id, &finding.aliases))
        .chain(candidates.iter().map(|candidate| {
            exploitation::cve_ids(&candidate.finding.vulnerability_id, &candidate.aliases)
        }))
        .enumerate()
        .map(|(index, cves)| (i64::try_from(index).unwrap_or(i64::MAX), cves))
        .collect();
    let mut exploitation = exploitation::for_findings(database, &keyed).await?;
    let mut position = 0_i64;
    let mut take = || {
        let value = exploitation.remove(&position).unwrap_or_default();
        position += 1;
        value
    };

    let mut entries: Vec<Entry> = outcome
        .new_findings
        .iter()
        .map(|finding| Entry {
            finding_id: finding.finding_id,
            organization_id: finding.organization_id,
            project_slug: finding.project_slug.clone(),
            purl: finding.purl.clone(),
            vulnerability_id: finding.vulnerability_id.clone(),
            aliases: finding.aliases.clone(),
            summary: finding.summary.clone(),
            severity: finding.severity,
            cvss_score: finding.cvss_score,
            reason: if finding.reopened { "reopened" } else { "new" },
            exploitation: take(),
        })
        .collect();
    let mut to_mark: Vec<i64> = entries
        .iter()
        .filter(|entry| entry.exploitation.known_exploited)
        .map(|entry| entry.finding_id)
        .collect();
    for candidate in candidates {
        let exploitation = take();
        if !exploitation.known_exploited {
            continue;
        }
        to_mark.push(candidate.finding.id);
        if opened.contains(&candidate.finding.id) {
            continue;
        }
        entries.push(Entry {
            finding_id: candidate.finding.id,
            organization_id: candidate.organization_id,
            project_slug: candidate.project_slug,
            purl: candidate.finding.purl,
            vulnerability_id: candidate.finding.vulnerability_id,
            aliases: candidate.aliases,
            summary: candidate.summary,
            severity: candidate
                .finding
                .severity
                .parse()
                .unwrap_or(Severity::Unknown),
            cvss_score: candidate.cvss_score,
            reason: "exploited",
            exploitation,
        });
    }

    let mut by_organization: BTreeMap<i64, Vec<Entry>> = BTreeMap::new();
    for entry in entries {
        by_organization
            .entry(entry.organization_id)
            .or_default()
            .push(entry);
    }
    let mut deliveries = Vec::new();
    for (organization_id, entries) in by_organization {
        let Some(webhook) = organization_webhooks::Entity::find_by_id(organization_id)
            .one(database)
            .await?
            .filter(|webhook| webhook.enabled)
        else {
            continue;
        };
        let minimum: Severity = webhook
            .minimum_severity
            .parse()
            .unwrap_or(Severity::Unknown);
        let entries: Vec<Entry> = entries
            .into_iter()
            .filter(|entry| {
                if webhook.exploited_only {
                    entry.exploitation.known_exploited
                } else {
                    entry.exploitation.known_exploited || entry.severity >= minimum
                }
            })
            .collect();
        if entries.is_empty() {
            continue;
        }
        let Some(organization) = organizations::Entity::find_by_id(organization_id)
            .one(database)
            .await?
        else {
            continue;
        };
        let payload = NewFindingsPayload {
            event: "findings.new".to_owned(),
            organization: PayloadOrganization {
                url: link(public_url, &format!("organizations/{}", organization.slug)),
                slug: organization.slug,
                name: organization.name,
            },
            run: run(outcome),
            count: entries.len(),
            highest_severity: entries
                .iter()
                .map(|entry| entry.severity)
                .max()
                .unwrap_or(Severity::Unknown),
            known_exploited_count: entries
                .iter()
                .filter(|entry| entry.exploitation.known_exploited)
                .count(),
            findings: entries
                .into_iter()
                .map(|entry| PayloadFinding {
                    url: link(public_url, &format!("findings/{}", entry.finding_id)),
                    project: entry.project_slug,
                    component: entry.purl,
                    vulnerability: entry.vulnerability_id,
                    aliases: entry.aliases,
                    severity: entry.severity,
                    cvss_score: entry.cvss_score,
                    summary: entry.summary,
                    reopened: entry.reason == "reopened",
                    reason: entry.reason.to_owned(),
                    known_exploited: entry.exploitation.known_exploited,
                    kev_due_date: entry.exploitation.kev_due_date,
                    epss: entry.exploitation.epss_score,
                    epss_percentile: entry.exploitation.epss_percentile,
                })
                .collect(),
        };
        deliveries.push(Delivery {
            organization_id,
            url: webhook.url,
            payload,
        });
    }
    mark_notified(database, &to_mark).await?;
    Ok(deliveries)
}

/// The `run.failed` payload for a failed run.
pub fn run_failed_payload(outcome: &RunOutcome, public_url: &Url) -> Option<RunFailedPayload> {
    let error = outcome.error.clone()?;
    Some(RunFailedPayload {
        event: "run.failed".to_owned(),
        instance_url: public_url.to_string(),
        run: run(outcome),
        scope: outcome.scope.as_str().to_owned(),
        error,
    })
}

/// Sends webhook payloads.
#[derive(Debug, Clone)]
pub struct Notifier {
    http: reqwest::Client,
}

impl Notifier {
    pub fn new() -> std::result::Result<Self, reqwest::Error> {
        Ok(Self {
            http: reqwest::Client::builder()
                .user_agent(concat!("nanobom/", env!("CARGO_PKG_VERSION")))
                .timeout(Duration::from_secs(15))
                .build()?,
        })
    }

    /// Posts a payload; returns a short description of the outcome.
    pub async fn post<T: Serialize>(
        &self,
        url: &str,
        payload: &T,
    ) -> std::result::Result<String, String> {
        match self.http.post(url).json(payload).send().await {
            Ok(response) if response.status().is_success() => Ok(response.status().to_string()),
            Ok(response) => Err(response.status().to_string()),
            Err(error) => Err(error.without_url().to_string()),
        }
    }

    /// Delivers `findings.new` payloads and records the outcome on each webhook.
    pub async fn deliver(
        &self,
        database: &impl ConnectionTrait,
        deliveries: Vec<Delivery<NewFindingsPayload>>,
    ) -> Result<()> {
        for delivery in deliveries {
            let result = self.post(&delivery.url, &delivery.payload).await;
            let status = match &result {
                Ok(status) => status.clone(),
                Err(error) => format!("failed: {error}"),
            };
            match &result {
                Ok(_) => tracing::info!(
                    organization = delivery.organization_id,
                    findings = delivery.payload.count,
                    "webhook delivered"
                ),
                Err(error) => tracing::warn!(
                    organization = delivery.organization_id,
                    %error,
                    "webhook delivery failed"
                ),
            }
            if let Some(model) = organization_webhooks::Entity::find_by_id(delivery.organization_id)
                .one(database)
                .await?
            {
                let mut active: organization_webhooks::ActiveModel = model.into();
                active.last_delivery_at = Set(Some(Utc::now().fixed_offset()));
                active.last_delivery_status = Set(Some(status));
                active.update(database).await?;
            }
        }
        Ok(())
    }
}
