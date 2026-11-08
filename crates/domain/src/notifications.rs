//! Webhooks: each organization can send its new findings to a URL as JSON, grouped per run,
//! and the instance can report failed runs to another URL.
//!
//! Payloads (documented in the guide's webhook reference):
//!
//! - `findings.new`: new and reopened findings of one organization, at or above the webhook's
//!   minimum severity, and open findings that became known exploited since the last run
//!   (whatever their severity);
//! - `projects.stale`: projects of one organization whose SBOM stopped coming;
//! - `run.failed`: a run that could not complete, sent to the instance's failure webhook.
//!
//! Deliveries go through the queue of [`crate::deliveries`], which retries failed ones.
//!
//! Only the webhook settings ([`get`], [`set`], [`delete`]) take an actor. The rest is called
//! by the run worker after a run, with no actor; isolation then rests on grouping: a
//! `findings.new` or `projects.stale` document is built per organization from that
//! organization's projects only, and goes to that organization's webhook only. `run.failed`,
//! whose error may name packages of any organization, goes to the instance's failure webhook,
//! configured by the operator, never to an organization.
//!
//! Preparing a document and marking what it reports as notified (findings that became known
//! exploited, stale projects) happen in one transaction with the enqueueing
//! ([`queue_new_findings`], [`queue_stale`]): a crash cannot lose a notification nor send it
//! twice. Findings are marked even in organizations without an enabled webhook, so enabling
//! one later does not replay old findings; stale projects are marked only when a document
//! reports them, so a webhook enabled later still hears about projects that are already stale.
//!
//! Webhook addresses are not restricted to public hosts: an organization admin can make the
//! server post to any address it reaches. Only the status of the answer is kept, never its
//! body.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    time::Duration,
};

use chrono::{DateTime, FixedOffset, NaiveDate, Utc};
use nanobom_entity::{
    findings, organization_webhooks, organizations, projects, webhook_deliveries,
};
use nanobom_osv::Severity;
use reqwest::Url;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseConnection,
    EntityTrait, ModelTrait, QueryFilter, QueryOrder, TransactionTrait,
};
use serde::{Deserialize, Serialize};

use crate::{
    access::{Actor, Permission},
    deliveries::{self, Attempt, Outcome},
    error::{Error, Result},
    evaluation::{RunOutcome, Scope},
    exploitation::{self, Exploitation, QUERY_CHUNK},
    problem::Problem,
    staleness,
};

/// An organization's webhook settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Webhook {
    pub url: String,
    /// Findings below this severity are left out, unless they are known exploited.
    pub minimum_severity: Severity,
    /// A disabled webhook keeps its settings but receives nothing.
    pub enabled: bool,
    /// Deliver only known exploited findings.
    pub exploited_only: bool,
}

fn view(model: organization_webhooks::Model) -> Webhook {
    Webhook {
        url: model.url,
        minimum_severity: model.minimum_severity.parse().unwrap_or(Severity::Unknown),
        enabled: model.enabled,
        exploited_only: model.exploited_only,
    }
}

/// Validates a webhook address: an absolute `http` or `https` URL with a host. Private and
/// loopback addresses are accepted.
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

/// The webhook of an organization, if configured. Requires [`Permission::ManageWebhook`]: the
/// URL may embed a secret, so members do not see it.
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

/// Creates or replaces the webhook of an organization. Disabling it or changing its URL abandons
/// its pending deliveries, as removing it does: retries never go to an address the admins
/// replaced or turned off. Requires [`Permission::ManageWebhook`].
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
            if !enabled || model.url != url.as_str() {
                deliveries::cancel_pending(database, organization_id).await?;
            }
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
                exploited_only: Set(exploited_only),
            }
            .insert(database)
            .await?
        }
    };
    Ok(view(model))
}

/// Removes the webhook of an organization and abandons its pending deliveries. Requires
/// [`Permission::ManageWebhook`]; removing a missing webhook succeeds.
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
    deliveries::cancel_pending(database, organization_id).await?;
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayloadStaleProject {
    pub project: String,
    pub last_upload_at: Option<DateTime<FixedOffset>>,
    pub url: String,
}

/// `projects.stale`: projects of one organization whose SBOM stopped coming.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StaleProjectsPayload {
    pub event: String,
    pub organization: PayloadOrganization,
    pub projects: Vec<PayloadStaleProject>,
}

fn run(outcome: &RunOutcome) -> PayloadRun {
    PayloadRun {
        id: outcome.run_id,
        trigger: outcome.trigger.as_str().to_owned(),
        started_at: outcome.started_at,
    }
}

/// An absolute link to a page of the interface.
pub fn link(public_url: &Url, path: &str) -> String {
    public_url
        .join(path)
        .map_or_else(|_| public_url.to_string(), |url| url.to_string())
}

/// A document sent to a webhook.
pub trait Payload: Serialize {
    /// The `event` field: `findings.new`, `projects.stale` or `run.failed`.
    fn event(&self) -> &str;
}

impl Payload for NewFindingsPayload {
    fn event(&self) -> &str {
        &self.event
    }
}

impl Payload for StaleProjectsPayload {
    fn event(&self) -> &str {
        &self.event
    }
}

impl Payload for RunFailedPayload {
    fn event(&self) -> &str {
        &self.event
    }
}

/// A webhook delivery to make.
#[derive(Debug, Clone)]
pub struct Delivery<T> {
    /// `None` for the instance's failure webhook.
    pub organization_id: Option<i64>,
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

/// The open findings of a run's scope that were never notified as known exploited, in the order
/// they were found.
async fn unnotified_open_findings(
    database: &impl ConnectionTrait,
    scope: Scope,
) -> Result<Vec<Candidate>> {
    // Ordered explicitly: SQLite happens to return rows by identifier, PostgreSQL in whatever
    // order its table holds them, which changes as rows are updated.
    let mut query = findings::Entity::find()
        .filter(findings::Column::Status.eq("open"))
        .filter(findings::Column::ExploitedNotifiedAt.is_null())
        .order_by_asc(findings::Column::Id);
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
    let facts = exploitation::vulnerability_facts(
        database,
        open.iter().map(|finding| finding.vulnerability_id.as_str()),
    )
    .await?;
    Ok(open
        .into_iter()
        .filter_map(|finding| {
            let project = projects.get(&finding.project_id)?;
            // Cloned, not removed: several findings can share a vulnerability.
            let record = facts
                .get(&finding.vulnerability_id)
                .cloned()
                .unwrap_or_default();
            Some(Candidate {
                organization_id: project.organization_id,
                project_slug: project.slug.clone(),
                aliases: record.aliases,
                summary: record.summary,
                cvss_score: record.cvss_score,
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
            organization_id: Some(organization_id),
            url: webhook.url,
            payload,
        });
    }
    mark_notified(database, &to_mark).await?;
    Ok(deliveries)
}

/// The `projects.stale` deliveries to make: one per organization with an enabled webhook and
/// projects that became stale since their last notification, whatever the webhook's minimum
/// severity and `exploited_only`. The projects are marked as notified.
pub async fn stale_deliveries(
    database: &impl ConnectionTrait,
    stale_after_days: u32,
    public_url: &Url,
) -> Result<Vec<Delivery<StaleProjectsPayload>>> {
    let mut deliveries = Vec::new();
    let mut notified = Vec::new();
    for (organization_id, projects) in staleness::newly_stale(database, stale_after_days).await? {
        let Some(organization) = organizations::Entity::find_by_id(organization_id)
            .one(database)
            .await?
        else {
            continue;
        };
        let Some(webhook) = organization_webhooks::Entity::find_by_id(organization_id)
            .one(database)
            .await?
            .filter(|webhook| webhook.enabled)
        else {
            continue;
        };
        notified.extend(projects.iter().map(|project| project.id));
        deliveries.push(Delivery {
            organization_id: Some(organization_id),
            url: webhook.url,
            payload: StaleProjectsPayload {
                event: "projects.stale".to_owned(),
                projects: projects
                    .into_iter()
                    .map(|project| PayloadStaleProject {
                        url: link(
                            public_url,
                            &format!(
                                "organizations/{}/projects/{}",
                                organization.slug, project.slug
                            ),
                        ),
                        project: project.slug,
                        last_upload_at: project.last_upload_at,
                    })
                    .collect(),
                organization: PayloadOrganization {
                    url: link(public_url, &format!("organizations/{}", organization.slug)),
                    slug: organization.slug,
                    name: organization.name,
                },
            },
        });
    }
    staleness::mark_notified(database, &notified).await?;
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

/// Records deliveries in the queue, due now, and returns their ids. Nothing is posted: the
/// caller attempts them with [`Notifier::attempt_all`], or leaves them to the retry loop.
pub async fn enqueue<T: Payload>(
    database: &impl ConnectionTrait,
    deliveries: &[Delivery<T>],
) -> Result<Vec<i64>> {
    let now = Utc::now().fixed_offset();
    let mut ids = Vec::with_capacity(deliveries.len());
    for delivery in deliveries {
        let row = deliveries::enqueue(
            database,
            delivery.organization_id,
            &delivery.url,
            delivery.payload.event(),
            &delivery.payload,
            now,
        )
        .await?;
        ids.push(row.id);
    }
    Ok(ids)
}

/// Prepares the `findings.new` deliveries of a run ([`new_findings_deliveries`]) and records
/// them in the queue, in the transaction that marks the findings notified: either every
/// document is owed to its receiver, or nothing is marked. Returns the ids to attempt.
pub async fn queue_new_findings(
    database: &DatabaseConnection,
    outcome: &RunOutcome,
    public_url: &Url,
) -> Result<Vec<i64>> {
    let transaction = database.begin().await?;
    let deliveries = new_findings_deliveries(&transaction, outcome, public_url).await?;
    let ids = enqueue(&transaction, &deliveries).await?;
    transaction.commit().await?;
    Ok(ids)
}

/// Prepares the `projects.stale` deliveries ([`stale_deliveries`]) and records them in the
/// queue, in the transaction that marks the projects notified. Returns the ids to attempt.
pub async fn queue_stale(
    database: &DatabaseConnection,
    stale_after_days: u32,
    public_url: &Url,
) -> Result<Vec<i64>> {
    let transaction = database.begin().await?;
    let deliveries = stale_deliveries(&transaction, stale_after_days, public_url).await?;
    let ids = enqueue(&transaction, &deliveries).await?;
    transaction.commit().await?;
    Ok(ids)
}

/// Sends webhook payloads through the delivery queue.
#[derive(Debug, Clone)]
pub struct Notifier {
    http: reqwest::Client,
}

impl Notifier {
    /// A client with a 15-second timeout per post, so a receiver that hangs holds one attempt
    /// only. Fails only if the TLS backend cannot be initialized.
    pub fn new() -> std::result::Result<Self, reqwest::Error> {
        Ok(Self {
            http: reqwest::Client::builder()
                .user_agent(concat!("nanobom/", env!("CARGO_PKG_VERSION")))
                .timeout(Duration::from_secs(15))
                .build()?,
        })
    }

    /// Posts a JSON document once.
    async fn post(&self, url: &str, body: String) -> Attempt {
        let request = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        match request.send().await {
            Ok(response) => Attempt::Answered {
                status: response.status().as_u16(),
                description: response.status().to_string(),
            },
            Err(error) => Attempt::Unreachable(error.without_url().to_string()),
        }
    }

    /// Records every delivery in the queue, then makes their first attempts. All rows exist
    /// before the first post, so a receiver that hangs and a restart meanwhile lose no
    /// document. Failed attempts are left to [`Notifier::retry_due`].
    pub async fn deliver<T: Payload>(
        &self,
        database: &impl ConnectionTrait,
        deliveries: Vec<Delivery<T>>,
    ) -> Result<Vec<Outcome>> {
        let ids = enqueue(database, &deliveries).await?;
        self.attempt_all(database, &ids).await
    }

    /// Makes the first attempt of queued deliveries, one after the other. A delivery that
    /// another attempt holds, or that was cancelled, is skipped.
    pub async fn attempt_all(
        &self,
        database: &impl ConnectionTrait,
        ids: &[i64],
    ) -> Result<Vec<Outcome>> {
        let mut outcomes = Vec::new();
        for &id in ids {
            outcomes.extend(self.attempt(database, id).await?);
        }
        Ok(outcomes)
    }

    /// Attempts the deliveries that are due, at most `limit` of them, oldest due first. Called
    /// by the server's retry loop; a delivery that a concurrent attempt claimed is skipped.
    pub async fn retry_due(
        &self,
        database: &impl ConnectionTrait,
        limit: u64,
    ) -> Result<Vec<Outcome>> {
        let mut outcomes = Vec::new();
        for row in deliveries::due(database, Utc::now().fixed_offset(), limit).await? {
            outcomes.extend(self.attempt(database, row.id).await?);
        }
        Ok(outcomes)
    }

    /// Claims a delivery, posts it and records the result; `None` when another attempt holds
    /// it, it is not due, or it was cancelled during the attempt.
    async fn attempt(&self, database: &impl ConnectionTrait, id: i64) -> Result<Option<Outcome>> {
        let Some(row) = deliveries::claim(database, id, Utc::now().fixed_offset()).await? else {
            return Ok(None);
        };
        let attempt = self.post(&row.url, row.payload.clone()).await;
        log(&row, &attempt);
        let delivery = row.id;
        let outcome =
            deliveries::record(database, row, &attempt, Utc::now().fixed_offset()).await?;
        if outcome.is_none() {
            tracing::info!(
                delivery,
                "webhook delivery cancelled or taken over during its attempt; result not recorded"
            );
        }
        Ok(outcome)
    }
}

fn log(row: &webhook_deliveries::Model, attempt: &Attempt) {
    let number = row.attempts + 1;
    if attempt.succeeded() {
        tracing::info!(
            delivery = row.id,
            organization = row.organization_id,
            event = row.event,
            attempt = number,
            "webhook delivered"
        );
    } else {
        let status = attempt.description();
        tracing::warn!(
            delivery = row.id,
            organization = row.organization_id,
            event = row.event,
            attempt = number,
            status,
            "webhook delivery failed"
        );
    }
}
