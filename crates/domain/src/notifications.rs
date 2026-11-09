//! Webhooks and emails: each organization can send its new findings to a URL as JSON, grouped
//! per run, and by email ([`crate::email`]); the instance can report failed runs to another URL.
//!
//! Payloads (documented in the guide's webhook reference):
//!
//! - `findings.new`: new and reopened findings of one organization, at or above the webhook's
//!   minimum severity, and open findings that became known exploited since the last run
//!   (whatever their severity);
//! - `projects.stale`: projects of one organization whose SBOM stopped coming;
//! - `run.failed`: a run that could not complete, sent to the instance's failure webhook.
//!
//! Deliveries go through the queue of [`crate::deliveries`], which retries failed ones. An
//! organization's webhook and its email recipients are two [`Target`]s of the same documents,
//! each with its own filters (minimum severity, known exploited only): a document is prepared
//! for each.
//!
//! Only the webhook settings ([`get`], [`set`], [`delete`]) take an actor. The rest is called
//! by the run worker after a run, with no actor; isolation then rests on grouping: a
//! `findings.new` or `projects.stale` document is built per organization from that
//! organization's projects only, and goes to that organization's webhook and email recipients
//! only. `run.failed`,
//! whose error may name packages of any organization, goes to the instance's failure webhook,
//! configured by the operator, never to an organization.
//!
//! Preparing a document and marking what it reports as notified (findings that became known
//! exploited, stale projects) happen in one transaction with the enqueueing
//! ([`queue_new_findings`], [`queue_stale`]): a crash cannot lose a notification nor send it
//! twice. Findings are marked even in organizations without an enabled webhook or email, so
//! enabling one later does not replay old findings; stale projects are marked only when a
//! document reports them, so a webhook enabled later still hears about projects that are
//! already stale.
//!
//! An organization's webhook has a [`Format`]: the generic JSON documents above, or a message
//! for Slack or Microsoft Teams ([`crate::chat`]) that says the same thing. The format applies to
//! `findings.new` and `projects.stale`; `run.failed` is always JSON. The body is rendered when
//! the delivery is queued ([`Payload::render`]), so retries resend it unchanged.
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
    EntityTrait, ModelTrait, QueryFilter, QueryOrder,
};
use serde::{Deserialize, Serialize};

use crate::{
    access::{Actor, Permission},
    chat,
    deliveries::{self, Attempt, Channel, Outcome},
    dependencies::Graph,
    email::{self, Language, Mailer},
    error::{Error, Result},
    evaluation::{self, RunOutcome, Scope},
    exploitation::{self, Exploitation, QUERY_CHUNK},
    problem::Problem,
    staleness,
};

/// What a webhook receives.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// The documents described in the webhook reference.
    #[default]
    Json,
    /// A Slack Incoming Webhook message (Block Kit).
    Slack,
    /// A message with an Adaptive Card, for a Microsoft Teams Workflows webhook.
    Teams,
}

impl Format {
    pub const ALL: [Format; 3] = [Format::Json, Format::Slack, Format::Teams];

    /// The lower-case name stored in the database and shown in the settings form; parsed back
    /// with [`Format::parse`].
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Json => "json",
            Format::Slack => "slack",
            Format::Teams => "teams",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|format| format.as_str() == value)
    }
}

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
    /// What the receiver gets: JSON documents, or a chat message.
    pub format: Format,
}

fn view(model: organization_webhooks::Model) -> Webhook {
    Webhook {
        url: model.url,
        minimum_severity: model.minimum_severity.parse().unwrap_or(Severity::Unknown),
        enabled: model.enabled,
        exploited_only: model.exploited_only,
        format: Format::parse(&model.format).unwrap_or_default(),
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
/// replaced or turned off. Changing its format abandons them too, since their bodies were
/// rendered for the previous one. Requires [`Permission::ManageWebhook`].
pub async fn set(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
    webhook: &Webhook,
) -> Result<Webhook> {
    actor
        .authorize(database, organization_id, Permission::ManageWebhook)
        .await?;
    let url = validate_url(&webhook.url)?;
    let Webhook {
        minimum_severity,
        enabled,
        exploited_only,
        format,
        ..
    } = *webhook;
    let existing = organization_webhooks::Entity::find_by_id(organization_id)
        .one(database)
        .await?;
    let model = match existing {
        Some(model) => {
            if !enabled || model.url != url.as_str() || model.format != format.as_str() {
                deliveries::cancel_pending(database, organization_id, Channel::Webhook).await?;
            }
            let mut active: organization_webhooks::ActiveModel = model.into();
            active.url = Set(url.to_string());
            active.minimum_severity = Set(minimum_severity.as_str().to_owned());
            active.enabled = Set(enabled);
            active.exploited_only = Set(exploited_only);
            active.format = Set(format.as_str().to_owned());
            active.update(database).await?
        }
        None => {
            organization_webhooks::ActiveModel {
                organization_id: Set(organization_id),
                url: Set(url.to_string()),
                minimum_severity: Set(minimum_severity.as_str().to_owned()),
                enabled: Set(enabled),
                exploited_only: Set(exploited_only),
                format: Set(format.as_str().to_owned()),
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
    deliveries::cancel_pending(database, organization_id, Channel::Webhook).await?;
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
    /// The names of the project's direct dependencies that lead to the component, per the
    /// dependency graph of its latest SBOM; empty when the graph does not say.
    pub introduced_via: Vec<String>,
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

    /// The body to post, in the webhook's format. Documents without a chat rendering are sent
    /// as JSON whatever the format.
    fn render(&self, _format: Format) -> String {
        serde_json::to_string(self).expect("payloads serialize to JSON")
    }

    /// The email of this document, for the documents organizations receive by email.
    fn email(&self, _language: Language) -> Option<email::Message> {
        None
    }
}

impl Payload for NewFindingsPayload {
    fn event(&self) -> &str {
        &self.event
    }

    fn render(&self, format: Format) -> String {
        match format {
            Format::Json => serde_json::to_string(self).expect("payloads serialize to JSON"),
            Format::Slack => chat::slack_new_findings(self),
            Format::Teams => chat::teams_new_findings(self),
        }
    }

    fn email(&self, language: Language) -> Option<email::Message> {
        Some(email::new_findings(self, language))
    }
}

impl Payload for StaleProjectsPayload {
    fn event(&self) -> &str {
        &self.event
    }

    fn render(&self, format: Format) -> String {
        match format {
            Format::Json => serde_json::to_string(self).expect("payloads serialize to JSON"),
            Format::Slack => chat::slack_stale_projects(self),
            Format::Teams => chat::teams_stale_projects(self),
        }
    }

    fn email(&self, language: Language) -> Option<email::Message> {
        Some(email::stale_projects(self, language))
    }
}

impl Payload for RunFailedPayload {
    fn event(&self) -> &str {
        &self.event
    }
}

/// Where a delivery goes, and how its payload is rendered when it is queued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Webhook {
        url: String,
        format: Format,
    },
    Email {
        recipients: Vec<String>,
        language: Language,
    },
}

/// A delivery to make.
#[derive(Debug, Clone)]
pub struct Delivery<T> {
    /// `None` for the instance's failure webhook.
    pub organization_id: Option<i64>,
    pub target: Target,
    pub payload: T,
}

/// Where an organization's notifications go, with the filters of each destination.
struct Destination {
    target: Target,
    minimum_severity: Severity,
    exploited_only: bool,
}

impl Destination {
    fn accepts(&self, entry: &Entry) -> bool {
        if self.exploited_only {
            entry.exploitation.known_exploited
        } else {
            entry.exploitation.known_exploited || entry.severity >= self.minimum_severity
        }
    }
}

/// The destinations of an organization: its webhook if enabled, and its email recipients when
/// the instance sends email (`email`) and the organization has some.
async fn destinations(
    database: &impl ConnectionTrait,
    organization_id: i64,
    email: bool,
) -> Result<Vec<Destination>> {
    let mut destinations = Vec::new();
    if let Some(webhook) = organization_webhooks::Entity::find_by_id(organization_id)
        .one(database)
        .await?
        .filter(|webhook| webhook.enabled)
    {
        destinations.push(Destination {
            minimum_severity: webhook
                .minimum_severity
                .parse()
                .unwrap_or(Severity::Unknown),
            exploited_only: webhook.exploited_only,
            target: Target::Webhook {
                format: Format::parse(&webhook.format).unwrap_or_default(),
                url: webhook.url,
            },
        });
    }
    if email && let Some(settings) = email::settings(database, organization_id).await? {
        destinations.push(Destination {
            minimum_severity: settings.minimum_severity,
            exploited_only: settings.exploited_only,
            target: Target::Email {
                recipients: settings.recipients,
                language: settings.language,
            },
        });
    }
    Ok(destinations)
}

/// A finding to deliver, with why and what is known about its exploitation.
struct Entry {
    finding_id: i64,
    organization_id: i64,
    project_id: i64,
    project_slug: String,
    purl: String,
    vulnerability_id: String,
    aliases: Vec<String>,
    summary: Option<String>,
    severity: Severity,
    cvss_score: Option<f64>,
    reason: Reason,
    exploitation: Exploitation,
}

/// Why a finding is delivered, sent as `PayloadFinding::reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    New,
    Reopened,
    Exploited,
}

impl Reason {
    fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Reopened => "reopened",
            Self::Exploited => "exploited",
        }
    }
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

/// The `findings.new` deliveries a successful run calls for: one per organization and
/// destination (an enabled webhook, email recipients when `email` is on) with findings to
/// report, which are
///
/// - the findings the run opened or reopened, at or above the destination's minimum severity
///   (known exploited ones whatever their severity);
/// - the open findings of the run's scope that are known exploited and were never notified as
///   such (`exploited` reason), once.
///
/// With `exploited_only`, only known exploited findings are delivered. Every known exploited
/// open finding of the scope is then marked as notified, with or without a destination, so
/// that enabling one later does not replay old findings.
pub async fn new_findings_deliveries(
    database: &impl ConnectionTrait,
    outcome: &RunOutcome,
    public_url: &Url,
    email: bool,
) -> Result<Vec<Delivery<NewFindingsPayload>>> {
    let opened: BTreeSet<i64> = outcome
        .new_findings
        .iter()
        .map(|finding| finding.finding_id)
        .collect();
    let candidates = unnotified_open_findings(database, outcome.scope).await?;

    // Keyed by finding id: a finding the run opened is also a candidate, with the same
    // identifiers, so its two keys carry the same data.
    let keyed: Vec<(i64, Vec<String>)> = outcome
        .new_findings
        .iter()
        .map(|finding| {
            (
                finding.finding_id,
                exploitation::cve_ids(&finding.vulnerability_id, &finding.aliases),
            )
        })
        .chain(candidates.iter().map(|candidate| {
            (
                candidate.finding.id,
                exploitation::cve_ids(&candidate.finding.vulnerability_id, &candidate.aliases),
            )
        }))
        .collect();
    let exploitation = exploitation::for_findings(database, &keyed).await?;
    let exploitation_of = |id: i64| exploitation.get(&id).cloned().unwrap_or_default();

    let mut entries: Vec<Entry> = outcome
        .new_findings
        .iter()
        .map(|finding| Entry {
            finding_id: finding.finding_id,
            organization_id: finding.organization_id,
            project_id: finding.project_id,
            project_slug: finding.project_slug.clone(),
            purl: finding.purl.clone(),
            vulnerability_id: finding.vulnerability_id.clone(),
            aliases: finding.aliases.clone(),
            summary: finding.summary.clone(),
            severity: finding.severity,
            cvss_score: finding.cvss_score,
            reason: if finding.reopened {
                Reason::Reopened
            } else {
                Reason::New
            },
            exploitation: exploitation_of(finding.finding_id),
        })
        .collect();
    let mut to_mark: Vec<i64> = entries
        .iter()
        .filter(|entry| entry.exploitation.known_exploited)
        .map(|entry| entry.finding_id)
        .collect();
    for candidate in candidates {
        let exploitation = exploitation_of(candidate.finding.id);
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
            project_id: candidate.finding.project_id,
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
            reason: Reason::Exploited,
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
    let mut graphs: HashMap<i64, Graph> = HashMap::new();
    for (organization_id, entries) in by_organization {
        let destinations = destinations(database, organization_id, email).await?;
        if destinations.is_empty() {
            continue;
        }
        let Some(organization) = organizations::Entity::find_by_id(organization_id)
            .one(database)
            .await?
        else {
            continue;
        };
        for destination in destinations {
            let entries: Vec<&Entry> = entries
                .iter()
                .filter(|entry| destination.accepts(entry))
                .collect();
            if entries.is_empty() {
                continue;
            }
            let mut findings = Vec::with_capacity(entries.len());
            for entry in &entries {
                let graph = match graphs.entry(entry.project_id) {
                    std::collections::hash_map::Entry::Occupied(graph) => graph.into_mut(),
                    std::collections::hash_map::Entry::Vacant(vacant) => {
                        vacant.insert(Graph::load(database, entry.project_id).await?)
                    }
                };
                let mut introduced_via: Vec<String> = graph
                    .introduced_via(&entry.purl)
                    .into_iter()
                    .map(|component| component.name)
                    .collect();
                introduced_via.dedup();
                findings.push(PayloadFinding {
                    url: link(public_url, &format!("findings/{}", entry.finding_id)),
                    project: entry.project_slug.clone(),
                    component: entry.purl.clone(),
                    vulnerability: entry.vulnerability_id.clone(),
                    aliases: entry.aliases.clone(),
                    severity: entry.severity,
                    cvss_score: entry.cvss_score,
                    summary: entry.summary.clone(),
                    reopened: entry.reason == Reason::Reopened,
                    reason: entry.reason.as_str().to_owned(),
                    known_exploited: entry.exploitation.known_exploited,
                    kev_due_date: entry.exploitation.kev_due_date,
                    epss: entry.exploitation.epss_score,
                    epss_percentile: entry.exploitation.epss_percentile,
                    introduced_via,
                });
            }
            let payload = NewFindingsPayload {
                event: "findings.new".to_owned(),
                organization: PayloadOrganization {
                    url: link(public_url, &format!("organizations/{}", organization.slug)),
                    slug: organization.slug.clone(),
                    name: organization.name.clone(),
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
                findings,
            };
            deliveries.push(Delivery {
                organization_id: Some(organization_id),
                target: destination.target,
                payload,
            });
        }
    }
    mark_notified(database, &to_mark).await?;
    Ok(deliveries)
}

/// The `projects.stale` deliveries to make: one per organization and destination (an enabled
/// webhook, email recipients when `email` is on) for the projects that became stale since their
/// last notification, whatever the destination's minimum severity and `exploited_only`. The
/// projects are marked as notified.
pub async fn stale_deliveries(
    database: &impl ConnectionTrait,
    stale_after_days: u32,
    public_url: &Url,
    email: bool,
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
        let destinations = destinations(database, organization_id, email).await?;
        if destinations.is_empty() {
            continue;
        }
        notified.extend(projects.iter().map(|project| project.id));
        let payload = StaleProjectsPayload {
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
        };
        for destination in destinations {
            deliveries.push(Delivery {
                organization_id: Some(organization_id),
                target: destination.target,
                payload: payload.clone(),
            });
        }
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
        let (channel, address, body) = match &delivery.target {
            Target::Webhook { url, format } => (
                Channel::Webhook,
                url.clone(),
                delivery.payload.render(*format),
            ),
            Target::Email {
                recipients,
                language,
            } => {
                let message = delivery
                    .payload
                    .email(*language)
                    .expect("only documents with an email are sent by email");
                (
                    Channel::Email,
                    recipients.join(", "),
                    serde_json::to_string(&message).expect("messages serialize to JSON"),
                )
            }
        };
        let row = deliveries::enqueue_body(
            database,
            delivery.organization_id,
            channel,
            &address,
            delivery.payload.event(),
            body,
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
    email: bool,
) -> Result<Vec<i64>> {
    let transaction = crate::database::begin_write(database).await?;
    let deliveries = new_findings_deliveries(&transaction, outcome, public_url, email).await?;
    let ids = enqueue(&transaction, &deliveries).await?;
    transaction.commit().await?;
    // The attempt logs only know the queued row, whose body is rendered (JSON, Slack, Teams or
    // an email), so the number of findings is logged here, under the same delivery id.
    for (delivery, id) in deliveries.iter().zip(&ids) {
        tracing::info!(
            delivery = id,
            organization = delivery.organization_id,
            channel = match delivery.target {
                Target::Webhook { .. } => Channel::Webhook.as_str(),
                Target::Email { .. } => Channel::Email.as_str(),
            },
            findings = delivery.payload.count,
            known_exploited = delivery.payload.known_exploited_count,
            "findings.new delivery queued"
        );
    }
    Ok(ids)
}

/// Prepares the `projects.stale` deliveries ([`stale_deliveries`]) and records them in the
/// queue, in the transaction that marks the projects notified. Returns the ids to attempt.
pub async fn queue_stale(
    database: &DatabaseConnection,
    stale_after_days: u32,
    public_url: &Url,
    email: bool,
) -> Result<Vec<i64>> {
    let transaction = crate::database::begin_write(database).await?;
    let deliveries = stale_deliveries(&transaction, stale_after_days, public_url, email).await?;
    let ids = enqueue(&transaction, &deliveries).await?;
    transaction.commit().await?;
    Ok(ids)
}

/// Records the runs left `running` by a crash or a restart as failed
/// ([`evaluation::fail_interrupted`]) and queues their `run.failed` documents to
/// `failure_webhook` (`None`: not configured), in one transaction, so that a crash in between
/// cannot leave a run failed with its document lost. Nothing is posted: the retry loop
/// delivers them. Returns the failed runs.
pub async fn fail_interrupted_runs(
    database: &DatabaseConnection,
    failure_webhook: Option<&Url>,
    public_url: &Url,
) -> Result<Vec<RunOutcome>> {
    let transaction = crate::database::begin_write(database).await?;
    let outcomes = evaluation::fail_interrupted(&transaction).await?;
    if let Some(url) = failure_webhook {
        let failures: Vec<Delivery<RunFailedPayload>> = outcomes
            .iter()
            .filter_map(|outcome| {
                Some(Delivery {
                    organization_id: None,
                    target: Target::Webhook {
                        url: url.to_string(),
                        format: Format::Json,
                    },
                    payload: run_failed_payload(outcome, public_url)?,
                })
            })
            .collect();
        enqueue(&transaction, &failures).await?;
    }
    transaction.commit().await?;
    Ok(outcomes)
}

/// Sends webhook payloads and emails through the delivery queue.
#[derive(Debug, Clone)]
pub struct Notifier {
    http: reqwest::Client,
    /// `None` when the instance has no SMTP server: email is off.
    mailer: Option<Mailer>,
}

impl Notifier {
    /// A client with a 15-second timeout per post, so a receiver that hangs holds one attempt
    /// only, and no mailer. Fails only if the TLS backend cannot be initialized.
    pub fn new() -> std::result::Result<Self, reqwest::Error> {
        Ok(Self {
            http: reqwest::Client::builder()
                .user_agent(concat!("nanobom/", env!("CARGO_PKG_VERSION")))
                .timeout(Duration::from_secs(15))
                .build()?,
            mailer: None,
        })
    }

    /// Sends emails through this mailer.
    #[must_use]
    pub fn with_mailer(mut self, mailer: Mailer) -> Self {
        self.mailer = Some(mailer);
        self
    }

    /// The mailer, when the instance sends email.
    pub fn mailer(&self) -> Option<&Mailer> {
        self.mailer.as_ref()
    }

    /// Posts a JSON body once. Slack and Teams answer 200 and 202, which count as delivered
    /// like any 2xx.
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
    ) -> Result<Vec<(Channel, Outcome)>> {
        let ids = enqueue(database, &deliveries).await?;
        self.attempt_all(database, &ids).await
    }

    /// Makes the first attempt of queued deliveries, one after the other. A delivery that
    /// another attempt holds, or that was cancelled, is skipped.
    pub async fn attempt_all(
        &self,
        database: &impl ConnectionTrait,
        ids: &[i64],
    ) -> Result<Vec<(Channel, Outcome)>> {
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
    ) -> Result<Vec<(Channel, Outcome)>> {
        let mut outcomes = Vec::new();
        for row in deliveries::due(database, Utc::now().fixed_offset(), limit).await? {
            outcomes.extend(self.attempt(database, row.id).await?);
        }
        Ok(outcomes)
    }

    /// Claims a delivery, posts or mails it and records the result; `None` when another
    /// attempt holds it, it is not due, or it was cancelled during the attempt.
    async fn attempt(
        &self,
        database: &impl ConnectionTrait,
        id: i64,
    ) -> Result<Option<(Channel, Outcome)>> {
        let Some(row) = deliveries::claim(database, id, Utc::now().fixed_offset()).await? else {
            return Ok(None);
        };
        let channel = Channel::parse(&row.channel);
        let attempt = match (channel, &self.mailer) {
            (Channel::Webhook, _) => self.post(&row.url, row.payload.clone()).await,
            (Channel::Email, Some(mailer)) => mailer.send_stored(&row.url, &row.payload).await,
            (Channel::Email, None) => {
                Attempt::Impossible("email is not configured on this server".to_owned())
            }
        };
        log(&row, channel, &attempt);
        let delivery = row.id;
        let outcome =
            deliveries::record(database, row, &attempt, Utc::now().fixed_offset()).await?;
        if outcome.is_none() {
            tracing::info!(
                delivery,
                channel = channel.as_str(),
                "delivery cancelled or taken over during its attempt; result not recorded"
            );
        }
        Ok(outcome.map(|outcome| (channel, outcome)))
    }
}

fn log(row: &webhook_deliveries::Model, channel: Channel, attempt: &Attempt) {
    let number = row.attempts + 1;
    let channel = channel.as_str();
    if attempt.succeeded() {
        tracing::info!(
            delivery = row.id,
            organization = row.organization_id,
            channel,
            event = row.event,
            attempt = number,
            "notification delivered"
        );
    } else {
        let status = attempt.description();
        tracing::warn!(
            delivery = row.id,
            organization = row.organization_id,
            channel,
            event = row.event,
            attempt = number,
            status,
            "notification delivery failed"
        );
    }
}
