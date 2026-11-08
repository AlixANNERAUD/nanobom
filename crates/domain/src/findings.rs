//! Findings: a vulnerability affecting a component of a project, with its lifecycle (open,
//! fixed, ignored) and the full history of what happened to it.
//!
//! A finding is identified by its project, its package URL and its vulnerability identifier,
//! and is never deleted while its project exists: a fixed finding that comes back is reopened,
//! keeping its history. Runs ([`crate::evaluation`]) open, fix and reopen findings; members
//! only ignore and restore them ([`ignore`], [`restore`]). Every status change appends an
//! [`Event`] in the same transaction:
//!
//! - a run reports it: opened;
//! - open or ignored, a run no longer reports it: fixed;
//! - fixed, a run reports it again: reopened (open);
//! - open, a member ignores it: ignored;
//! - ignored, a member restores it or the first run after its expiry comes: open.
//!
//! Listings carry the [`Exploitation`] signals of each finding, and order by them: known
//! exploited first, then by severity, then by EPSS. The severity stored on a finding is the
//! highest among its aliases at the last run that reported it.

use std::{collections::HashMap, str::FromStr};

use chrono::{DateTime, FixedOffset, Utc};
use nanobom_entity::{
    finding_events, findings, organizations, projects, upload_tokens, users, vulnerabilities,
};
use nanobom_osv::{Severity, Vulnerability, schema::Reference};
use packageurl::PackageUrl;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    QueryOrder, TransactionSession, TransactionTrait,
};
use serde::{Deserialize, Serialize};

use crate::{
    access::{Actor, Permission},
    dependencies::{ComponentRef, DependencyPaths, Graph},
    error::{Error, Result},
    evaluation::record_event,
    exploitation::{self, Exploitation, QUERY_CHUNK, VulnerabilityFacts, vulnerability_facts},
    problem::Problem,
};

/// Where a finding stands in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Reported by the latest run and not ignored.
    Open,
    /// No longer reported: the component is gone or upgraded, or OSV no longer lists it.
    Fixed,
    /// Reported, but a member decided it does not apply, possibly until an expiry date.
    Ignored,
}

impl Status {
    /// Every status, in the order the interface shows them.
    pub const ALL: [Status; 3] = [Status::Open, Status::Ignored, Status::Fixed];

    /// The name stored in the `findings.status` column.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Open => "open",
            Status::Fixed => "fixed",
            Status::Ignored => "ignored",
        }
    }

    pub(crate) fn parse(value: &str) -> Self {
        match value {
            "fixed" => Status::Fixed,
            "ignored" => Status::Ignored,
            _ => Status::Open,
        }
    }
}

impl FromStr for Status {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "open" => Ok(Status::Open),
            "fixed" => Ok(Status::Fixed),
            "ignored" => Ok(Status::Ignored),
            other => Err(format!("unknown status {other:?}")),
        }
    }
}

/// What happened to a finding. Run events carry the run; member events carry the member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Opened,
    Fixed,
    /// A fixed finding reported again.
    Reopened,
    /// Ignored by a member, with a reason.
    Ignored,
    /// Returned to open by a member.
    Restored,
    /// Returned to open by a run because the ignore reached its expiry.
    IgnoreExpired,
}

impl EventKind {
    /// The name stored in the `finding_events.kind` column.
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Opened => "opened",
            EventKind::Fixed => "fixed",
            EventKind::Reopened => "reopened",
            EventKind::Ignored => "ignored",
            EventKind::Restored => "restored",
            EventKind::IgnoreExpired => "ignore_expired",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "fixed" => EventKind::Fixed,
            "reopened" => EventKind::Reopened,
            "ignored" => EventKind::Ignored,
            "restored" => EventKind::Restored,
            "ignore_expired" => EventKind::IgnoreExpired,
            _ => EventKind::Opened,
        }
    }
}

/// A finding as listed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: i64,
    pub project_id: i64,
    pub project_slug: String,
    pub purl: String,
    pub ecosystem: String,
    pub component_name: String,
    pub component_version: Option<String>,
    pub vulnerability_id: String,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub severity: Severity,
    pub cvss_score: Option<f64>,
    pub status: Status,
    pub first_seen_at: DateTime<FixedOffset>,
    pub last_seen_at: DateTime<FixedOffset>,
    pub fixed_at: Option<DateTime<FixedOffset>>,
    /// The reason of the latest ignore. It is not cleared when the finding is restored or
    /// fixed, so read it only while the status is [`Status::Ignored`].
    pub ignore_reason: Option<String>,
    /// Like `ignore_reason`, meaningful only while the finding is ignored.
    pub ignore_expires_at: Option<DateTime<FixedOffset>>,
    pub exploitation: Exploitation,
    /// The project's direct dependencies that lead to the component (itself when it is one),
    /// per the dependency graph of the latest SBOM, sorted by name. Empty when the graph does
    /// not say, or when the component is no longer in the project.
    pub introduced_via: Vec<ComponentRef>,
}

/// Which findings to list. Empty lists mean "any".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filter {
    pub severities: Vec<Severity>,
    pub statuses: Vec<Status>,
    pub ecosystem: Option<String>,
    /// Only findings with a known exploited CVE.
    pub exploited_only: bool,
}

fn component_name_and_version(purl: &str) -> (String, Option<String>) {
    match PackageUrl::from_str(purl) {
        Ok(parsed) => (
            match parsed.namespace() {
                Some(namespace) => format!("{namespace}/{}", parsed.name()),
                None => parsed.name().to_owned(),
            },
            parsed.version().map(str::to_owned),
        ),
        Err(_) => (purl.to_owned(), None),
    }
}

fn view(
    finding: findings::Model,
    project_slug: String,
    vulnerability: Option<&VulnerabilityFacts>,
) -> Finding {
    let (component_name, component_version) = component_name_and_version(&finding.purl);
    Finding {
        id: finding.id,
        project_id: finding.project_id,
        project_slug,
        component_name,
        component_version,
        ecosystem: finding.ecosystem,
        aliases: vulnerability
            .map(|vulnerability| vulnerability.aliases.clone())
            .unwrap_or_default(),
        summary: vulnerability.and_then(|vulnerability| vulnerability.summary.clone()),
        cvss_score: vulnerability.and_then(|vulnerability| vulnerability.cvss_score),
        severity: finding.severity.parse().unwrap_or(Severity::Unknown),
        status: Status::parse(&finding.status),
        purl: finding.purl,
        vulnerability_id: finding.vulnerability_id,
        first_seen_at: finding.first_seen_at,
        last_seen_at: finding.last_seen_at,
        fixed_at: finding.fixed_at,
        ignore_reason: finding.ignore_reason,
        ignore_expires_at: finding.ignore_expires_at,
        exploitation: Exploitation::default(),
        introduced_via: Vec::new(),
    }
}

/// The findings of a project: known exploited first, then most severe first, then by EPSS
/// score (findings without one last). Requires [`Permission::View`].
pub async fn list(
    database: &impl ConnectionTrait,
    actor: &Actor,
    project_id: i64,
    filter: &Filter,
) -> Result<Vec<Finding>> {
    let project = crate::projects::authorize(database, actor, project_id, Permission::View).await?;
    project_findings(database, project, filter).await
}

/// The open findings of a project an upload token covers, most severe first (then as `list`
/// orders them), for the evaluation returned to CI after an upload. The token is the
/// authorization, checked as [`crate::inventory::ingest`] does; a project outside it is
/// [`Error::NotFound`].
pub async fn open_for_upload_token(
    database: &impl ConnectionTrait,
    token: &upload_tokens::Model,
    project_id: i64,
) -> Result<Vec<Finding>> {
    // The same check as `inventory::ingest`: the token's organization, and its project when
    // the token is limited to one.
    let project = projects::Entity::find_by_id(project_id)
        .one(database)
        .await?
        .filter(|project| {
            project.organization_id == token.organization_id
                && token.project_id.is_none_or(|allowed| allowed == project.id)
        })
        .ok_or(Error::NotFound)?;
    let filter = Filter {
        statuses: vec![Status::Open],
        ..Filter::default()
    };
    let mut findings = project_findings(database, project, &filter).await?;
    // Stable: findings of the same severity keep the order of `list`.
    findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));
    Ok(findings)
}

/// The findings of a project, without authorization: known exploited first, then most severe
/// first, then by EPSS score (findings without one last), then by CVSS score, component and
/// vulnerability.
async fn project_findings(
    database: &impl ConnectionTrait,
    project: projects::Model,
    filter: &Filter,
) -> Result<Vec<Finding>> {
    let project_id = project.id;
    let mut query = findings::Entity::find().filter(findings::Column::ProjectId.eq(project_id));
    if !filter.severities.is_empty() {
        query = query.filter(
            findings::Column::Severity.is_in(filter.severities.iter().map(|value| value.as_str())),
        );
    }
    if !filter.statuses.is_empty() {
        query = query.filter(
            findings::Column::Status.is_in(filter.statuses.iter().map(|value| value.as_str())),
        );
    }
    if let Some(ecosystem) = &filter.ecosystem {
        query = query.filter(findings::Column::Ecosystem.eq(ecosystem));
    }
    let rows = query
        .order_by_asc(findings::Column::Purl)
        .all(database)
        .await?;
    let facts = vulnerability_facts(
        database,
        rows.iter().map(|finding| finding.vulnerability_id.as_str()),
    )
    .await?;
    let mut findings: Vec<Finding> = rows
        .into_iter()
        .map(|finding| {
            let vulnerability = facts.get(&finding.vulnerability_id);
            view(finding, project.slug.clone(), vulnerability)
        })
        .collect();
    let keys: Vec<(i64, Vec<String>)> = findings
        .iter()
        .map(|finding| {
            (
                finding.id,
                exploitation::cve_ids(&finding.vulnerability_id, &finding.aliases),
            )
        })
        .collect();
    let mut exploitations = exploitation::for_findings(database, &keys).await?;
    let graph = Graph::load(database, project_id).await?;
    for finding in &mut findings {
        finding.exploitation = exploitations.remove(&finding.id).unwrap_or_default();
        finding.introduced_via = graph.introduced_via(&finding.purl);
    }
    if filter.exploited_only {
        findings.retain(|finding| finding.exploitation.known_exploited);
    }
    findings.sort_by(|left, right| {
        right
            .exploitation
            .known_exploited
            .cmp(&left.exploitation.known_exploited)
            .then(right.severity.cmp(&left.severity))
            .then(
                right
                    .exploitation
                    .epss_score
                    .unwrap_or(-1.0)
                    .total_cmp(&left.exploitation.epss_score.unwrap_or(-1.0)),
            )
            .then_with(|| {
                right
                    .cvss_score
                    .unwrap_or(-1.0)
                    .total_cmp(&left.cvss_score.unwrap_or(-1.0))
            })
            .then(left.component_name.cmp(&right.component_name))
            .then(left.vulnerability_id.cmp(&right.vulnerability_id))
    });
    Ok(findings)
}

/// The ecosystems present among a project's findings, for filters. Requires
/// [`Permission::View`].
pub async fn ecosystems(
    database: &impl ConnectionTrait,
    actor: &Actor,
    project_id: i64,
) -> Result<Vec<String>> {
    crate::projects::authorize(database, actor, project_id, Permission::View).await?;
    let mut ecosystems: Vec<String> = findings::Entity::find()
        .filter(findings::Column::ProjectId.eq(project_id))
        .all(database)
        .await?
        .into_iter()
        .map(|finding| finding.ecosystem)
        .collect();
    ecosystems.sort();
    ecosystems.dedup();
    Ok(ecosystems)
}

/// One entry of a finding's history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub created_at: DateTime<FixedOffset>,
    pub kind: EventKind,
    pub actor: Option<String>,
    pub reason: Option<String>,
    pub run_id: Option<i64>,
}

/// Another component affected by the same vulnerability, in a project the actor can see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffectedComponent {
    pub finding_id: i64,
    pub organization_slug: String,
    pub project_slug: String,
    pub purl: String,
    pub status: Status,
}

/// Everything about a finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingDetail {
    pub finding: Finding,
    pub organization_slug: String,
    /// Whether the actor may ignore or restore this finding.
    pub can_triage: bool,
    pub details: Option<String>,
    pub published: Option<DateTime<FixedOffset>>,
    pub modified: DateTime<FixedOffset>,
    pub cvss_version: Option<String>,
    pub cvss_vector: Option<String>,
    /// Versions of the package that fix the vulnerability, per the OSV record's ranges.
    pub fixed_versions: Vec<String>,
    pub references: Vec<Reference>,
    pub ignored_by: Option<String>,
    pub affected_components: Vec<AffectedComponent>,
    pub events: Vec<Event>,
    /// How the project pulls in the component; `None` when its latest SBOM did not say which
    /// components the project depends on directly.
    pub dependency_paths: Option<DependencyPaths>,
}

async fn usernames(
    database: &impl ConnectionTrait,
    identifiers: impl Iterator<Item = i64>,
) -> Result<HashMap<i64, String>> {
    let identifiers: Vec<i64> = identifiers.collect();
    if identifiers.is_empty() {
        return Ok(HashMap::new());
    }
    Ok(users::Entity::find()
        .filter(users::Column::Id.is_in(identifiers))
        .all(database)
        .await?
        .into_iter()
        .map(|user| (user.id, user.username))
        .collect())
}

/// A finding with its vulnerability, history and the other affected components. Requires
/// [`Permission::View`]. The other affected components are limited to the organizations the
/// actor can see, so the page never reveals that another organization uses a package.
pub async fn detail(
    database: &impl ConnectionTrait,
    actor: &Actor,
    finding_id: i64,
) -> Result<FindingDetail> {
    let finding = findings::Entity::find_by_id(finding_id)
        .one(database)
        .await?
        .ok_or(Error::NotFound)?;
    let project =
        crate::projects::authorize(database, actor, finding.project_id, Permission::View).await?;
    let role = actor
        .authorize(database, project.organization_id, Permission::View)
        .await?;
    let organization = organizations::Entity::find_by_id(project.organization_id)
        .one(database)
        .await?
        .ok_or(Error::NotFound)?;
    let vulnerability = vulnerabilities::Entity::find_by_id(finding.vulnerability_id.clone())
        .one(database)
        .await?
        .ok_or(Error::NotFound)?;
    let record: Option<Vulnerability> = serde_json::from_str(&vulnerability.record).ok();
    let graph = Graph::load(database, project.id).await?;
    let dependency_paths = graph.paths(&finding.purl);
    let (component_name, _) = component_name_and_version(&finding.purl);
    let package_name = component_name
        .rsplit('/')
        .next()
        .unwrap_or(&component_name)
        .to_owned();
    let fixed_versions = record
        .as_ref()
        .map(|record| {
            let exact = record.fixed_versions(Some(&component_name));
            if exact.is_empty() {
                record.fixed_versions(Some(&package_name))
            } else {
                exact
            }
        })
        .unwrap_or_default();

    let events = finding_events::Entity::find()
        .filter(finding_events::Column::FindingId.eq(finding.id))
        .order_by_asc(finding_events::Column::CreatedAt)
        .order_by_asc(finding_events::Column::Id)
        .all(database)
        .await?;
    let names = usernames(
        database,
        events
            .iter()
            .filter_map(|event| event.actor_user_id)
            .chain(finding.ignored_by_user_id),
    )
    .await?;

    let visible = crate::organizations::list(database, actor)
        .await?
        .into_iter()
        .map(|organization| (organization.id, organization.slug))
        .collect::<HashMap<_, _>>();
    let mut affected_components = Vec::new();
    for (other, other_project) in findings::Entity::find()
        .filter(findings::Column::VulnerabilityId.eq(finding.vulnerability_id.clone()))
        .filter(findings::Column::Id.ne(finding.id))
        .find_also_related(projects::Entity)
        .all(database)
        .await?
    {
        let Some(other_project) = other_project else {
            continue;
        };
        let Some(organization_slug) = visible.get(&other_project.organization_id) else {
            continue;
        };
        affected_components.push(AffectedComponent {
            finding_id: other.id,
            organization_slug: organization_slug.clone(),
            project_slug: other_project.slug,
            purl: other.purl,
            status: Status::parse(&other.status),
        });
    }
    affected_components.sort_by(|left, right| {
        (&left.organization_slug, &left.project_slug, &left.purl).cmp(&(
            &right.organization_slug,
            &right.project_slug,
            &right.purl,
        ))
    });

    Ok(FindingDetail {
        organization_slug: organization.slug,
        can_triage: role.allows(Permission::TriageFindings),
        details: vulnerability.details.clone(),
        published: vulnerability.published,
        modified: vulnerability.modified,
        cvss_version: vulnerability.cvss_version.clone(),
        cvss_vector: vulnerability.cvss_vector.clone(),
        fixed_versions,
        references: record.map(|record| record.references).unwrap_or_default(),
        ignored_by: finding
            .ignored_by_user_id
            .and_then(|id| names.get(&id).cloned()),
        events: events
            .into_iter()
            .map(|event| Event {
                created_at: event.created_at,
                kind: EventKind::parse(&event.kind),
                actor: event.actor_user_id.and_then(|id| names.get(&id).cloned()),
                reason: event.reason,
                run_id: event.run_id,
            })
            .collect(),
        affected_components,
        dependency_paths,
        finding: {
            let facts = VulnerabilityFacts {
                aliases: serde_json::from_str(&vulnerability.aliases).unwrap_or_default(),
                summary: vulnerability.summary.clone(),
                cvss_score: vulnerability.cvss_score,
            };
            let mut view = view(finding, project.slug, Some(&facts));
            view.introduced_via = graph.introduced_via(&view.purl);
            view.exploitation = exploitation::for_cves(
                database,
                &exploitation::cve_ids(&view.vulnerability_id, &view.aliases),
            )
            .await?;
            view
        },
    })
}

async fn triaged_finding(
    database: &impl ConnectionTrait,
    actor: &Actor,
    finding_id: i64,
) -> Result<findings::Model> {
    let finding = findings::Entity::find_by_id(finding_id)
        .one(database)
        .await?
        .ok_or(Error::NotFound)?;
    crate::projects::authorize(
        database,
        actor,
        finding.project_id,
        Permission::TriageFindings,
    )
    .await?;
    Ok(finding)
}

/// Ignores an open finding, with a mandatory reason (at most 2000 characters) and an optional
/// expiry in the future. Requires [`Permission::TriageFindings`]. The finding returns to open
/// at the first run after the expiry, not at the expiry itself; ignoring a finding that is not
/// open is a [`Problem::OnlyOpenCanBeIgnored`] conflict.
pub async fn ignore(
    database: &(impl ConnectionTrait + TransactionTrait),
    actor: &Actor,
    finding_id: i64,
    reason: &str,
    expires_at: Option<DateTime<FixedOffset>>,
) -> Result<()> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(Error::invalid(Problem::ReasonRequired));
    }
    if reason.chars().count() > 2000 {
        return Err(Error::invalid(Problem::ReasonTooLong { maximum: 2000 }));
    }
    if expires_at.is_some_and(|expiry| expiry <= Utc::now()) {
        return Err(Error::invalid(Problem::ExpiryNotInFuture));
    }
    let transaction = crate::database::begin_write(database).await?;
    let finding = triaged_finding(&transaction, actor, finding_id).await?;
    if Status::parse(&finding.status) != Status::Open {
        return Err(Error::conflict(Problem::OnlyOpenCanBeIgnored));
    }
    let mut active: findings::ActiveModel = finding.into();
    active.status = Set(Status::Ignored.as_str().to_owned());
    active.ignore_reason = Set(Some(reason.to_owned()));
    active.ignore_expires_at = Set(expires_at);
    active.ignored_by_user_id = Set(Some(actor.user_id));
    active.ignored_at = Set(Some(Utc::now().fixed_offset()));
    active.update(&transaction).await?;
    record_event(
        &transaction,
        finding_id,
        EventKind::Ignored,
        Some(actor.user_id),
        Some(reason.to_owned()),
        None,
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

/// Returns an ignored finding to open. Requires [`Permission::TriageFindings`].
pub async fn restore(
    database: &(impl ConnectionTrait + TransactionTrait),
    actor: &Actor,
    finding_id: i64,
) -> Result<()> {
    let transaction = crate::database::begin_write(database).await?;
    let finding = triaged_finding(&transaction, actor, finding_id).await?;
    if Status::parse(&finding.status) != Status::Ignored {
        return Err(Error::conflict(Problem::OnlyIgnoredCanBeRestored));
    }
    let mut active: findings::ActiveModel = finding.into();
    active.status = Set(Status::Open.as_str().to_owned());
    active.update(&transaction).await?;
    record_event(
        &transaction,
        finding_id,
        EventKind::Restored,
        Some(actor.user_id),
        None,
        None,
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

/// Open findings by severity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub unknown: u64,
}

impl SeverityCounts {
    pub fn add(&mut self, severity: Severity) {
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Unknown => self.unknown += 1,
        }
    }

    pub fn get(&self, severity: Severity) -> u64 {
        match severity {
            Severity::Critical => self.critical,
            Severity::High => self.high,
            Severity::Medium => self.medium,
            Severity::Low => self.low,
            Severity::Unknown => self.unknown,
        }
    }

    pub fn total(&self) -> u64 {
        self.critical + self.high + self.medium + self.low + self.unknown
    }
}

/// A project with its open findings, for the organization page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectOverview {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub last_upload_at: Option<DateTime<FixedOffset>>,
    pub open: SeverityCounts,
    pub ignored: u64,
    /// Open findings with a known exploited CVE.
    pub known_exploited: i64,
    /// No SBOM received for longer than the stale threshold.
    pub stale: bool,
}

/// The projects of an organization with their open findings by severity; `stale_after_days`
/// is the stale threshold (0: never stale).
pub async fn overview(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
    stale_after_days: u32,
) -> Result<Vec<ProjectOverview>> {
    let now = chrono::Utc::now().fixed_offset();
    let projects = crate::projects::list(database, actor, organization_id).await?;
    let mut overviews: Vec<ProjectOverview> = projects
        .iter()
        .map(|project| ProjectOverview {
            id: project.id,
            slug: project.slug.clone(),
            name: project.name.clone(),
            last_upload_at: project.last_upload_at,
            open: SeverityCounts::default(),
            ignored: 0,
            known_exploited: 0,
            stale: crate::staleness::is_stale(
                project.created_at,
                project.last_upload_at,
                now,
                stale_after_days,
            ),
        })
        .collect();
    let index: HashMap<i64, usize> = overviews
        .iter()
        .enumerate()
        .map(|(position, project)| (project.id, position))
        .collect();
    let identifiers: Vec<i64> = projects.iter().map(|project| project.id).collect();
    for chunk in identifiers.chunks(QUERY_CHUNK) {
        let rows = findings::Entity::find()
            .filter(findings::Column::ProjectId.is_in(chunk.iter().copied()))
            .filter(findings::Column::Status.ne(Status::Fixed.as_str()))
            .all(database)
            .await?;
        let facts = vulnerability_facts(
            database,
            rows.iter().map(|finding| finding.vulnerability_id.as_str()),
        )
        .await?;
        let keys: Vec<(i64, Vec<String>)> = rows
            .iter()
            .map(|finding| {
                let aliases = facts
                    .get(&finding.vulnerability_id)
                    .map_or(&[][..], |facts| facts.aliases.as_slice());
                (
                    finding.id,
                    exploitation::cve_ids(&finding.vulnerability_id, aliases),
                )
            })
            .collect();
        let exploitations = exploitation::for_findings(database, &keys).await?;
        for finding in rows {
            let overview = &mut overviews[index[&finding.project_id]];
            match Status::parse(&finding.status) {
                Status::Ignored => overview.ignored += 1,
                _ => {
                    overview
                        .open
                        .add(finding.severity.parse().unwrap_or(Severity::Unknown));
                    if exploitations
                        .get(&finding.id)
                        .is_some_and(|value| value.known_exploited)
                    {
                        overview.known_exploited += 1;
                    }
                }
            }
        }
    }
    Ok(overviews)
}

/// Open findings by severity across the whole instance, for metrics.
pub async fn open_counts(database: &impl ConnectionTrait) -> Result<SeverityCounts> {
    let mut counts = SeverityCounts::default();
    for finding in findings::Entity::find()
        .filter(findings::Column::Status.eq(Status::Open.as_str()))
        .all(database)
        .await?
    {
        counts.add(finding.severity.parse().unwrap_or(Severity::Unknown));
    }
    Ok(counts)
}
