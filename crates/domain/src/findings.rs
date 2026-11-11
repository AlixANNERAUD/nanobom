//! Findings: a vulnerability affecting a component of a project, with its lifecycle (open,
//! fixed, ignored) and the full history of what happened to it.
//!
//! A finding is identified by its project version ([`crate::versions`]), its package URL and
//! its vulnerability identifier, and is never deleted while its version exists: a fixed
//! finding that comes back is reopened, keeping its history. Runs ([`crate::evaluation`]) open, fix and reopen findings; members
//! only ignore and restore them ([`ignore`], [`restore`]). Every status change appends an
//! [`Event`] in the same transaction:
//!
//! - a run reports it: opened;
//! - open or ignored, a run no longer reports it: fixed;
//! - fixed, a run reports it again: reopened (open);
//! - open, a member ignores it, or an upload token imports a VEX statement saying it does not
//!   apply ([`crate::vex`]): ignored;
//! - ignored, a member restores it or the first run after its expiry comes: open.
//!
//! An ignore always has a free-text reason, and may have a machine-readable [`Justification`]
//! (the CycloneDX impact analysis vocabulary), which VEX exports carry.
//!
//! Listings carry the [`Exploitation`] signals of each finding, and order by them: known
//! exploited first, then by severity, then by EPSS. The severity stored on a finding is the
//! highest among its aliases at the last run that reported it.

use std::{collections::HashMap, str::FromStr};

use chrono::{DateTime, FixedOffset, Utc};
use nanobom_entity::{
    components, finding_events, findings, organizations, project_versions, projects, upload_tokens,
    users, vulnerabilities,
};
use nanobom_osv::{Severity, Vulnerability, schema::Reference};
use packageurl::PackageUrl;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect, TransactionSession, TransactionTrait,
};
use serde::{Deserialize, Serialize};

use crate::{
    access::{Actor, Permission, Reader},
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

/// Why a finding does not affect the product, in machine-readable form: the CycloneDX impact
/// analysis justifications, plus the `false_positive` state, which takes no justification in
/// CycloneDX but is the other way to say a vulnerability does not apply. Stored as their
/// CycloneDX names in `findings.ignore_justification` and `finding_events.justification`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Justification {
    /// The vulnerable code was removed or tree-shaken.
    CodeNotPresent,
    /// The vulnerable code is not invoked at runtime.
    CodeNotReachable,
    /// Exploitation requires a configuration option that is not set (or unset).
    RequiresConfiguration,
    /// Exploitation requires a dependency that is not present.
    RequiresDependency,
    /// Exploitation requires an environment that is not present.
    RequiresEnvironment,
    /// Exploitation requires a compiler flag that is not set (or unset).
    ProtectedByCompiler,
    /// Exploits are prevented at runtime.
    ProtectedAtRuntime,
    /// Attacks are blocked at the physical, logical or network perimeter.
    ProtectedAtPerimeter,
    /// Preventive measures reduce the likelihood or impact of the vulnerability.
    ProtectedByMitigatingControl,
    /// The vulnerability was wrongly associated with the component.
    FalsePositive,
}

impl Justification {
    /// Every justification, in the order of the CycloneDX specification, then
    /// [`Justification::FalsePositive`].
    pub const ALL: [Justification; 10] = [
        Justification::CodeNotPresent,
        Justification::CodeNotReachable,
        Justification::RequiresConfiguration,
        Justification::RequiresDependency,
        Justification::RequiresEnvironment,
        Justification::ProtectedByCompiler,
        Justification::ProtectedAtRuntime,
        Justification::ProtectedAtPerimeter,
        Justification::ProtectedByMitigatingControl,
        Justification::FalsePositive,
    ];

    /// The CycloneDX name, also the stored value.
    pub fn as_str(self) -> &'static str {
        match self {
            Justification::CodeNotPresent => "code_not_present",
            Justification::CodeNotReachable => "code_not_reachable",
            Justification::RequiresConfiguration => "requires_configuration",
            Justification::RequiresDependency => "requires_dependency",
            Justification::RequiresEnvironment => "requires_environment",
            Justification::ProtectedByCompiler => "protected_by_compiler",
            Justification::ProtectedAtRuntime => "protected_at_runtime",
            Justification::ProtectedAtPerimeter => "protected_at_perimeter",
            Justification::ProtectedByMitigatingControl => "protected_by_mitigating_control",
            Justification::FalsePositive => "false_positive",
        }
    }

    /// Parses a CycloneDX name; anything else is [`Problem::UnknownJustification`].
    pub fn parse(value: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|justification| justification.as_str() == value)
            .ok_or_else(|| {
                Error::invalid(Problem::UnknownJustification {
                    justification: value.to_owned(),
                })
            })
    }

    /// Reads a stored value; an unknown one (never written) reads as none.
    pub(crate) fn from_column(value: Option<&str>) -> Option<Self> {
        value.and_then(|value| Self::parse(value).ok())
    }
}

/// What happened to a finding. Run events carry the run; member events carry the member, or
/// the upload token for ignores imported from a VEX document.
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
    /// Copied, with its status and ignore, from the latest version when an upload created the
    /// finding's version; the reason holds the name of the version it was copied from (empty
    /// for the unnamed version).
    Inherited,
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
            EventKind::Inherited => "inherited",
        }
    }

    fn parse(value: &str) -> Self {
        match value {
            "fixed" => EventKind::Fixed,
            "reopened" => EventKind::Reopened,
            "ignored" => EventKind::Ignored,
            "restored" => EventKind::Restored,
            "ignore_expired" => EventKind::IgnoreExpired,
            "inherited" => EventKind::Inherited,
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
    /// The name of the project version the finding belongs to; empty for the unnamed version.
    pub version: String,
    pub purl: String,
    pub ecosystem: String,
    pub component_name: String,
    pub component_version: Option<String>,
    /// The component's license per the latest SBOM; `None` when it does not give one, or when
    /// the component is no longer in the project.
    pub license: Option<String>,
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
    /// Like `ignore_reason`, meaningful only while the finding is ignored.
    pub ignore_justification: Option<Justification>,
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
    version: String,
    vulnerability: Option<&VulnerabilityFacts>,
) -> Finding {
    let (component_name, component_version) = component_name_and_version(&finding.purl);
    Finding {
        id: finding.id,
        project_id: finding.project_id,
        project_slug,
        version,
        component_name,
        component_version,
        license: None,
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
        ignore_justification: Justification::from_column(finding.ignore_justification.as_deref()),
        ignore_reason: finding.ignore_reason,
        ignore_expires_at: finding.ignore_expires_at,
        exploitation: Exploitation::default(),
        introduced_via: Vec::new(),
    }
}

/// The findings of a project's latest version: known exploited first, then most severe first,
/// then by EPSS score (findings without one last). Requires [`Permission::View`].
pub async fn list(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    project_id: i64,
    filter: &Filter,
) -> Result<Vec<Finding>> {
    list_in_version(database, reader, project_id, None, filter).await
}

/// Like [`list`], for the version named `version` (`None`: the latest); a missing version is
/// [`Error::NotFound`].
pub async fn list_in_version(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    project_id: i64,
    version: Option<&str>,
    filter: &Filter,
) -> Result<Vec<Finding>> {
    let project =
        crate::projects::authorize(database, reader, project_id, Permission::View).await?;
    let version = crate::versions::select(database, project_id, version).await?;
    version_findings(database, project, &version, filter).await
}

/// The open findings of a project version an upload token covers, most severe first (then as
/// `list` orders them), for the evaluation returned to CI after an upload: the gate judges the
/// version uploaded, not the others. A project outside the token is [`Error::NotFound`].
pub async fn open_for_upload_token(
    database: &impl ConnectionTrait,
    token: &upload_tokens::Model,
    project_id: i64,
    version: &str,
) -> Result<Vec<Finding>> {
    let filter = Filter {
        statuses: vec![Status::Open],
        ..Filter::default()
    };
    let mut findings = list_in_version(database, token, project_id, Some(version), &filter).await?;
    // Stable: findings of the same severity keep the order of `list`.
    findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));
    Ok(findings)
}

/// The findings of a version of a project, without authorization: known exploited first, then
/// most severe first, then by EPSS score (findings without one last), then by CVSS score,
/// component and vulnerability.
async fn version_findings(
    database: &impl ConnectionTrait,
    project: projects::Model,
    version: &project_versions::Model,
    filter: &Filter,
) -> Result<Vec<Finding>> {
    let version_id = version.id;
    let mut query = findings::Entity::find().filter(findings::Column::VersionId.eq(version_id));
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
            view(
                finding,
                project.slug.clone(),
                version.name.clone(),
                vulnerability,
            )
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
    let (graph, licenses) = if findings.is_empty() {
        (Graph::default(), HashMap::new())
    } else {
        (
            Graph::load(database, version_id).await?,
            licenses(database, version_id, None).await?,
        )
    };
    for finding in &mut findings {
        finding.exploitation = exploitations.remove(&finding.id).unwrap_or_default();
        finding.introduced_via = graph.introduced_via(&finding.purl);
        // Not `remove`: a component with several vulnerabilities has one finding for each.
        finding.license = licenses.get(&finding.purl).cloned();
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

/// The licenses of a version's components, by package URL, of every component or of the one
/// `purl` names; components without a license are left out.
async fn licenses(
    database: &impl ConnectionTrait,
    version_id: i64,
    purl: Option<&str>,
) -> Result<HashMap<String, String>> {
    let mut query = components::Entity::find()
        .select_only()
        .column(components::Column::Purl)
        .column(components::Column::License)
        .filter(components::Column::VersionId.eq(version_id))
        .filter(components::Column::License.is_not_null());
    if let Some(purl) = purl {
        query = query.filter(components::Column::Purl.eq(purl));
    }
    Ok(query
        .into_tuple::<(String, String)>()
        .all(database)
        .await?
        .into_iter()
        .collect())
}

/// The ecosystems present among the findings of a project's latest version, for filters.
/// Requires [`Permission::View`].
pub async fn ecosystems(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    project_id: i64,
) -> Result<Vec<String>> {
    ecosystems_in_version(database, reader, project_id, None).await
}

/// Like [`ecosystems`], for the version named `version` (`None`: the latest).
pub async fn ecosystems_in_version(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    project_id: i64,
    version: Option<&str>,
) -> Result<Vec<String>> {
    let version = crate::versions::find(database, reader, project_id, version).await?;
    let mut ecosystems: Vec<String> = findings::Entity::find()
        .filter(findings::Column::VersionId.eq(version.id))
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
    /// The member's username.
    pub actor: Option<String>,
    /// The name of the upload token that imported a VEX statement.
    pub token: Option<String>,
    pub reason: Option<String>,
    pub justification: Option<Justification>,
    pub run_id: Option<i64>,
}

/// Another component affected by the same vulnerability, in an active version of a project the
/// reader can see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffectedComponent {
    pub finding_id: i64,
    pub organization_slug: String,
    pub project_slug: String,
    /// The project version the component is in; empty for the unnamed version.
    pub version: String,
    pub purl: String,
    pub status: Status,
}

/// Where a version of a project stands with a vulnerability, as [`VersionFinding`] reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionStatus {
    /// A finding of the version is open.
    Open,
    /// None is open, one is ignored.
    Ignored,
    /// Every finding of the version is fixed.
    Fixed,
    /// The version never had a finding for the vulnerability.
    NotAffected,
}

impl VersionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            VersionStatus::Open => "open",
            VersionStatus::Ignored => "ignored",
            VersionStatus::Fixed => "fixed",
            VersionStatus::NotAffected => "not_affected",
        }
    }

    /// The finding statuses in the order they decide a version's: an open finding outweighs an
    /// ignored one, which outweighs a fixed one.
    fn rank(status: Status) -> u8 {
        match status {
            Status::Open => 0,
            Status::Ignored => 1,
            Status::Fixed => 2,
        }
    }
}

/// A version of a finding's project and where it stands with the finding's vulnerability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionFinding {
    /// Empty for the unnamed version.
    pub version: String,
    pub latest: bool,
    pub active: bool,
    /// The version of the finding itself.
    pub current: bool,
    pub status: VersionStatus,
    /// The version's finding that decides its status, the one of the same component when there
    /// is one; `None` when the version is not affected.
    pub finding_id: Option<i64>,
}

pub(crate) async fn token_names(
    database: &impl ConnectionTrait,
    identifiers: impl Iterator<Item = i64>,
) -> Result<HashMap<i64, String>> {
    let identifiers: Vec<i64> = identifiers.collect();
    if identifiers.is_empty() {
        return Ok(HashMap::new());
    }
    Ok(upload_tokens::Entity::find()
        .filter(upload_tokens::Column::Id.is_in(identifiers))
        .all(database)
        .await?
        .into_iter()
        .map(|token| (token.id, token.name))
        .collect())
}

/// Everything about a finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingDetail {
    pub finding: Finding,
    pub organization_slug: String,
    /// Whether the reader may ignore or restore this finding (never for a token).
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
    /// The name of the upload token that ignored the finding from a VEX document.
    pub ignored_by_token: Option<String>,
    pub affected_components: Vec<AffectedComponent>,
    /// Every version of the project, newest first, with its status for the vulnerability (or
    /// any of its aliases).
    pub versions: Vec<VersionFinding>,
    pub events: Vec<Event>,
    /// How the project pulls in the component; `None` when its latest SBOM did not say which
    /// components the project depends on directly.
    pub dependency_paths: Option<DependencyPaths>,
}

pub(crate) async fn usernames(
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
/// [`Permission::View`]. The other affected components are limited to the projects the reader
/// can see, so the page never reveals that another organization uses a package.
pub async fn detail(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    finding_id: i64,
) -> Result<FindingDetail> {
    let reader = reader.into();
    let finding = findings::Entity::find_by_id(finding_id)
        .one(database)
        .await?
        .ok_or(Error::NotFound)?;
    let project =
        crate::projects::authorize(database, reader, finding.project_id, Permission::View).await?;
    let role = reader
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
    let version_id = finding.version_id;
    let version_name = match version_id {
        Some(version_id) => project_versions::Entity::find_by_id(version_id)
            .one(database)
            .await?
            .map(|version| version.name)
            .unwrap_or_default(),
        None => String::new(),
    };
    // The finding's own version, whichever is latest: its page describes that version.
    let graph = match version_id {
        Some(version_id) => Graph::load(database, version_id).await?,
        None => Graph::default(),
    };
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
    let tokens = token_names(
        database,
        events
            .iter()
            .filter_map(|event| event.upload_token_id)
            .chain(finding.ignored_by_upload_token_id),
    )
    .await?;

    let visible = crate::organizations::list(database, reader)
        .await?
        .into_iter()
        .map(|organization| (organization.id, organization.slug))
        .collect::<HashMap<_, _>>();
    let mut affected = Vec::new();
    for (other, other_project) in findings::Entity::find()
        .filter(findings::Column::VulnerabilityId.eq(finding.vulnerability_id.clone()))
        .filter(findings::Column::Id.ne(finding.id))
        .filter(findings::Column::VersionId.in_subquery(crate::versions::active_ids()))
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
        if !reader.reaches_project(other_project.id) {
            continue;
        }
        affected.push((other, organization_slug.clone(), other_project.slug));
    }
    let affected_versions = version_names(
        database,
        affected.iter().filter_map(|(other, _, _)| other.version_id),
    )
    .await?;
    let mut affected_components: Vec<AffectedComponent> = affected
        .into_iter()
        .map(
            |(other, organization_slug, project_slug)| AffectedComponent {
                finding_id: other.id,
                organization_slug,
                project_slug,
                version: other
                    .version_id
                    .and_then(|id| affected_versions.get(&id).cloned())
                    .unwrap_or_default(),
                purl: other.purl,
                status: Status::parse(&other.status),
            },
        )
        .collect();
    affected_components.sort_by(|left, right| {
        (
            &left.organization_slug,
            &left.project_slug,
            &left.version,
            &left.purl,
        )
            .cmp(&(
                &right.organization_slug,
                &right.project_slug,
                &right.version,
                &right.purl,
            ))
    });
    let aliases: Vec<String> = serde_json::from_str(&vulnerability.aliases).unwrap_or_default();
    let versions = across_versions(database, &finding, &aliases).await?;

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
        ignored_by_token: finding
            .ignored_by_upload_token_id
            .and_then(|id| tokens.get(&id).cloned()),
        events: events
            .into_iter()
            .map(|event| Event {
                created_at: event.created_at,
                kind: EventKind::parse(&event.kind),
                actor: event.actor_user_id.and_then(|id| names.get(&id).cloned()),
                token: event
                    .upload_token_id
                    .and_then(|id| tokens.get(&id).cloned()),
                justification: Justification::from_column(event.justification.as_deref()),
                reason: event.reason,
                run_id: event.run_id,
            })
            .collect(),
        affected_components,
        versions,
        dependency_paths,
        finding: {
            let facts = VulnerabilityFacts {
                aliases,
                summary: vulnerability.summary.clone(),
                cvss_score: vulnerability.cvss_score,
            };
            let mut view = view(finding, project.slug, version_name, Some(&facts));
            view.introduced_via = graph.introduced_via(&view.purl);
            if let Some(version_id) = version_id {
                view.license = licenses(database, version_id, Some(&view.purl))
                    .await?
                    .remove(&view.purl);
            }
            view.exploitation = exploitation::for_cves(
                database,
                &exploitation::cve_ids(&view.vulnerability_id, &view.aliases),
            )
            .await?;
            view
        },
    })
}

/// The names of these versions, by identifier.
async fn version_names(
    database: &impl ConnectionTrait,
    identifiers: impl Iterator<Item = i64>,
) -> Result<HashMap<i64, String>> {
    let identifiers: Vec<i64> = identifiers
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut names = HashMap::with_capacity(identifiers.len());
    for chunk in identifiers.chunks(QUERY_CHUNK) {
        let rows: Vec<(i64, String)> = project_versions::Entity::find()
            .select_only()
            .column(project_versions::Column::Id)
            .column(project_versions::Column::Name)
            .filter(project_versions::Column::Id.is_in(chunk.iter().copied()))
            .into_tuple()
            .all(database)
            .await?;
        names.extend(rows);
    }
    Ok(names)
}

/// Every version of a finding's project with its status for the finding's vulnerability, for
/// comparing releases. A version's findings filed under an alias count too (OSV often lists one
/// issue under a GHSA and a CVE, and which identifier a version's finding carries depends on
/// what OSV reported when it was opened): identifiers match when they or their aliases meet,
/// ignoring case, as for VEX statements ([`crate::vex`]).
///
/// The project's distinct vulnerabilities are read through the index on findings'
/// `(project_id, vulnerability_id)`; only the matching findings are then loaded.
async fn across_versions(
    database: &impl ConnectionTrait,
    finding: &findings::Model,
    aliases: &[String],
) -> Result<Vec<VersionFinding>> {
    let wanted: std::collections::HashSet<String> = std::iter::once(&finding.vulnerability_id)
        .chain(aliases)
        .map(|identifier| identifier.to_uppercase())
        .collect();
    let identifiers: Vec<String> = findings::Entity::find()
        .select_only()
        .column(findings::Column::VulnerabilityId)
        .distinct()
        .filter(findings::Column::ProjectId.eq(finding.project_id))
        .order_by_asc(findings::Column::VulnerabilityId)
        .into_tuple()
        .all(database)
        .await?;
    let facts = vulnerability_facts(database, identifiers.iter().map(String::as_str)).await?;
    let matching: Vec<String> = identifiers
        .into_iter()
        .filter(|identifier| {
            let its_aliases = facts
                .get(identifier)
                .map_or(&[][..], |facts| facts.aliases.as_slice());
            std::iter::once(identifier)
                .chain(its_aliases)
                .any(|name| wanted.contains(&name.to_uppercase()))
        })
        .collect();
    let mut related: Vec<findings::Model> = Vec::new();
    for chunk in matching.chunks(QUERY_CHUNK) {
        related.extend(
            findings::Entity::find()
                .filter(findings::Column::ProjectId.eq(finding.project_id))
                .filter(findings::Column::VulnerabilityId.is_in(chunk.iter().cloned()))
                .order_by_asc(findings::Column::Id)
                .all(database)
                .await?,
        );
    }
    let mut by_version: HashMap<i64, Vec<findings::Model>> = HashMap::new();
    for other in related {
        if let Some(version_id) = other.version_id {
            by_version.entry(version_id).or_default().push(other);
        }
    }
    let versions = project_versions::Entity::find()
        .filter(project_versions::Column::ProjectId.eq(finding.project_id))
        .order_by_desc(project_versions::Column::CreatedAt)
        .order_by_desc(project_versions::Column::Id)
        .all(database)
        .await?;
    Ok(versions
        .into_iter()
        .map(|version| {
            // Ordered by identifier, so among equals the oldest finding decides.
            let deciding = by_version.get(&version.id).and_then(|candidates| {
                candidates.iter().min_by_key(|candidate| {
                    (
                        VersionStatus::rank(Status::parse(&candidate.status)),
                        candidate.purl != finding.purl,
                        candidate.id,
                    )
                })
            });
            VersionFinding {
                current: Some(version.id) == finding.version_id,
                version: version.name,
                latest: version.latest,
                active: version.active,
                status: match deciding.map(|candidate| Status::parse(&candidate.status)) {
                    Some(Status::Open) => VersionStatus::Open,
                    Some(Status::Ignored) => VersionStatus::Ignored,
                    Some(Status::Fixed) => VersionStatus::Fixed,
                    None => VersionStatus::NotAffected,
                },
                finding_id: deciding.map(|candidate| candidate.id),
            }
        })
        .collect())
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

/// The longest ignore reason, in characters.
pub const MAXIMUM_REASON_LENGTH: usize = 2000;

/// Checks an ignore reason and returns it trimmed.
fn ignore_reason(reason: &str) -> Result<&str> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(Error::invalid(Problem::ReasonRequired));
    }
    if reason.chars().count() > MAXIMUM_REASON_LENGTH {
        return Err(Error::invalid(Problem::ReasonTooLong {
            maximum: MAXIMUM_REASON_LENGTH,
        }));
    }
    Ok(reason)
}

/// Who ignores a finding.
#[derive(Debug, Clone, Copy)]
pub(crate) enum IgnoredBy {
    Member(i64),
    UploadToken(i64),
}

/// Marks an open finding ignored and records the event, inside the caller's transaction. The
/// reason is already checked.
pub(crate) async fn mark_ignored(
    transaction: &impl ConnectionTrait,
    finding: findings::Model,
    by: IgnoredBy,
    reason: &str,
    justification: Option<Justification>,
    expires_at: Option<DateTime<FixedOffset>>,
) -> Result<()> {
    let finding_id = finding.id;
    let (user, token) = match by {
        IgnoredBy::Member(user) => (Some(user), None),
        IgnoredBy::UploadToken(token) => (None, Some(token)),
    };
    let now = Utc::now().fixed_offset();
    let mut active: findings::ActiveModel = finding.into();
    active.status = Set(Status::Ignored.as_str().to_owned());
    active.ignore_reason = Set(Some(reason.to_owned()));
    active.ignore_justification = Set(justification.map(|value| value.as_str().to_owned()));
    active.ignore_expires_at = Set(expires_at);
    active.ignored_by_user_id = Set(user);
    active.ignored_by_upload_token_id = Set(token);
    active.ignored_at = Set(Some(now));
    active.update(transaction).await?;
    finding_events::ActiveModel {
        finding_id: Set(finding_id),
        created_at: Set(now),
        kind: Set(EventKind::Ignored.as_str().to_owned()),
        actor_user_id: Set(user),
        upload_token_id: Set(token),
        reason: Set(Some(reason.to_owned())),
        justification: Set(justification.map(|value| value.as_str().to_owned())),
        run_id: Set(None),
        ..Default::default()
    }
    .insert(transaction)
    .await?;
    Ok(())
}

/// Ignores an open finding, with a mandatory reason (at most [`MAXIMUM_REASON_LENGTH`]
/// characters), an optional machine-readable justification and an optional expiry in the
/// future. Requires [`Permission::TriageFindings`]. The finding returns to open at the first
/// run after the expiry, not at the expiry itself; ignoring a finding that is not open is a
/// [`Problem::OnlyOpenCanBeIgnored`] conflict.
pub async fn ignore(
    database: &(impl ConnectionTrait + TransactionTrait),
    actor: &Actor,
    finding_id: i64,
    reason: &str,
    justification: Option<Justification>,
    expires_at: Option<DateTime<FixedOffset>>,
) -> Result<()> {
    let reason = ignore_reason(reason)?;
    if expires_at.is_some_and(|expiry| expiry <= Utc::now()) {
        return Err(Error::invalid(Problem::ExpiryNotInFuture));
    }
    let transaction = crate::database::begin_write(database).await?;
    let finding = triaged_finding(&transaction, actor, finding_id).await?;
    if Status::parse(&finding.status) != Status::Open {
        return Err(Error::conflict(Problem::OnlyOpenCanBeIgnored));
    }
    mark_ignored(
        &transaction,
        finding,
        IgnoredBy::Member(actor.user_id),
        reason,
        justification,
        expires_at,
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

/// The open findings of a project version, for the summary of the project page.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenSummary {
    pub counts: SeverityCounts,
    /// Open findings with a known exploited CVE.
    pub known_exploited: i64,
}

/// The open findings of the version named `version` (`None`: the latest) of a project, by
/// severity, and how many of them are known exploited. Requires [`Permission::View`]; a missing
/// version is [`Error::NotFound`].
///
/// Unlike [`overview`], which merges the versions of a project, each finding of the version
/// counts once, so the counts are those of [`list_in_version`] restricted to open findings.
pub async fn open_summary_in_version(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    project_id: i64,
    version: Option<&str>,
) -> Result<OpenSummary> {
    let version = crate::versions::find(database, reader, project_id, version).await?;
    open_summary_of(database, version.id).await
}

/// The open findings of a version, without authorization: [`open_summary_in_version`] and the
/// public badge ([`crate::badges::summary`]) count them the same way.
pub(crate) async fn open_summary_of(
    database: &impl ConnectionTrait,
    version_id: i64,
) -> Result<OpenSummary> {
    let rows: Vec<(i64, String, String)> = findings::Entity::find()
        .select_only()
        .column(findings::Column::Id)
        .column(findings::Column::VulnerabilityId)
        .column(findings::Column::Severity)
        .filter(findings::Column::VersionId.eq(version_id))
        .filter(findings::Column::Status.eq(Status::Open.as_str()))
        .into_tuple()
        .all(database)
        .await?;
    let facts = vulnerability_facts(
        database,
        rows.iter()
            .map(|(_, vulnerability, _)| vulnerability.as_str()),
    )
    .await?;
    let keys: Vec<(i64, Vec<String>)> = rows
        .iter()
        .map(|(id, vulnerability, _)| {
            let aliases = facts
                .get(vulnerability)
                .map_or(&[][..], |facts| facts.aliases.as_slice());
            (*id, exploitation::cve_ids(vulnerability, aliases))
        })
        .collect();
    let exploitations = exploitation::for_findings(database, &keys).await?;
    let mut summary = OpenSummary::default();
    for (id, _, severity) in rows {
        summary
            .counts
            .add(severity.parse().unwrap_or(Severity::Unknown));
        if exploitations
            .get(&id)
            .is_some_and(|exploitation| exploitation.known_exploited)
        {
            summary.known_exploited += 1;
        }
    }
    Ok(summary)
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

/// A vulnerability of a package across the active versions of a project, for [`overview`].
#[derive(Default)]
struct Issue {
    /// The highest severity among the versions where it is open.
    open: Option<Severity>,
    known_exploited: bool,
    ignored: bool,
}

/// The projects of an organization with the open issues of their active versions by severity:
/// a vulnerability of a package counts once however many versions have it, at its highest
/// severity. `stale_after_days` is the stale threshold (0: never stale).
pub async fn overview(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    organization_id: i64,
    stale_after_days: u32,
) -> Result<Vec<ProjectOverview>> {
    let now = chrono::Utc::now().fixed_offset();
    let projects = crate::projects::list(database, reader, organization_id).await?;
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
    // A vulnerability of a package found in several versions is one issue to fix, counted once
    // at its highest severity: open when it is open in any version, ignored when ignored in
    // every version that has it open or ignored.
    let mut issues: HashMap<(i64, String, String, String), Issue> = HashMap::new();
    for chunk in identifiers.chunks(QUERY_CHUNK) {
        let rows = findings::Entity::find()
            .filter(findings::Column::ProjectId.is_in(chunk.iter().copied()))
            .filter(findings::Column::VersionId.in_subquery(crate::versions::active_ids()))
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
            let known_exploited = exploitations
                .get(&finding.id)
                .is_some_and(|value| value.known_exploited);
            let (package, _) = component_name_and_version(&finding.purl);
            let issue = issues
                .entry((
                    finding.project_id,
                    finding.vulnerability_id,
                    finding.ecosystem,
                    package,
                ))
                .or_default();
            match Status::parse(&finding.status) {
                Status::Ignored => issue.ignored = true,
                _ => {
                    let severity = finding.severity.parse().unwrap_or(Severity::Unknown);
                    issue.open = Some(issue.open.map_or(severity, |open| open.max(severity)));
                    issue.known_exploited |= known_exploited;
                }
            }
        }
    }
    for ((project_id, ..), issue) in issues {
        let overview = &mut overviews[index[&project_id]];
        match issue.open {
            Some(severity) => {
                overview.open.add(severity);
                if issue.known_exploited {
                    overview.known_exploited += 1;
                }
            }
            None if issue.ignored => overview.ignored += 1,
            None => {}
        }
    }
    Ok(overviews)
}

/// Open findings of active versions by severity across the whole instance, for metrics.
pub async fn open_counts(database: &impl ConnectionTrait) -> Result<SeverityCounts> {
    let mut counts = SeverityCounts::default();
    for finding in findings::Entity::find()
        .filter(findings::Column::Status.eq(Status::Open.as_str()))
        .filter(findings::Column::VersionId.in_subquery(crate::versions::active_ids()))
        .all(database)
        .await?
    {
        counts.add(finding.severity.parse().unwrap_or(Severity::Unknown));
    }
    Ok(counts)
}
