//! The vulnerability report of a project version: what a vendor hands to a customer, an auditor
//! or a regulator, rendered by the interface as a printable page and by the server for tokens.
//!
//! [`build`] gathers, for one version, what the project page shows across its sections: where
//! the data comes from (the upload, the last successful run, the freshness of KEV and EPSS),
//! the open findings in the project page's order, the ignored findings with their reason,
//! justification and who ignored them (as the finding page shows them), and the licenses. It
//! reads nothing a viewer of the project could not read.
//!
//! A project can hold thousands of findings and components, so the lists are bounded
//! ([`MAXIMUM_OPEN`], [`MAXIMUM_ASSESSED`], [`MAXIMUM_VIOLATIONS`], [`LICENSE_GROUPS`]) while
//! the counts cover everything. The findings come from one listing, and the fixed versions,
//! which need each advisory's OSV record, are read for the listed open findings only.

use std::collections::{BTreeSet, HashMap};

use chrono::{DateTime, Duration, FixedOffset, Utc};
use nanobom_entity::{findings as findings_entity, runs, sbom_uploads, vulnerabilities};
use nanobom_osv::Vulnerability;
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect,
};
use serde::{Deserialize, Serialize};

use crate::{
    access::Reader,
    error::Result,
    evaluation::Scope,
    exploitation::QUERY_CHUNK,
    findings::{Filter, Finding, SeverityCounts, Status},
    licenses::Violations,
};

/// Open findings listed at most; the others are counted.
pub const MAXIMUM_OPEN: usize = 500;
/// Ignored findings listed at most; the others are counted.
pub const MAXIMUM_ASSESSED: usize = 500;
/// License violations listed at most, when the organization has a policy.
pub const MAXIMUM_VIOLATIONS: usize = 200;
/// License expressions listed by count, when the organization has no policy; the others are
/// summed as "other".
pub const LICENSE_GROUPS: usize = 10;
/// The period of "fixed recently" in the summary.
pub const FIXED_RECENTLY_DAYS: i64 = 90;

/// The report of a project version, as of [`Report::generated_at`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub generated_at: DateTime<FixedOffset>,
    pub organization_slug: String,
    pub organization_name: String,
    pub project_slug: String,
    pub project_name: String,
    /// Empty for the unnamed version.
    pub version: String,
    pub latest: bool,
    /// An inactive version is no longer evaluated: its findings are those of its last run.
    pub active: bool,
    /// The latest upload of the version, which its components come from.
    pub upload: Option<Upload>,
    /// The version's components, as stored (those with a package URL).
    pub component_count: u64,
    /// The project received no SBOM for longer than the stale threshold, as the project page
    /// says.
    pub stale: bool,
    /// The project's last upload, any version.
    pub project_last_upload_at: Option<DateTime<FixedOffset>>,
    pub project_created_at: DateTime<FixedOffset>,
    /// The end of the last successful run that covered the project.
    pub last_evaluation: Option<DateTime<FixedOffset>>,
    /// When nanobom last read the CISA KEV catalog, for any CVE.
    pub kev_checked_at: Option<DateTime<FixedOffset>>,
    /// When nanobom last read FIRST EPSS scores, for any CVE.
    pub epss_checked_at: Option<DateTime<FixedOffset>>,
    pub summary: Summary,
    /// The open findings, known exploited first, as on the project page, at most
    /// [`MAXIMUM_OPEN`]; [`Summary::open`] counts them all.
    pub open: Vec<OpenFinding>,
    /// The ignored findings in the same order, at most [`MAXIMUM_ASSESSED`];
    /// [`Summary::ignored`] counts them all.
    pub assessed: Vec<AssessedFinding>,
    pub licenses: Licenses,
}

/// The upload a report is based on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upload {
    pub uploaded_at: DateTime<FixedOffset>,
    /// The CycloneDX or SPDX version of the document.
    pub specification_version: String,
    pub source_commit: Option<String>,
    pub image_tag: Option<String>,
    pub component_count: i64,
    /// Components of the SBOM without a package URL, which nanobom cannot check.
    pub components_without_purl: i64,
}

/// The counts of the summary, over every finding of the version.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub open: SeverityCounts,
    /// Open findings with a known exploited CVE.
    pub known_exploited: u64,
    pub ignored: u64,
    /// Findings fixed in the last [`FIXED_RECENTLY_DAYS`] days and still fixed.
    pub fixed_recently: u64,
}

/// An open finding with the versions of its package that fix it, per its OSV record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenFinding {
    pub finding: Finding,
    pub fixed_versions: Vec<String>,
}

/// An ignored finding with who ignored it and when, as the finding page shows it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssessedFinding {
    pub finding: Finding,
    pub ignored_at: Option<DateTime<FixedOffset>>,
    /// The member's username.
    pub ignored_by: Option<String>,
    /// The name of the upload token that imported a VEX statement.
    pub ignored_by_token: Option<String>,
}

/// The licenses of the version's components.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Licenses {
    /// The organization has an active policy: the components it forbids or warns about, at most
    /// [`MAXIMUM_VIOLATIONS`] of them, with the counts of all.
    Policy(Violations),
    /// Without a policy: the components by license expression.
    Counts(LicenseCounts),
}

/// Components by license expression, most common first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseCounts {
    /// At most [`LICENSE_GROUPS`] expressions with their count, most components first, then by
    /// expression.
    pub groups: Vec<(String, u64)>,
    /// Components of the other expressions.
    pub other: u64,
    /// Components whose SBOM entry gives no license.
    pub without: u64,
}

/// The report of the version named `version` (`None`: the latest) of a project. Requires
/// [`crate::access::Permission::View`]; a missing organization, project or version, or one
/// outside a token's reach, is [`crate::Error::NotFound`]. `stale_after_days` is the stale
/// threshold of the instance (0: never stale).
pub async fn build(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    organization_slug: &str,
    project_slug: &str,
    version: Option<&str>,
    stale_after_days: u32,
) -> Result<Report> {
    let reader = reader.into();
    let now = Utc::now().fixed_offset();
    let organization = crate::organizations::find(database, reader, organization_slug).await?;
    let project = crate::projects::find(database, reader, organization.id, project_slug).await?;
    let version = crate::versions::find(database, reader, project.id, version).await?;
    let findings = crate::findings::list_in_version(
        database,
        reader,
        project.id,
        Some(&version.name),
        &Filter {
            statuses: vec![Status::Open, Status::Ignored],
            ..Filter::default()
        },
    )
    .await?;

    let mut summary = Summary::default();
    let mut open = Vec::new();
    let mut ignored = Vec::new();
    for finding in findings {
        match finding.status {
            Status::Open => {
                summary.open.add(finding.severity);
                if finding.exploitation.known_exploited {
                    summary.known_exploited += 1;
                }
                if open.len() < MAXIMUM_OPEN {
                    open.push(finding);
                }
            }
            Status::Ignored => {
                summary.ignored += 1;
                if ignored.len() < MAXIMUM_ASSESSED {
                    ignored.push(finding);
                }
            }
            Status::Fixed => {}
        }
    }
    summary.fixed_recently = findings_entity::Entity::find()
        .filter(findings_entity::Column::VersionId.eq(version.id))
        .filter(findings_entity::Column::Status.eq(Status::Fixed.as_str()))
        .filter(findings_entity::Column::FixedAt.gte(now - Duration::days(FIXED_RECENTLY_DAYS)))
        .count(database)
        .await?;

    let fixed = fixed_versions(database, &open).await?;
    let open = open
        .into_iter()
        .map(|finding| OpenFinding {
            fixed_versions: fixed
                .get(&(
                    finding.vulnerability_id.clone(),
                    finding.component_name.clone(),
                ))
                .cloned()
                .unwrap_or_default(),
            finding,
        })
        .collect();
    let assessed = assessed(database, ignored).await?;

    let upload = sbom_uploads::Entity::find()
        .filter(sbom_uploads::Column::VersionId.eq(version.id))
        .order_by_desc(sbom_uploads::Column::UploadedAt)
        .order_by_desc(sbom_uploads::Column::Id)
        .one(database)
        .await?
        .map(|upload| Upload {
            uploaded_at: upload.uploaded_at,
            specification_version: upload.specification_version,
            source_commit: upload.source_commit,
            image_tag: upload.image_tag,
            component_count: upload.component_count,
            components_without_purl: upload.components_without_purl,
        });
    let component_count = nanobom_entity::components::Entity::find()
        .filter(nanobom_entity::components::Column::VersionId.eq(version.id))
        .count(database)
        .await?;

    let violations = crate::licenses::violations_in_version(
        database,
        reader,
        project.id,
        Some(&version.name),
        0,
        MAXIMUM_VIOLATIONS,
    )
    .await?;
    let licenses = if violations.active {
        Licenses::Policy(violations)
    } else {
        Licenses::Counts(license_counts(database, version.id).await?)
    };
    let (kev_checked_at, epss_checked_at) = crate::exploitation::last_checked(database).await?;

    Ok(Report {
        generated_at: now,
        organization_slug: organization.slug,
        organization_name: organization.name,
        stale: crate::staleness::is_stale(
            project.created_at,
            project.last_upload_at,
            now,
            stale_after_days,
        ),
        last_evaluation: last_evaluation(database, organization.id, project.id).await?,
        project_slug: project.slug,
        project_name: project.name,
        project_last_upload_at: project.last_upload_at,
        project_created_at: project.created_at,
        version: version.name,
        latest: version.latest,
        active: version.active,
        upload,
        component_count,
        kev_checked_at,
        epss_checked_at,
        summary,
        open,
        assessed,
        licenses,
    })
}

/// The versions fixing each listed finding, by vulnerability and component name, read from the
/// OSV records of their vulnerabilities as the finding page reads them: the ranges of the
/// component's full name, else of its name without namespace. Records are read in chunks and
/// dropped once parsed, since they can be large.
async fn fixed_versions(
    database: &impl ConnectionTrait,
    findings: &[Finding],
) -> Result<HashMap<(String, String), Vec<String>>> {
    let identifiers: Vec<&str> = findings
        .iter()
        .map(|finding| finding.vulnerability_id.as_str())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut fixed = HashMap::new();
    for chunk in identifiers.chunks(QUERY_CHUNK / 5) {
        let rows: Vec<(String, String)> = vulnerabilities::Entity::find()
            .select_only()
            .column(vulnerabilities::Column::Id)
            .column(vulnerabilities::Column::Record)
            .filter(vulnerabilities::Column::Id.is_in(chunk.iter().copied()))
            .into_tuple()
            .all(database)
            .await?;
        for (id, record) in rows {
            let Ok(record) = serde_json::from_str::<Vulnerability>(&record) else {
                continue;
            };
            for finding in findings
                .iter()
                .filter(|finding| finding.vulnerability_id == id)
            {
                let name = &finding.component_name;
                let key = (id.clone(), name.clone());
                if fixed.contains_key(&key) {
                    continue;
                }
                let package = name.rsplit('/').next().unwrap_or(name);
                let mut versions = record.fixed_versions(Some(name));
                if versions.is_empty() {
                    versions = record.fixed_versions(Some(package));
                }
                fixed.insert(key, versions);
            }
        }
    }
    Ok(fixed)
}

/// When a finding was ignored, and by which member and upload token.
type Ignore = (Option<DateTime<FixedOffset>>, Option<i64>, Option<i64>);

/// The ignored findings with who ignored them and when, read in chunks.
async fn assessed(
    database: &impl ConnectionTrait,
    findings: Vec<Finding>,
) -> Result<Vec<AssessedFinding>> {
    let identifiers: Vec<i64> = findings.iter().map(|finding| finding.id).collect();
    let mut ignores: HashMap<i64, Ignore> = HashMap::with_capacity(identifiers.len());
    for chunk in identifiers.chunks(QUERY_CHUNK) {
        let rows = findings_entity::Entity::find()
            .filter(findings_entity::Column::Id.is_in(chunk.iter().copied()))
            .all(database)
            .await?;
        ignores.extend(rows.into_iter().map(|finding| {
            (
                finding.id,
                (
                    finding.ignored_at,
                    finding.ignored_by_user_id,
                    finding.ignored_by_upload_token_id,
                ),
            )
        }));
    }
    let names =
        crate::findings::usernames(database, ignores.values().filter_map(|(_, user, _)| *user))
            .await?;
    let tokens = crate::findings::token_names(
        database,
        ignores.values().filter_map(|(_, _, token)| *token),
    )
    .await?;
    Ok(findings
        .into_iter()
        .map(|finding| {
            let (ignored_at, user, token) = ignores.get(&finding.id).copied().unwrap_or_default();
            AssessedFinding {
                ignored_at,
                ignored_by: user.and_then(|id| names.get(&id).cloned()),
                ignored_by_token: token.and_then(|id| tokens.get(&id).cloned()),
                finding,
            }
        })
        .collect())
}

/// The end of the last successful run covering a project: a run of the whole instance, of its
/// organization or of the project itself.
async fn last_evaluation(
    database: &impl ConnectionTrait,
    organization_id: i64,
    project_id: i64,
) -> Result<Option<DateTime<FixedOffset>>> {
    let covering = Condition::any()
        .add(runs::Column::Scope.eq(Scope::All.as_str()))
        .add(
            Condition::all()
                .add(runs::Column::Scope.eq(Scope::Organization(organization_id).as_str()))
                .add(runs::Column::OrganizationId.eq(organization_id)),
        )
        .add(
            Condition::all()
                .add(runs::Column::Scope.eq(Scope::Project(project_id).as_str()))
                .add(runs::Column::ProjectId.eq(project_id)),
        );
    Ok(runs::Entity::find()
        .filter(runs::Column::Status.eq("succeeded"))
        .filter(runs::Column::FinishedAt.is_not_null())
        .filter(covering)
        .order_by_desc(runs::Column::FinishedAt)
        .order_by_desc(runs::Column::Id)
        .one(database)
        .await?
        .and_then(|run| run.finished_at))
}

/// The version's components by license expression, counted by the database.
async fn license_counts(database: &impl ConnectionTrait, version_id: i64) -> Result<LicenseCounts> {
    use nanobom_entity::components;
    let rows: Vec<(Option<String>, i64)> = components::Entity::find()
        .select_only()
        .column(components::Column::License)
        .column_as(components::Column::Id.count(), "count")
        .filter(components::Column::VersionId.eq(version_id))
        .group_by(components::Column::License)
        .order_by_asc(components::Column::License)
        .into_tuple()
        .all(database)
        .await?;
    let mut counts = LicenseCounts::default();
    let mut groups = Vec::new();
    for (license, count) in rows {
        let count = u64::try_from(count).unwrap_or_default();
        match license {
            Some(license) => groups.push((license, count)),
            None => counts.without += count,
        }
    }
    // Most components first; the expression keeps the order of equal counts stable.
    groups.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    counts.other = groups
        .iter()
        .skip(LICENSE_GROUPS)
        .map(|(_, count)| count)
        .sum();
    groups.truncate(LICENSE_GROUPS);
    counts.groups = groups;
    Ok(counts)
}
