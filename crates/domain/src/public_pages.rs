//! Public pages of projects: the findings of a project version and how they were triaged, at a
//! public address, for the visitors of an open-source project.
//!
//! nanobom data is private, so a public page is off until someone who manages projects turns it
//! on ([`enable`]), project by project. Like a badge ([`crate::badges`]), the page is served at an
//! address made of a random **key** alone, and whoever holds the key reads [`page`] and [`vex()`]
//! and nothing else. The key is the page's own, independent of the badge's: publishing a badge
//! does not publish the page, and renewing or revoking one leaves the other alone.
//!
//! # What a page shows
//!
//! [`PublicPage`] is an allowlist: it copies the fields it shows from the report
//! ([`crate::report`]) rather than stripping a [`crate::report::Report`], so a field added to the
//! report later never reaches the public. It shows the project's name (not its organization),
//! the version, the freshness of the data, the counts, the open findings and the ignored ones
//! with their VEX justification and the day they were ignored. It never shows who ignored a
//! finding, the free-text reason (members write internal notes there), when an ignore expires,
//! the source commit or image tag, licenses, dependency paths, other versions or projects, or
//! anything that links into the interface. [`vex()`] follows the same rule.

use chrono::{DateTime, FixedOffset, Utc};
use nanobom_entity::{project_public_pages, projects};
use nanobom_osv::Severity;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, sea_query::Expr,
};
use serde::{Deserialize, Serialize};

use crate::{
    access::{Actor, Permission},
    badges::{generate_key, well_formed},
    error::{Error, Result},
    exploitation::Exploitation,
    findings::{Justification, SeverityCounts},
    report, vex,
};

/// The public page of a project version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicPage {
    pub project_name: String,
    /// Empty for the unnamed version.
    pub version: String,
    pub latest: bool,
    /// An inactive version is no longer evaluated: its findings are those of its last run.
    pub active: bool,
    /// When the version's latest SBOM was uploaded; `None` before the first upload.
    pub uploaded_at: Option<DateTime<FixedOffset>>,
    /// The version's components, as stored (those with a package URL).
    pub component_count: u64,
    /// Components of the latest SBOM without a package URL, which nanobom cannot check.
    pub components_without_purl: u64,
    /// The end of the last successful run that covered the project.
    pub last_evaluation: Option<DateTime<FixedOffset>>,
    /// When nanobom last read the CISA KEV catalog, for any CVE.
    pub kev_checked_at: Option<DateTime<FixedOffset>>,
    /// When nanobom last read FIRST EPSS scores, for any CVE.
    pub epss_checked_at: Option<DateTime<FixedOffset>>,
    /// The project received no SBOM for longer than the instance's stale threshold.
    pub stale: bool,
    pub summary: Summary,
    /// The open findings, known exploited first, as on the project page, at most
    /// [`report::MAXIMUM_OPEN`]; [`Summary::open`] counts them all.
    pub open: Vec<OpenFinding>,
    /// The ignored findings in the same order, at most [`report::MAXIMUM_ASSESSED`];
    /// [`Summary::ignored`] counts them all.
    pub assessed: Vec<AssessedFinding>,
}

/// The counts of a public page, over every finding of the version.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub open: SeverityCounts,
    /// Open findings with a known exploited CVE.
    pub known_exploited: u64,
    pub ignored: u64,
    /// Findings fixed in the last [`report::FIXED_RECENTLY_DAYS`] days and still fixed.
    pub fixed_recently: u64,
}

/// The component a finding is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    pub version: Option<String>,
    pub purl: String,
}

/// An open finding of a public page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenFinding {
    pub vulnerability_id: String,
    pub aliases: Vec<String>,
    /// The advisory's summary.
    pub summary: Option<String>,
    pub severity: Severity,
    pub cvss_score: Option<f64>,
    pub component: Component,
    /// Versions of the package that fix the vulnerability, per its OSV record.
    pub fixed_versions: Vec<String>,
    pub exploitation: Exploitation,
    pub first_seen_at: DateTime<FixedOffset>,
}

/// An ignored finding of a public page: what was decided, never who decided it or why in their
/// own words.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssessedFinding {
    pub vulnerability_id: String,
    pub aliases: Vec<String>,
    pub severity: Severity,
    pub component: Component,
    /// `None` for an ignore without a justification, often an accepted risk.
    pub justification: Option<Justification>,
    pub ignored_at: Option<DateTime<FixedOffset>>,
}

/// The key of a project's public page, `None` while it is off. Requires
/// [`Permission::ManageProjects`]: the key gives the page's address, which those who manage the
/// project decide to publish.
pub async fn key(
    database: &impl ConnectionTrait,
    actor: &Actor,
    project_id: i64,
) -> Result<Option<String>> {
    crate::projects::authorize(database, actor, project_id, Permission::ManageProjects).await?;
    Ok(project_public_pages::Entity::find_by_id(project_id)
        .one(database)
        .await?
        .map(|page| page.key))
}

/// Turns a project's public page on and returns its key. A page that is already on keeps its
/// key, so a "Turn on" sent from a stale page never breaks an address already published; only
/// [`regenerate`] replaces it. Requires [`Permission::ManageProjects`].
pub async fn enable(
    database: &impl ConnectionTrait,
    actor: &Actor,
    project_id: i64,
) -> Result<String> {
    let project =
        crate::projects::authorize(database, actor, project_id, Permission::ManageProjects).await?;
    if let Some(page) = project_public_pages::Entity::find_by_id(project_id)
        .one(database)
        .await?
    {
        return Ok(page.key);
    }
    let inserted = project_public_pages::Entity::insert(project_public_pages::ActiveModel {
        project_id: Set(project_id),
        key: Set(generate_key()),
        created_at: Set(Utc::now().fixed_offset()),
    })
    .exec(database)
    .await;
    // A concurrent request may have turned it on first: its key is the one to keep.
    let page = project_public_pages::Entity::find_by_id(project_id)
        .one(database)
        .await?;
    match (inserted, page) {
        (Ok(_), Some(page)) => {
            // The key itself is never logged: it is the page's only authorization.
            tracing::info!(project = %project.slug, user = actor.user_id, "public page turned on");
            Ok(page.key)
        }
        (Err(_), Some(page)) => Ok(page.key),
        (Err(error), None) => Err(error.into()),
        (Ok(_), None) => Err(Error::NotFound),
    }
}

/// Gives a public page that is on a new key and returns it; the old address stops working at
/// once. A page that is off is [`Error::NotFound`]: a "New address" sent from a stale page must
/// not publish a page someone has turned off. Requires [`Permission::ManageProjects`].
pub async fn regenerate(
    database: &impl ConnectionTrait,
    actor: &Actor,
    project_id: i64,
) -> Result<String> {
    let project =
        crate::projects::authorize(database, actor, project_id, Permission::ManageProjects).await?;
    let key = generate_key();
    let updated = project_public_pages::Entity::update_many()
        .col_expr(project_public_pages::Column::Key, Expr::value(key.clone()))
        .col_expr(
            project_public_pages::Column::CreatedAt,
            Expr::value(Utc::now().fixed_offset()),
        )
        .filter(project_public_pages::Column::ProjectId.eq(project_id))
        .exec(database)
        .await?;
    if updated.rows_affected == 0 {
        return Err(Error::NotFound);
    }
    tracing::info!(project = %project.slug, user = actor.user_id, "public page address replaced");
    Ok(key)
}

/// Turns a project's public page off: its address stops working. Turning off a page that is
/// off does nothing. Requires [`Permission::ManageProjects`].
pub async fn disable(
    database: &impl ConnectionTrait,
    actor: &Actor,
    project_id: i64,
) -> Result<()> {
    let project =
        crate::projects::authorize(database, actor, project_id, Permission::ManageProjects).await?;
    let deleted = project_public_pages::Entity::delete_by_id(project_id)
        .exec(database)
        .await?;
    if deleted.rows_affected > 0 {
        tracing::info!(project = %project.slug, user = actor.user_id, "public page turned off");
    }
    Ok(())
}

/// The project whose public page has this key.
async fn project(database: &impl ConnectionTrait, key: &str) -> Result<projects::Model> {
    if !well_formed(key) {
        return Err(Error::NotFound);
    }
    let page = project_public_pages::Entity::find()
        .filter(project_public_pages::Column::Key.eq(key))
        .one(database)
        .await?
        .ok_or(Error::NotFound)?;
    projects::Entity::find_by_id(page.project_id)
        .one(database)
        .await?
        .ok_or(Error::NotFound)
}

/// The public page with this key, for the version named `version` (`None`: the latest).
/// `stale_after_days` is the stale threshold of the instance (0: never stale).
///
/// Takes no actor: the key is the caller's authorization, and it only unlocks this page and
/// [`vex()`]. An unknown or malformed key and an unknown version are all [`Error::NotFound`], so a
/// caller cannot tell which part was wrong.
pub async fn page(
    database: &impl ConnectionTrait,
    key: &str,
    version: Option<&str>,
    stale_after_days: u32,
) -> Result<PublicPage> {
    let project = project(database, key).await?;
    let version = crate::versions::select(database, project.id, version).await?;
    let contents = report::contents(database, &project, &version, stale_after_days).await?;
    let (uploaded_at, components_without_purl) =
        contents.upload.as_ref().map_or((None, 0), |upload| {
            (
                Some(upload.uploaded_at),
                u64::try_from(upload.components_without_purl).unwrap_or_default(),
            )
        });
    Ok(PublicPage {
        project_name: project.name,
        version: version.name,
        latest: version.latest,
        active: version.active,
        uploaded_at,
        component_count: contents.component_count,
        components_without_purl,
        last_evaluation: contents.last_evaluation,
        kev_checked_at: contents.kev_checked_at,
        epss_checked_at: contents.epss_checked_at,
        stale: contents.stale,
        summary: Summary {
            open: contents.summary.open,
            known_exploited: contents.summary.known_exploited,
            ignored: contents.summary.ignored,
            fixed_recently: contents.summary.fixed_recently,
        },
        open: contents
            .open
            .into_iter()
            .map(|open| {
                let finding = open.finding;
                OpenFinding {
                    component: Component {
                        name: finding.component_name,
                        version: finding.component_version,
                        purl: finding.purl,
                    },
                    vulnerability_id: finding.vulnerability_id,
                    aliases: finding.aliases,
                    summary: finding.summary,
                    severity: finding.severity,
                    cvss_score: finding.cvss_score,
                    fixed_versions: open.fixed_versions,
                    exploitation: finding.exploitation,
                    first_seen_at: finding.first_seen_at,
                }
            })
            .collect(),
        assessed: contents
            .assessed
            .into_iter()
            .map(|assessed| {
                let finding = assessed.finding;
                AssessedFinding {
                    component: Component {
                        name: finding.component_name,
                        version: finding.component_version,
                        purl: finding.purl,
                    },
                    vulnerability_id: finding.vulnerability_id,
                    aliases: finding.aliases,
                    severity: finding.severity,
                    justification: finding.ignore_justification,
                    ignored_at: assessed.ignored_at,
                }
            })
            .collect(),
    })
}

/// The CycloneDX VEX document of the version named `version` (`None`: the latest) of the
/// project whose public page has this key, for scanners downstream. Like [`vex::export`],
/// without the organization and without `analysis.detail`, which carries the free-text reason
/// of each ignore. Not found as [`page`] is.
pub async fn vex(
    database: &impl ConnectionTrait,
    key: &str,
    version: Option<&str>,
) -> Result<vex::Document> {
    let project = project(database, key).await?;
    let version = crate::versions::select(database, project.id, version).await?;
    vex::version_document(database, project, &version, vex::Audience::Public).await
}
