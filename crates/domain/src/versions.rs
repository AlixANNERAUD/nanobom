//! Versions of a project: components, their dependency graph, uploads and findings belong to
//! one version of their project, as in Dependency-Track, where a project is a name and a
//! version.
//!
//! A project has at least one version. Uploads name theirs ([`crate::inventory::ingest`]); one that names
//! none goes to the unnamed version (name `""`), so a project that never names one behaves as if
//! versions did not exist. One version of each project is flagged **latest**: it is the one read
//! when a reader does not name a version ([`find`]). Runs evaluate the **active** versions
//! only, and organization-wide reads (search, counts, notifications) cover active versions
//! only; a project has at most [`MAXIMUM_ACTIVE`] of them.
//!
//! A version an upload creates **inherits** the open and ignored findings of the latest version
//! (`inherit`), so a release branch does not have to be triaged again; the run that follows
//! the upload then updates them like any findings, and they are never announced as new.
//!
//! Rows of the versioned tables also keep their `project_id`, which carries the foreign key that
//! deletes them with their project and lets organization-wide queries stay simple; their
//! `version_id` has no foreign key (see the migration), so this module and the writers keep the
//! two consistent.

use std::collections::HashMap;

use chrono::{DateTime, FixedOffset};
use nanobom_entity::{finding_events, findings, project_versions};
use nanobom_osv::Severity;
use sea_orm::{
    ActiveModelTrait,
    ActiveValue::Set,
    ColumnTrait, ConnectionTrait, DbErr, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect,
    sea_query::{Expr, OnConflict, Query, SelectStatement},
};
use serde::{Deserialize, Serialize};

use crate::{
    access::{Permission, Reader},
    error::{Error, Result},
    findings::{EventKind, SeverityCounts, Status},
    problem::Problem,
};

/// The name of the version uploads go to when they name none.
pub const UNNAMED: &str = "";

/// Inserts the first version of a new project, flagged latest, in the transaction that inserts
/// the project, so a project is never seen without a version. Projects created in the interface
/// start with the unnamed version; those created by an upload, with the version it names.
pub(crate) async fn insert_first(
    database: &impl ConnectionTrait,
    project_id: i64,
    name: &str,
    created_at: DateTime<FixedOffset>,
) -> Result<project_versions::Model> {
    Ok(project_versions::ActiveModel {
        project_id: Set(project_id),
        name: Set(name.to_owned()),
        latest: Set(true),
        active: Set(true),
        created_at: Set(created_at),
        last_upload_at: Set(None),
        dependencies_partial: Set(false),
        ..Default::default()
    }
    .insert(database)
    .await?)
}

/// The version of a project with this name, without authorization.
async fn named(
    database: &impl ConnectionTrait,
    project_id: i64,
    name: &str,
) -> Result<Option<project_versions::Model>> {
    Ok(project_versions::Entity::find()
        .filter(project_versions::Column::ProjectId.eq(project_id))
        .filter(project_versions::Column::Name.eq(name))
        .one(database)
        .await?)
}

/// The most active versions a project may have. nanobom keeps small databases, and each active
/// version is evaluated at every run and counted on every page: a project that needs more makes
/// old versions inactive. Dependency-Track has no such cap.
pub const MAXIMUM_ACTIVE: u64 = 50;

/// The longest version name, in characters.
pub const MAXIMUM_NAME_LENGTH: usize = 64;

/// Checks a version name given by CI and returns it trimmed: 1 to [`MAXIMUM_NAME_LENGTH`]
/// characters among ASCII letters, digits, `.`, `_`, `+`, `/` and `-`, enough for semantic
/// versions, build metadata and branch names (`release/2.4`). Names are case-sensitive.
pub fn validate_name(name: &str) -> Result<String> {
    let name = name.trim();
    let valid = (1..=MAXIMUM_NAME_LENGTH).contains(&name.len())
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._+/-".contains(character));
    if valid {
        Ok(name.to_owned())
    } else {
        Err(Error::invalid(Problem::InvalidVersionName {
            maximum: MAXIMUM_NAME_LENGTH,
        }))
    }
}

/// The version an upload goes to, as [`prepare_upload`] found or created it.
#[derive(Debug, Clone)]
pub(crate) struct UploadVersion {
    pub version: project_versions::Model,
    /// The upload created the version.
    pub created: bool,
    /// The latest version before the upload, when the upload created another one: the version
    /// whose findings the new one inherits.
    pub inherits_from: Option<project_versions::Model>,
}

/// The version of a project an upload goes to, without authorization: the one named (the
/// unnamed version when `name` is [`UNNAMED`]), created when missing.
///
/// A created version becomes the latest unless `latest` is `Some(false)`; `Some(true)` makes an
/// existing version the latest. The flag moves inside the caller's transaction, so readers
/// always see exactly one latest version. Creating a version beyond [`MAXIMUM_ACTIVE`] active
/// ones is a [`Problem::TooManyVersions`] conflict.
///
/// The caller must hold a write lock on the project row (the upload updates it first): on
/// PostgreSQL that serializes concurrent uploads to one project, which the cap and the latest
/// flag rely on. Creation itself is an insert that does nothing on conflict, so two uploads
/// creating the same version at once never fail on the unique index whatever the locking.
pub(crate) async fn prepare_upload(
    database: &impl ConnectionTrait,
    project_id: i64,
    name: &str,
    latest: Option<bool>,
    now: DateTime<FixedOffset>,
) -> Result<UploadVersion> {
    if let Some(version) = named(database, project_id, name).await? {
        let version = if latest == Some(true) && !version.latest {
            make_latest(database, version).await?
        } else {
            version
        };
        return Ok(UploadVersion {
            version,
            created: false,
            inherits_from: None,
        });
    }
    let active = project_versions::Entity::find()
        .filter(project_versions::Column::ProjectId.eq(project_id))
        .filter(project_versions::Column::Active.eq(true))
        .count(database)
        .await?;
    if active >= MAXIMUM_ACTIVE {
        return Err(Error::conflict(Problem::TooManyVersions {
            maximum: MAXIMUM_ACTIVE,
        }));
    }
    let previous = latest_version(database, project_id).await?;
    let inserted = project_versions::Entity::insert(project_versions::ActiveModel {
        project_id: Set(project_id),
        name: Set(name.to_owned()),
        latest: Set(false),
        active: Set(true),
        created_at: Set(now),
        last_upload_at: Set(None),
        dependencies_partial: Set(false),
        ..Default::default()
    })
    .on_conflict(
        OnConflict::columns([
            project_versions::Column::ProjectId,
            project_versions::Column::Name,
        ])
        .do_nothing()
        .to_owned(),
    )
    .exec_without_returning(database)
    .await?;
    let version = named(database, project_id, name)
        .await?
        .ok_or_else(|| Error::Database(DbErr::RecordNotFound("project version".to_owned())))?;
    // Another upload created it between the lookup and the insert: it is that upload's.
    if inserted == 0 {
        return Ok(UploadVersion {
            version,
            created: false,
            inherits_from: None,
        });
    }
    // A project without a latest version (never the case today) takes the new one whatever
    // the upload asks, so that reads always find one.
    let version = if latest != Some(false) || previous.is_none() {
        make_latest(database, version).await?
    } else {
        version
    };
    Ok(UploadVersion {
        version,
        created: true,
        inherits_from: previous,
    })
}

/// Flags a version latest and clears the flag on the others of its project, in the caller's
/// transaction.
async fn make_latest(
    database: &impl ConnectionTrait,
    version: project_versions::Model,
) -> Result<project_versions::Model> {
    project_versions::Entity::update_many()
        .col_expr(project_versions::Column::Latest, Expr::value(false))
        .filter(project_versions::Column::ProjectId.eq(version.project_id))
        .filter(project_versions::Column::Id.ne(version.id))
        .exec(database)
        .await?;
    let mut version: project_versions::ActiveModel = version.into();
    version.latest = Set(true);
    Ok(version.update(database).await?)
}

/// The latest version of a project, without authorization.
async fn latest_version(
    database: &impl ConnectionTrait,
    project_id: i64,
) -> Result<Option<project_versions::Model>> {
    Ok(project_versions::Entity::find()
        .filter(project_versions::Column::ProjectId.eq(project_id))
        .filter(project_versions::Column::Latest.eq(true))
        // Exactly one is latest; the order only makes the choice stable if that ever breaks.
        .order_by_desc(project_versions::Column::Id)
        .one(database)
        .await?)
}

/// The version a read of a project is about, without authorization: the one named, or the
/// latest version when `name` is `None`. Every read of one project's components, findings or
/// graph goes through this, so naming a version is a matter of passing it down. A missing
/// version is [`Error::NotFound`].
pub(crate) async fn select(
    database: &impl ConnectionTrait,
    project_id: i64,
    name: Option<&str>,
) -> Result<project_versions::Model> {
    match name {
        Some(name) => named(database, project_id, name).await?,
        None => latest_version(database, project_id).await?,
    }
    .ok_or(Error::NotFound)
}

/// A version of a project by name, `None` for the latest one. Requires [`Permission::View`] in
/// the project's organization; a version of a project the reader cannot see is
/// [`Error::NotFound`], like a missing one.
pub async fn find(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    project_id: i64,
    name: Option<&str>,
) -> Result<project_versions::Model> {
    crate::projects::authorize(database, reader, project_id, Permission::View).await?;
    select(database, project_id, name).await
}

/// The latest version of each of these projects, without authorization.
pub(crate) async fn latest_of(
    database: &impl ConnectionTrait,
    project_ids: &[i64],
) -> Result<Vec<project_versions::Model>> {
    let mut versions = Vec::new();
    // Bounded lists stay under the bind parameter limits of every database.
    for chunk in project_ids.chunks(500) {
        versions.extend(
            project_versions::Entity::find()
                .filter(project_versions::Column::ProjectId.is_in(chunk.iter().copied()))
                .filter(project_versions::Column::Latest.eq(true))
                .order_by_asc(project_versions::Column::ProjectId)
                .all(database)
                .await?,
        );
    }
    Ok(versions)
}

/// The active versions of these projects, by project then creation, without authorization.
pub(crate) async fn active(
    database: &impl ConnectionTrait,
    project_ids: &[i64],
) -> std::result::Result<Vec<project_versions::Model>, DbErr> {
    let mut versions = Vec::new();
    for chunk in project_ids.chunks(500) {
        versions.extend(
            project_versions::Entity::find()
                .filter(project_versions::Column::ProjectId.is_in(chunk.iter().copied()))
                .filter(project_versions::Column::Active.eq(true))
                .order_by_asc(project_versions::Column::ProjectId)
                .order_by_asc(project_versions::Column::Id)
                .all(database)
                .await?,
        );
    }
    Ok(versions)
}

/// The identifiers of every active version, as a subquery: organization-wide reads filter their
/// rows with `version_id IN (…)` so inactive versions drop out without a join.
pub(crate) fn active_ids() -> SelectStatement {
    Query::select()
        .column(project_versions::Column::Id)
        .from(project_versions::Entity)
        .and_where(project_versions::Column::Active.eq(true))
        .to_owned()
}

/// Records an upload on a version: when it happened and whether its graph lost links.
pub(crate) async fn record_upload(
    database: &impl ConnectionTrait,
    version: project_versions::Model,
    uploaded_at: DateTime<FixedOffset>,
    dependencies_partial: bool,
) -> Result<project_versions::Model> {
    let mut version: project_versions::ActiveModel = version.into();
    version.last_upload_at = Set(Some(uploaded_at));
    version.dependencies_partial = Set(dependencies_partial);
    Ok(version.update(database).await?)
}

/// Copies the open and ignored findings of `from` into `to`, a version an upload just created,
/// as Dependency-Track copies the audit trail when it clones a version: a new release starts
/// with the triage of the latest one, and its first run then matches these findings like any
/// other, fixing those whose component the new SBOM no longer has.
///
/// The copies keep the status, severity, ignore, first and last seen times and the
/// known-exploited notification of their original, so neither they nor their exploitation are
/// announced again. Fixed findings are not copied: nothing of them applies to the new SBOM (an
/// ignore ends when its finding is fixed), and a vulnerability that comes back in the new
/// version is news. The history is not copied either; each copy gets one
/// [`EventKind::Inherited`] event naming the version it comes from (in its reason), recorded as
/// made by the upload's token.
pub(crate) async fn inherit(
    database: &impl ConnectionTrait,
    from: &project_versions::Model,
    to: &project_versions::Model,
    upload_token_id: i64,
    now: DateTime<FixedOffset>,
) -> Result<usize> {
    let originals = findings::Entity::find()
        .filter(findings::Column::VersionId.eq(from.id))
        .filter(findings::Column::Status.ne(Status::Fixed.as_str()))
        .order_by_asc(findings::Column::Id)
        .all(database)
        .await?;
    if originals.is_empty() {
        return Ok(0);
    }
    let copies: Vec<findings::ActiveModel> = originals
        .into_iter()
        .map(|finding| findings::ActiveModel {
            project_id: Set(to.project_id),
            version_id: Set(Some(to.id)),
            purl: Set(finding.purl),
            ecosystem: Set(finding.ecosystem),
            vulnerability_id: Set(finding.vulnerability_id),
            status: Set(finding.status),
            severity: Set(finding.severity),
            first_seen_at: Set(finding.first_seen_at),
            last_seen_at: Set(finding.last_seen_at),
            fixed_at: Set(None),
            ignore_reason: Set(finding.ignore_reason),
            ignore_expires_at: Set(finding.ignore_expires_at),
            ignored_by_user_id: Set(finding.ignored_by_user_id),
            ignored_at: Set(finding.ignored_at),
            exploited_notified_at: Set(finding.exploited_notified_at),
            ignore_justification: Set(finding.ignore_justification),
            ignored_by_upload_token_id: Set(finding.ignored_by_upload_token_id),
            ..Default::default()
        })
        .collect();
    let count = copies.len();
    // Bounded batches stay under the bind parameter limits of every database.
    for batch in copies.chunks(500) {
        findings::Entity::insert_many(batch.to_vec())
            .exec(database)
            .await?;
    }
    // Multi-row inserts do not return every identifier on all databases: the new version had no
    // findings, so all of its findings are the copies.
    let identifiers: Vec<i64> = findings::Entity::find()
        .select_only()
        .column(findings::Column::Id)
        .filter(findings::Column::VersionId.eq(to.id))
        .order_by_asc(findings::Column::Id)
        .into_tuple()
        .all(database)
        .await?;
    let events: Vec<finding_events::ActiveModel> = identifiers
        .into_iter()
        .map(|finding_id| finding_events::ActiveModel {
            finding_id: Set(finding_id),
            created_at: Set(now),
            kind: Set(EventKind::Inherited.as_str().to_owned()),
            actor_user_id: Set(None),
            upload_token_id: Set(Some(upload_token_id)),
            reason: Set(Some(from.name.clone())),
            justification: Set(None),
            run_id: Set(None),
            ..Default::default()
        })
        .collect();
    for batch in events.chunks(500) {
        finding_events::Entity::insert_many(batch.to_vec())
            .exec(database)
            .await?;
    }
    Ok(count)
}

/// A version of a project, as listed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionSummary {
    /// The identifier the version's uploads and findings refer to.
    pub id: i64,
    /// Empty for the unnamed version.
    pub name: String,
    pub latest: bool,
    pub active: bool,
    pub created_at: DateTime<FixedOffset>,
    pub last_upload_at: Option<DateTime<FixedOffset>>,
    /// Open findings of the version by severity.
    pub open: SeverityCounts,
}

/// The versions of a project, newest first, with their open findings. Requires
/// [`Permission::View`].
pub async fn list(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    project_id: i64,
) -> Result<Vec<VersionSummary>> {
    crate::projects::authorize(database, reader, project_id, Permission::View).await?;
    let versions = project_versions::Entity::find()
        .filter(project_versions::Column::ProjectId.eq(project_id))
        .order_by_desc(project_versions::Column::CreatedAt)
        .order_by_desc(project_versions::Column::Id)
        .all(database)
        .await?;
    let mut open: HashMap<i64, SeverityCounts> = HashMap::new();
    let rows: Vec<(Option<i64>, String)> = findings::Entity::find()
        .select_only()
        .column(findings::Column::VersionId)
        .column(findings::Column::Severity)
        .filter(findings::Column::ProjectId.eq(project_id))
        .filter(findings::Column::Status.eq(Status::Open.as_str()))
        .into_tuple()
        .all(database)
        .await?;
    for (version_id, severity) in rows {
        if let Some(version_id) = version_id {
            open.entry(version_id)
                .or_default()
                .add(severity.parse().unwrap_or(Severity::Unknown));
        }
    }
    Ok(versions
        .into_iter()
        .map(|version| VersionSummary {
            open: open.remove(&version.id).unwrap_or_default(),
            id: version.id,
            name: version.name,
            latest: version.latest,
            active: version.active,
            created_at: version.created_at,
            last_upload_at: version.last_upload_at,
        })
        .collect())
}
