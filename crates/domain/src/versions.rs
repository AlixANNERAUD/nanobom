//! Versions of a project: components, their dependency graph, uploads and findings belong to
//! one version of their project, as in Dependency-Track, where a project is a name and a
//! version.
//!
//! A project has at least one version. Uploads name theirs ([`crate::inventory::ingest`]); one that names
//! none goes to the unnamed version (name `""`), so a project that never names one behaves as if
//! versions did not exist. One version of each project is flagged **latest**: it is the one read
//! when a reader does not name a version ([`find`]). Runs evaluate the **active** versions
//! only, and organization-wide reads (search, counts, notifications, metrics) cover active
//! versions only; inactive versions stay readable and exportable by name.
//!
//! A project has at most [`MAXIMUM_ACTIVE`] active versions. An upload that would go past the
//! cap (creating a version, or reactivating an inactive one) makes the active version uploaded
//! to the longest ago inactive instead of failing, so pipelines that send a build number as the
//! version keep working; nothing is ever deleted automatically. Users who manage projects make
//! versions inactive and active again ([`set_active`]), mark one latest ([`set_latest`]) and
//! delete them ([`delete`]). The latest version is always active.
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
use nanobom_entity::{
    component_dependencies, components, finding_events, findings, project_versions, projects,
    sbom_uploads,
};
use nanobom_osv::Severity;
use sea_orm::{
    ActiveModelTrait,
    ActiveValue::Set,
    ColumnTrait, ConnectionTrait, DbErr, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, TransactionSession, TransactionTrait,
    sea_query::{Expr, OnConflict, Query, SelectStatement},
};
use serde::{Deserialize, Serialize};

use crate::{
    access::{Actor, Permission, Reader},
    error::{Error, Result},
    findings::{EventKind, SeverityCounts, Status},
    problem::Problem,
};

/// The name of the version uploads go to when they name none.
pub const UNNAMED: &str = "";

/// Inserts the first version of a new project, flagged latest, in the transaction that inserts
/// the project, so a project is never seen without a version. Projects created in the interface
/// start with the unnamed version, renamed by their first upload naming one if still unused;
/// those created by an upload, with the version it names.
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
/// version is evaluated at every run and counted on every page: past the cap, uploads make the
/// version uploaded to the longest ago inactive (see the module documentation).
/// Dependency-Track has no such cap.
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
/// always see exactly one latest version. An inactive version becomes active again, as it is
/// in use. Creating or reactivating a version when the project already has [`MAXIMUM_ACTIVE`]
/// active ones first makes another inactive ([`make_room`]).
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
        let version = if version.active {
            version
        } else {
            make_room(database, project_id).await?;
            tracing::info!(
                project_id,
                version = %version.name,
                "inactive version made active by an upload"
            );
            let mut version: project_versions::ActiveModel = version.into();
            version.active = Set(true);
            version.update(database).await?
        };
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
    if name != UNNAMED
        && let Some(version) = claim_unused_unnamed(database, project_id, name).await?
    {
        return Ok(UploadVersion {
            version,
            created: true,
            inherits_from: None,
        });
    }
    make_room(database, project_id).await?;
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

/// Makes active versions of a project inactive until there is room for one more under
/// [`MAXIMUM_ACTIVE`], in the caller's transaction: those whose last upload (their creation
/// when they never had one) is the oldest go first, never the latest. The version about to be
/// created or reactivated is not active yet, so it is never among them.
///
/// Inactive versions keep everything (components, findings, triage) and become active again
/// with their next upload; nothing is deleted.
async fn make_room(database: &impl ConnectionTrait, project_id: i64) -> Result<()> {
    let mut candidates: Vec<project_versions::Model> = project_versions::Entity::find()
        .filter(project_versions::Column::ProjectId.eq(project_id))
        .filter(project_versions::Column::Active.eq(true))
        .order_by_asc(project_versions::Column::Id)
        .all(database)
        .await?;
    // Room for one more: at most `MAXIMUM_ACTIVE - 1` may stay.
    let excess = (candidates.len() as u64 + 1).saturating_sub(MAXIMUM_ACTIVE);
    if excess == 0 {
        return Ok(());
    }
    candidates.retain(|version| !version.latest);
    // Sorted in Rust rather than with `COALESCE` in SQL: there are at most a few dozen, and
    // the identifier breaks ties between versions created in the same instant.
    candidates.sort_by_key(|version| {
        (
            version.last_upload_at.unwrap_or(version.created_at),
            version.id,
        )
    });
    for version in candidates
        .into_iter()
        .take(usize::try_from(excess).unwrap_or(usize::MAX))
    {
        tracing::info!(
            project_id,
            version = %version.name,
            last_upload_at = ?version.last_upload_at,
            maximum = MAXIMUM_ACTIVE,
            "version made inactive: the project reached its maximum of active versions"
        );
        let mut version: project_versions::ActiveModel = version.into();
        version.active = Set(false);
        version.update(database).await?;
    }
    Ok(())
}

/// Renames a project's unnamed version to `name` when it is the project's only version and
/// never received anything, and returns it. A project created in the interface starts with an
/// unnamed version; without this, its first upload naming a version would leave that empty
/// version next to the named one forever. The version is the only one, so it is already the
/// latest whatever the upload asks.
async fn claim_unused_unnamed(
    database: &impl ConnectionTrait,
    project_id: i64,
    name: &str,
) -> Result<Option<project_versions::Model>> {
    let mut versions = project_versions::Entity::find()
        .filter(project_versions::Column::ProjectId.eq(project_id))
        .order_by_asc(project_versions::Column::Id)
        .limit(2)
        .all(database)
        .await?;
    let Some(version) = versions.pop() else {
        return Ok(None);
    };
    if !versions.is_empty() || version.name != UNNAMED || version.last_upload_at.is_some() {
        return Ok(None);
    }
    let used = components::Entity::find()
        .filter(components::Column::VersionId.eq(version.id))
        .count(database)
        .await?
        > 0
        || findings::Entity::find()
            .filter(findings::Column::VersionId.eq(version.id))
            .count(database)
            .await?
            > 0
        || sbom_uploads::Entity::find()
            .filter(sbom_uploads::Column::VersionId.eq(version.id))
            .count(database)
            .await?
            > 0;
    if used {
        return Ok(None);
    }
    let mut version: project_versions::ActiveModel = version.into();
    version.name = Set(name.to_owned());
    Ok(Some(version.update(database).await?))
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

/// Takes the write lock on a project's row for the rest of the transaction, as uploads do by
/// updating it first: on PostgreSQL, changes to a project's versions then wait for one another
/// and for uploads, so the cap and the latest flag hold. SQLite already serializes writers.
async fn lock_project(database: &impl ConnectionTrait, project_id: i64) -> Result<()> {
    projects::Entity::update_many()
        .col_expr(projects::Column::Name, Expr::col(projects::Column::Name))
        .filter(projects::Column::Id.eq(project_id))
        .exec(database)
        .await?;
    Ok(())
}

/// Authorizes a change to a project's versions and opens its transaction: the project row is
/// locked ([`lock_project`]) and the version named `name` read inside it.
async fn begin_change<C: ConnectionTrait + TransactionTrait>(
    database: &C,
    actor: &Actor,
    project_id: i64,
    name: &str,
) -> Result<(C::Transaction, project_versions::Model)> {
    crate::projects::authorize(database, actor, project_id, Permission::ManageProjects).await?;
    let transaction = crate::database::begin_write(database).await?;
    lock_project(&transaction, project_id).await?;
    let version = named(&transaction, project_id, name)
        .await?
        .ok_or(Error::NotFound)?;
    Ok((transaction, version))
}

/// Makes a version inactive (`active` false) or active again. Requires
/// [`Permission::ManageProjects`]. An inactive version is no longer evaluated by runs, counted
/// or notified, and stays readable and exportable; making it active again lets the next run
/// catch up.
///
/// The latest version cannot be made inactive ([`Problem::LatestVersionInactive`]): another one
/// must be marked latest first. Making a version active again when the project already has
/// [`MAXIMUM_ACTIVE`] active versions is a [`Problem::TooManyVersions`] conflict: unlike an
/// upload, a user choosing which versions to keep is better asked than overruled.
pub async fn set_active(
    database: &(impl ConnectionTrait + TransactionTrait),
    actor: &Actor,
    project_id: i64,
    name: &str,
    active: bool,
) -> Result<project_versions::Model> {
    let (transaction, version) = begin_change(database, actor, project_id, name).await?;
    if version.active == active {
        return Ok(version);
    }
    if !active && version.latest {
        return Err(Error::conflict(Problem::LatestVersionInactive));
    }
    if active {
        let count = project_versions::Entity::find()
            .filter(project_versions::Column::ProjectId.eq(project_id))
            .filter(project_versions::Column::Active.eq(true))
            .count(&transaction)
            .await?;
        if count >= MAXIMUM_ACTIVE {
            return Err(Error::conflict(Problem::TooManyVersions {
                maximum: MAXIMUM_ACTIVE,
            }));
        }
    }
    let mut version: project_versions::ActiveModel = version.into();
    version.active = Set(active);
    let version = version.update(&transaction).await?;
    transaction.commit().await?;
    tracing::info!(
        project_id,
        version = %version.name,
        active,
        user = actor.user_id,
        "version activity changed"
    );
    Ok(version)
}

/// Marks a version latest, the one read when a reader names none, and clears the flag on the
/// others. Requires [`Permission::ManageProjects`]. An inactive version cannot be the latest
/// ([`Problem::InactiveVersionLatest`]): it must be made active first.
pub async fn set_latest(
    database: &(impl ConnectionTrait + TransactionTrait),
    actor: &Actor,
    project_id: i64,
    name: &str,
) -> Result<project_versions::Model> {
    let (transaction, version) = begin_change(database, actor, project_id, name).await?;
    if version.latest {
        return Ok(version);
    }
    if !version.active {
        return Err(Error::conflict(Problem::InactiveVersionLatest));
    }
    let version = make_latest(&transaction, version).await?;
    transaction.commit().await?;
    tracing::info!(project_id, version = %version.name, user = actor.user_id, "latest version changed");
    Ok(version)
}

/// Deletes a version with its components, dependency graph, upload history and findings (with
/// their history), in one transaction. Requires [`Permission::ManageProjects`].
///
/// The latest version cannot be deleted ([`Problem::LatestVersionDeleted`]), nor the only
/// version of a project ([`Problem::LastVersion`]): a project always has a latest version, and
/// deleting the project is the way to remove everything.
///
/// The rows are deleted explicitly, children first: `version_id` has no foreign key (see the
/// module documentation). The version's row goes first, so that a run updating the version,
/// which locks that row ([`crate::evaluation`]), has either finished, and its findings are
/// deleted here, or will find the version gone and leave it alone.
pub async fn delete(
    database: &(impl ConnectionTrait + TransactionTrait),
    actor: &Actor,
    project_id: i64,
    name: &str,
) -> Result<()> {
    let (transaction, version) = begin_change(database, actor, project_id, name).await?;
    // The only version is also the latest: checked first, as its message says what to do.
    let others = project_versions::Entity::find()
        .filter(project_versions::Column::ProjectId.eq(project_id))
        .filter(project_versions::Column::Id.ne(version.id))
        .count(&transaction)
        .await?;
    if others == 0 {
        return Err(Error::conflict(Problem::LastVersion));
    }
    if version.latest {
        return Err(Error::conflict(Problem::LatestVersionDeleted));
    }
    project_versions::Entity::delete_by_id(version.id)
        .exec(&transaction)
        .await?;
    finding_events::Entity::delete_many()
        .filter(
            finding_events::Column::FindingId.in_subquery(
                Query::select()
                    .column(findings::Column::Id)
                    .from(findings::Entity)
                    .and_where(findings::Column::VersionId.eq(version.id))
                    .to_owned(),
            ),
        )
        .exec(&transaction)
        .await?;
    findings::Entity::delete_many()
        .filter(findings::Column::VersionId.eq(version.id))
        .exec(&transaction)
        .await?;
    // Before the components, which the edges reference.
    component_dependencies::Entity::delete_many()
        .filter(component_dependencies::Column::VersionId.eq(version.id))
        .exec(&transaction)
        .await?;
    components::Entity::delete_many()
        .filter(components::Column::VersionId.eq(version.id))
        .exec(&transaction)
        .await?;
    sbom_uploads::Entity::delete_many()
        .filter(sbom_uploads::Column::VersionId.eq(version.id))
        .exec(&transaction)
        .await?;
    transaction.commit().await?;
    tracing::info!(project_id, version = %version.name, user = actor.user_id, "version deleted");
    Ok(())
}
