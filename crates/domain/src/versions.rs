//! Versions of a project: components, their dependency graph, uploads and findings belong to
//! one version of their project.
//!
//! A project has at least one version. The unnamed version (name `""`) is created with the
//! project and receives every upload that names no version, so a project that never names one
//! behaves as if versions did not exist. One version of each project is flagged **latest**: it
//! is the one read when a reader does not name a version ([`find`]). Runs evaluate the
//! **active** versions only, and organization-wide reads (search, counts, notifications) cover
//! active versions only.
//!
//! Rows of the versioned tables also keep their `project_id`, which carries the foreign key that
//! deletes them with their project and lets organization-wide queries stay simple; their
//! `version_id` has no foreign key (see the migration), so this module and the writers keep the
//! two consistent.

use chrono::{DateTime, FixedOffset};
use nanobom_entity::project_versions;
use sea_orm::{
    ActiveModelTrait,
    ActiveValue::Set,
    ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, QueryOrder,
    sea_query::{Query, SelectStatement},
};

use crate::{
    access::{Permission, Reader},
    error::{Error, Result},
};

/// The name of the version uploads go to when they name none.
pub const UNNAMED: &str = "";

/// Inserts the unnamed version of a project. A new project's is flagged latest and inserted in
/// the transaction that inserts the project, so a project is never seen without a version.
pub(crate) async fn insert_unnamed(
    database: &impl ConnectionTrait,
    project_id: i64,
    latest: bool,
    created_at: DateTime<FixedOffset>,
) -> Result<project_versions::Model> {
    Ok(project_versions::ActiveModel {
        project_id: Set(project_id),
        name: Set(UNNAMED.to_owned()),
        latest: Set(latest),
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

/// The unnamed version of a project, created when missing, without authorization. It is
/// flagged latest only when the project has no latest version yet.
pub(crate) async fn unnamed(
    database: &impl ConnectionTrait,
    project_id: i64,
    created_at: DateTime<FixedOffset>,
) -> Result<project_versions::Model> {
    if let Some(version) = named(database, project_id, UNNAMED).await? {
        return Ok(version);
    }
    let first = latest(database, project_id).await?.is_none();
    insert_unnamed(database, project_id, first, created_at).await
}

/// The latest version of a project, without authorization.
async fn latest(
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
        None => latest(database, project_id).await?,
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
