//! Projects: a repository, an application or a container image whose SBOM is uploaded by CI.
//!
//! A project belongs to one organization and is identified by its slug within it, as in
//! `/api/organizations/{organization}/projects/{project}/sbom`. Its components are those of its
//! latest upload ([`crate::inventory`]).

use chrono::Utc;
use nanobom_entity::projects;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, ModelTrait,
    QueryFilter, QueryOrder,
};

use crate::{
    access::{Actor, Permission, Reader},
    error::{Error, Result},
    names,
    problem::{Field, Problem},
};

/// The projects of an organization, sorted by slug: only its own for a project token.
/// Requires [`Permission::View`].
pub async fn list(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    organization_id: i64,
) -> Result<Vec<projects::Model>> {
    let reader = reader.into();
    reader
        .authorize(database, organization_id, Permission::View)
        .await?;
    let mut query =
        projects::Entity::find().filter(projects::Column::OrganizationId.eq(organization_id));
    if let Some(project_id) = reader.project_limit() {
        query = query.filter(projects::Column::Id.eq(project_id));
    }
    Ok(query
        .order_by_asc(projects::Column::Slug)
        .all(database)
        .await?)
}

pub(crate) async fn find_model(
    database: &impl ConnectionTrait,
    organization_id: i64,
    slug: &str,
) -> Result<Option<projects::Model>> {
    Ok(projects::Entity::find()
        .filter(projects::Column::OrganizationId.eq(organization_id))
        .filter(projects::Column::Slug.eq(slug.trim().to_ascii_lowercase()))
        .one(database)
        .await?)
}

/// Finds a project of an organization by slug (case-insensitive). Requires
/// [`Permission::View`] in the organization; a missing project, or one outside a project
/// token, is [`Error::NotFound`].
pub async fn find(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    organization_id: i64,
    slug: &str,
) -> Result<projects::Model> {
    let reader = reader.into();
    reader
        .authorize(database, organization_id, Permission::View)
        .await?;
    find_model(database, organization_id, slug)
        .await?
        .filter(|project| reader.reaches_project(project.id))
        .ok_or(Error::NotFound)
}

/// Finds a project by identifier and checks a permission in its organization. This is how
/// functions that take a bare project identifier stay isolated: the organization comes from
/// the project row, never from the caller.
pub(crate) async fn authorize(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    project_id: i64,
    permission: Permission,
) -> Result<projects::Model> {
    let reader = reader.into();
    let project = projects::Entity::find_by_id(project_id)
        .one(database)
        .await?
        .filter(|project| reader.reaches_project(project.id))
        .ok_or(Error::NotFound)?;
    reader
        .authorize(database, project.organization_id, permission)
        .await?;
    Ok(project)
}

/// Inserts a project without checking any permission; the name defaults to the slug.
pub(crate) async fn insert(
    database: &impl ConnectionTrait,
    organization_id: i64,
    slug: &str,
    name: Option<&str>,
) -> Result<projects::Model> {
    let slug = names::slug(Field::ProjectSlug, slug)?;
    let name = match name {
        Some(name) => names::display_name(Field::ProjectName, name)?,
        None => slug.clone(),
    };
    if find_model(database, organization_id, &slug)
        .await?
        .is_some()
    {
        return Err(Error::conflict(Problem::ProjectExists { slug }));
    }
    Ok(projects::ActiveModel {
        organization_id: Set(organization_id),
        slug: Set(slug),
        name: Set(name),
        created_at: Set(Utc::now().fixed_offset()),
        last_upload_at: Set(None),
        ..Default::default()
    }
    .insert(database)
    .await?)
}

/// Creates an empty project; projects are also created by the first upload of an
/// organization-wide token. Requires [`Permission::ManageProjects`]; a taken slug is a
/// [`Problem::ProjectExists`] conflict.
pub async fn create(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
    slug: &str,
    name: &str,
) -> Result<projects::Model> {
    actor
        .authorize(database, organization_id, Permission::ManageProjects)
        .await?;
    insert(database, organization_id, slug, Some(name)).await
}

/// Changes the display name; the slug stays. Requires [`Permission::ManageProjects`].
pub async fn rename(
    database: &impl ConnectionTrait,
    actor: &Actor,
    project_id: i64,
    name: &str,
) -> Result<projects::Model> {
    let project = authorize(database, actor, project_id, Permission::ManageProjects).await?;
    let name = names::display_name(Field::ProjectName, name)?;
    let mut project: projects::ActiveModel = project.into();
    project.name = Set(name);
    Ok(project.update(database).await?)
}

/// Deletes a project with its components, upload history and findings. Requires
/// [`Permission::ManageProjects`]. Upload tokens limited to the project are deleted with it;
/// an organization-wide token that uploads to the same slug again recreates it, empty.
pub async fn delete(database: &impl ConnectionTrait, actor: &Actor, project_id: i64) -> Result<()> {
    let project = authorize(database, actor, project_id, Permission::ManageProjects).await?;
    tracing::info!(project = %project.slug, user = actor.user_id, "project deleted");
    project.delete(database).await?;
    Ok(())
}
