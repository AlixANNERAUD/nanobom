//! Projects: a repository, an application or a container image whose SBOM is uploaded by CI.

use chrono::Utc;
use nanobom_entity::projects;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, ModelTrait,
    QueryFilter, QueryOrder,
};

use crate::{
    access::{Actor, Permission},
    error::{Error, Result},
    names,
};

/// The projects of an organization, sorted by slug.
pub async fn list(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
) -> Result<Vec<projects::Model>> {
    actor
        .authorize(database, organization_id, Permission::View)
        .await?;
    Ok(projects::Entity::find()
        .filter(projects::Column::OrganizationId.eq(organization_id))
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

/// Finds a project of an organization by slug.
pub async fn find(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
    slug: &str,
) -> Result<projects::Model> {
    actor
        .authorize(database, organization_id, Permission::View)
        .await?;
    find_model(database, organization_id, slug)
        .await?
        .ok_or(Error::NotFound)
}

/// Finds a project by identifier and checks a permission in its organization.
pub(crate) async fn authorize(
    database: &impl ConnectionTrait,
    actor: &Actor,
    project_id: i64,
    permission: Permission,
) -> Result<projects::Model> {
    let project = projects::Entity::find_by_id(project_id)
        .one(database)
        .await?
        .ok_or(Error::NotFound)?;
    actor
        .authorize(database, project.organization_id, permission)
        .await?;
    Ok(project)
}

pub(crate) async fn insert(
    database: &impl ConnectionTrait,
    organization_id: i64,
    slug: &str,
    name: Option<&str>,
) -> Result<projects::Model> {
    let slug = names::slug("the project slug", slug)?;
    let name = match name {
        Some(name) => names::display_name("the project name", name)?,
        None => slug.clone(),
    };
    if find_model(database, organization_id, &slug)
        .await?
        .is_some()
    {
        return Err(Error::conflict(format!(
            "the project {slug:?} already exists"
        )));
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
/// organization-wide token.
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

pub async fn rename(
    database: &impl ConnectionTrait,
    actor: &Actor,
    project_id: i64,
    name: &str,
) -> Result<projects::Model> {
    let project = authorize(database, actor, project_id, Permission::ManageProjects).await?;
    let name = names::display_name("the project name", name)?;
    let mut project: projects::ActiveModel = project.into();
    project.name = Set(name);
    Ok(project.update(database).await?)
}

/// Deletes a project with its components, upload history and findings.
pub async fn delete(database: &impl ConnectionTrait, actor: &Actor, project_id: i64) -> Result<()> {
    let project = authorize(database, actor, project_id, Permission::ManageProjects).await?;
    tracing::info!(project = %project.slug, user = actor.user_id, "project deleted");
    project.delete(database).await?;
    Ok(())
}
