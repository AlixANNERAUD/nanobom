//! Organizations. Every project belongs to exactly one organization, and users see only the
//! organizations they are members of (instance administrators see all of them).
//!
//! Manual membership changes never leave an organization without an owner (see
//! [`crate::memberships`]). A user may get a *personal* organization at creation, named after
//! them; it behaves like any other organization. Organizations are also created on the fly from
//! identity provider groups ([`crate::memberships::synchronize`]).

use std::collections::BTreeMap;

use chrono::Utc;
use nanobom_entity::{memberships, organizations};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, ModelTrait,
    QueryFilter, QueryOrder, TransactionSession, TransactionTrait,
};
use serde::{Deserialize, Serialize};

use crate::{
    access::{Actor, Permission, Reader, Role},
    error::{Error, Result},
    memberships::Source,
    names,
    problem::{Field, Problem},
};

/// An organization together with the actor's role in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    pub id: i64,
    pub slug: String,
    pub name: String,
    /// Created along with a user account, rather than by hand or from a group mapping.
    pub is_personal: bool,
    /// The actor's effective role; [`Role::Owner`] for instance administrators.
    pub role: Role,
}

impl Organization {
    fn new(model: organizations::Model, role: Role) -> Self {
        Self {
            id: model.id,
            slug: model.slug,
            name: model.name,
            is_personal: model.is_personal,
            role,
        }
    }
}

/// Creates an organization owned by the actor, through a manual membership. Any signed-in user
/// may do so; a taken slug is a [`Problem::OrganizationExists`] conflict.
pub async fn create(
    database: &(impl ConnectionTrait + TransactionTrait),
    actor: &Actor,
    slug: &str,
    name: &str,
) -> Result<Organization> {
    let slug = names::slug(Field::OrganizationSlug, slug)?;
    let name = names::display_name(Field::OrganizationName, name)?;
    let transaction = crate::database::begin_write(database).await?;
    if find_model_by_slug(&transaction, &slug).await?.is_some() {
        return Err(Error::conflict(Problem::OrganizationExists { slug }));
    }
    let now = Utc::now().fixed_offset();
    let organization = organizations::ActiveModel {
        slug: Set(slug),
        name: Set(name),
        is_personal: Set(false),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(&transaction)
    .await?;
    memberships::ActiveModel {
        organization_id: Set(organization.id),
        user_id: Set(actor.user_id),
        role: Set(Role::Owner.as_str().to_owned()),
        source: Set(Source::Manual.as_str().to_owned()),
        created_at: Set(now),
        ..Default::default()
    }
    .insert(&transaction)
    .await?;
    transaction.commit().await?;
    Ok(Organization::new(organization, Role::Owner))
}

async fn find_model_by_slug(
    database: &impl ConnectionTrait,
    slug: &str,
) -> Result<Option<organizations::Model>> {
    Ok(organizations::Entity::find()
        .filter(organizations::Column::Slug.eq(slug.trim().to_ascii_lowercase()))
        .one(database)
        .await?)
}

/// The organizations the reader can see, sorted by name: a token sees its own, as a
/// [`Role::Viewer`].
pub async fn list(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
) -> Result<Vec<Organization>> {
    let actor = match reader.into() {
        Reader::User(actor) => actor,
        Reader::Token(reach) => {
            return Ok(organizations::Entity::find_by_id(reach.organization_id)
                .one(database)
                .await?
                .map(|model| Organization::new(model, Role::Viewer))
                .into_iter()
                .collect());
        }
    };
    let mut roles: BTreeMap<i64, Role> = BTreeMap::new();
    let memberships = memberships::Entity::find()
        .filter(memberships::Column::UserId.eq(actor.user_id))
        .all(database)
        .await?;
    for membership in memberships {
        let role = Role::parse(&membership.role)?;
        let entry = roles.entry(membership.organization_id).or_insert(role);
        *entry = (*entry).max(role);
    }
    let query = organizations::Entity::find().order_by_asc(organizations::Column::Name);
    let models = if actor.is_instance_administrator {
        query.all(database).await?
    } else {
        query
            .filter(organizations::Column::Id.is_in(roles.keys().copied()))
            .all(database)
            .await?
    };
    Ok(models
        .into_iter()
        .map(|model| {
            let role = if actor.is_instance_administrator {
                Role::Owner
            } else {
                roles[&model.id]
            };
            Organization::new(model, role)
        })
        .collect())
}

/// Finds an organization by slug (case-insensitive). Organizations the reader cannot see are
/// [`Error::NotFound`], like missing ones.
pub async fn find(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    slug: &str,
) -> Result<Organization> {
    let reader = reader.into();
    let model = find_model_by_slug(database, slug)
        .await?
        .ok_or(Error::NotFound)?;
    let role = reader
        .authorize(database, model.id, Permission::View)
        .await?;
    Ok(Organization::new(model, role))
}

/// Changes the display name; the slug, which appears in URLs and upload endpoints, never
/// changes. Requires [`Permission::ManageOrganization`].
pub async fn rename(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
    name: &str,
) -> Result<()> {
    actor
        .authorize(database, organization_id, Permission::ManageOrganization)
        .await?;
    let name = names::display_name(Field::OrganizationName, name)?;
    let model = organizations::Entity::find_by_id(organization_id)
        .one(database)
        .await?
        .ok_or(Error::NotFound)?;
    let mut model: organizations::ActiveModel = model.into();
    model.name = Set(name);
    model.update(database).await?;
    Ok(())
}

/// Deletes an organization with its projects, findings, tokens and memberships (through
/// foreign key cascades). Requires [`Permission::DeleteOrganization`]. A user who still has a
/// synchronized group mapping to the slug gets a new, empty organization at their next
/// sign-in.
pub async fn delete(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
) -> Result<()> {
    actor
        .authorize(database, organization_id, Permission::DeleteOrganization)
        .await?;
    let model = organizations::Entity::find_by_id(organization_id)
        .one(database)
        .await?
        .ok_or(Error::NotFound)?;
    tracing::info!(organization = %model.slug, user = actor.user_id, "organization deleted");
    model.delete(database).await?;
    Ok(())
}
