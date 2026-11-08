//! Members of organizations and their roles.
//!
//! A user can hold two memberships in the same organization: a manual one, managed by the
//! organization's admins, and a synchronized one, derived from identity provider groups at each
//! sign-in. They are stored apart so a sign-in never overwrites a manual change; the effective
//! role is the higher of the two.

use std::collections::BTreeMap;

use chrono::Utc;
use nanobom_entity::{memberships, organizations, users};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, ModelTrait,
    QueryFilter, TransactionSession, TransactionTrait,
};
use serde::{Deserialize, Serialize};

use crate::{
    access::{Actor, Permission, Role},
    error::{Error, Result},
    names,
    problem::{Field, Problem},
    users as user_accounts,
};

/// Where a membership comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// Added in the interface or the command line.
    Manual,
    /// Derived from the identity provider's groups at sign-in.
    Synchronized,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Manual => "manual",
            Source::Synchronized => "synchronized",
        }
    }
}

/// A member of an organization as shown to its admins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub user_id: i64,
    pub username: String,
    pub display_name: String,
    pub email: Option<String>,
    /// The higher of the manual and synchronized roles.
    pub role: Role,
    pub manual_role: Option<Role>,
    pub synchronized_role: Option<Role>,
}

/// The members of an organization, sorted by username.
pub async fn list(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
) -> Result<Vec<Member>> {
    actor
        .authorize(database, organization_id, Permission::View)
        .await?;
    let rows = memberships::Entity::find()
        .filter(memberships::Column::OrganizationId.eq(organization_id))
        .find_also_related(users::Entity)
        .all(database)
        .await?;
    let mut members: BTreeMap<String, Member> = BTreeMap::new();
    for (membership, user) in rows {
        let Some(user) = user else { continue };
        let role = Role::parse(&membership.role)?;
        let member = members
            .entry(user.username.clone())
            .or_insert_with(|| Member {
                user_id: user.id,
                username: user.username.clone(),
                display_name: user.display_name.clone(),
                email: user.email.clone(),
                role,
                manual_role: None,
                synchronized_role: None,
            });
        if membership.source == Source::Synchronized.as_str() {
            member.synchronized_role = Some(role);
        } else {
            member.manual_role = Some(role);
        }
        member.role = member.role.max(role);
    }
    Ok(members.into_values().collect())
}

/// Checks that the actor may give or take away `role`: admins manage roles up to admin, owners
/// also manage owners.
async fn authorize_role_change(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
    roles: &[Option<Role>],
) -> Result<()> {
    let permission = if roles.contains(&Some(Role::Owner)) {
        Permission::ManageOwners
    } else {
        Permission::ManageMembers
    };
    actor
        .authorize(database, organization_id, permission)
        .await?;
    Ok(())
}

async fn manual_membership(
    database: &impl ConnectionTrait,
    organization_id: i64,
    user_id: i64,
) -> Result<Option<memberships::Model>> {
    Ok(memberships::Entity::find()
        .filter(memberships::Column::OrganizationId.eq(organization_id))
        .filter(memberships::Column::UserId.eq(user_id))
        .filter(memberships::Column::Source.eq(Source::Manual.as_str()))
        .one(database)
        .await?)
}

/// Fails if the organization would be left without any owner.
async fn ensure_an_owner_remains(
    database: &impl ConnectionTrait,
    organization_id: i64,
) -> Result<()> {
    let owners = memberships::Entity::find()
        .filter(memberships::Column::OrganizationId.eq(organization_id))
        .filter(memberships::Column::Role.eq(Role::Owner.as_str()))
        .one(database)
        .await?;
    if owners.is_none() {
        return Err(Error::conflict(Problem::LastOwner));
    }
    Ok(())
}

/// Adds an existing user, found by username or email address, to an organization.
pub async fn add(
    database: &(impl ConnectionTrait + TransactionTrait),
    actor: &Actor,
    organization_id: i64,
    login: &str,
    role: Role,
) -> Result<Member> {
    authorize_role_change(database, actor, organization_id, &[Some(role)]).await?;
    let user = user_accounts::find_by_login(database, login)
        .await?
        .ok_or_else(|| {
            Error::invalid(Problem::UnknownUser {
                login: login.trim().to_owned(),
            })
        })?;
    if manual_membership(database, organization_id, user.id)
        .await?
        .is_some()
    {
        return Err(Error::conflict(Problem::AlreadyMember {
            username: user.username,
        }));
    }
    memberships::ActiveModel {
        organization_id: Set(organization_id),
        user_id: Set(user.id),
        role: Set(role.as_str().to_owned()),
        source: Set(Source::Manual.as_str().to_owned()),
        created_at: Set(Utc::now().fixed_offset()),
        ..Default::default()
    }
    .insert(database)
    .await?;
    member(database, actor, organization_id, user.id).await
}

async fn member(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
    user_id: i64,
) -> Result<Member> {
    list(database, actor, organization_id)
        .await?
        .into_iter()
        .find(|member| member.user_id == user_id)
        .ok_or(Error::NotFound)
}

/// Changes the manual role of a member.
pub async fn set_role(
    database: &(impl ConnectionTrait + TransactionTrait),
    actor: &Actor,
    organization_id: i64,
    user_id: i64,
    role: Role,
) -> Result<Member> {
    let transaction = database.begin().await?;
    let membership = manual_membership(&transaction, organization_id, user_id).await?;
    let current = membership
        .as_ref()
        .map(|membership| Role::parse(&membership.role))
        .transpose()?;
    authorize_role_change(&transaction, actor, organization_id, &[current, Some(role)]).await?;
    let membership = membership.ok_or(Error::NotFound)?;
    let mut membership: memberships::ActiveModel = membership.into();
    membership.role = Set(role.as_str().to_owned());
    membership.update(&transaction).await?;
    ensure_an_owner_remains(&transaction, organization_id).await?;
    transaction.commit().await?;
    member(database, actor, organization_id, user_id).await
}

/// Removes the manual membership of a user. Members may also leave on their own.
pub async fn remove(
    database: &(impl ConnectionTrait + TransactionTrait),
    actor: &Actor,
    organization_id: i64,
    user_id: i64,
) -> Result<()> {
    let transaction = database.begin().await?;
    let membership = manual_membership(&transaction, organization_id, user_id).await?;
    let current = membership
        .as_ref()
        .map(|membership| Role::parse(&membership.role))
        .transpose()?;
    if actor.user_id == user_id && membership.is_some() {
        actor
            .authorize(&transaction, organization_id, Permission::View)
            .await?;
    } else {
        authorize_role_change(&transaction, actor, organization_id, &[current]).await?;
    }
    let membership = membership.ok_or(Error::NotFound)?;
    membership.delete(&transaction).await?;
    ensure_an_owner_remains(&transaction, organization_id).await?;
    transaction.commit().await?;
    Ok(())
}

/// Replaces the synchronized memberships of a user with `roles`, keyed by organization slug.
/// Organizations that do not exist yet are created. Manual memberships are left untouched.
pub async fn synchronize(
    database: &(impl ConnectionTrait + TransactionTrait),
    user_id: i64,
    roles: &BTreeMap<String, Role>,
) -> Result<()> {
    let transaction = database.begin().await?;
    memberships::Entity::delete_many()
        .filter(memberships::Column::UserId.eq(user_id))
        .filter(memberships::Column::Source.eq(Source::Synchronized.as_str()))
        .exec(&transaction)
        .await?;
    let now = Utc::now().fixed_offset();
    for (slug, role) in roles {
        let slug = names::slug(Field::OrganizationSlug, slug)?;
        let organization = match organizations::Entity::find()
            .filter(organizations::Column::Slug.eq(&slug))
            .one(&transaction)
            .await?
        {
            Some(organization) => organization,
            None => {
                tracing::info!(organization = %slug, "organization created from group mapping");
                organizations::ActiveModel {
                    slug: Set(slug.clone()),
                    name: Set(slug.clone()),
                    is_personal: Set(false),
                    created_at: Set(now),
                    ..Default::default()
                }
                .insert(&transaction)
                .await?
            }
        };
        memberships::ActiveModel {
            organization_id: Set(organization.id),
            user_id: Set(user_id),
            role: Set(role.as_str().to_owned()),
            source: Set(Source::Synchronized.as_str().to_owned()),
            created_at: Set(now),
            ..Default::default()
        }
        .insert(&transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}
