//! User accounts. Local accounts have a password hash; accounts created through OpenID Connect
//! have an identity instead, and may have both.

use chrono::Utc;
use nanobom_entity::{memberships, organizations, users};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    QueryOrder, TransactionSession, TransactionTrait,
};

use crate::{
    access::{Actor, Role},
    error::{Error, Result},
    memberships::Source,
    names,
};

/// A user to create.
#[derive(Debug, Clone, Default)]
pub struct NewUser {
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub password_hash: Option<String>,
    pub is_instance_administrator: bool,
}

/// Creates a user and, when `personal_organization` is set, an organization they own.
pub async fn create(
    database: &(impl ConnectionTrait + TransactionTrait),
    user: NewUser,
    personal_organization: bool,
) -> Result<users::Model> {
    let username = names::slug("the username", &user.username)?;
    let email = user.email.as_deref().map(names::email).transpose()?;
    let display_name = match user.display_name.as_deref() {
        Some(name) if !name.trim().is_empty() => names::display_name("the display name", name)?,
        _ => username.clone(),
    };

    let transaction = database.begin().await?;
    if find_by_username(&transaction, &username).await?.is_some() {
        return Err(Error::conflict(format!(
            "the username {username:?} is taken"
        )));
    }
    if let Some(email) = &email
        && find_by_email(&transaction, email).await?.is_some()
    {
        return Err(Error::conflict(format!(
            "the email address {email:?} is already used"
        )));
    }
    let now = Utc::now().fixed_offset();
    let created = users::ActiveModel {
        username: Set(username.clone()),
        email: Set(email),
        display_name: Set(display_name.clone()),
        password_hash: Set(user.password_hash),
        is_instance_administrator: Set(user.is_instance_administrator),
        is_disabled: Set(false),
        created_at: Set(now),
        last_login_at: Set(None),
        ..Default::default()
    }
    .insert(&transaction)
    .await?;

    if personal_organization {
        let slug = available_organization_slug(&transaction, &username).await?;
        let organization = organizations::ActiveModel {
            slug: Set(slug),
            name: Set(display_name),
            is_personal: Set(true),
            created_at: Set(now),
            ..Default::default()
        }
        .insert(&transaction)
        .await?;
        memberships::ActiveModel {
            organization_id: Set(organization.id),
            user_id: Set(created.id),
            role: Set(Role::Owner.as_str().to_owned()),
            source: Set(Source::Manual.as_str().to_owned()),
            created_at: Set(now),
            ..Default::default()
        }
        .insert(&transaction)
        .await?;
    }
    transaction.commit().await?;
    tracing::info!(user = %created.username, "user created");
    Ok(created)
}

/// Creates a user on behalf of an instance administrator.
pub async fn create_as(
    database: &(impl ConnectionTrait + TransactionTrait),
    actor: &Actor,
    user: NewUser,
    personal_organization: bool,
) -> Result<users::Model> {
    actor.require_instance_administrator()?;
    create(database, user, personal_organization).await
}

/// The first free organization slug among `base`, `base-2`, `base-3`…
pub(crate) async fn available_organization_slug(
    database: &impl ConnectionTrait,
    base: &str,
) -> Result<String> {
    for suffix in 1.. {
        let candidate = if suffix == 1 {
            base.to_owned()
        } else {
            let suffix = format!("-{suffix}");
            let mut prefix = base.to_owned();
            prefix.truncate(names::MAXIMUM_LENGTH - suffix.len());
            format!("{prefix}{suffix}")
        };
        let taken = organizations::Entity::find()
            .filter(organizations::Column::Slug.eq(&candidate))
            .one(database)
            .await?
            .is_some();
        if !taken {
            return Ok(candidate);
        }
    }
    unreachable!("an unbounded range always yields a free slug")
}

pub async fn find_by_id(database: &impl ConnectionTrait, id: i64) -> Result<Option<users::Model>> {
    Ok(users::Entity::find_by_id(id).one(database).await?)
}

pub async fn find_by_username(
    database: &impl ConnectionTrait,
    username: &str,
) -> Result<Option<users::Model>> {
    Ok(users::Entity::find()
        .filter(users::Column::Username.eq(username.trim().to_ascii_lowercase()))
        .one(database)
        .await?)
}

pub async fn find_by_email(
    database: &impl ConnectionTrait,
    email: &str,
) -> Result<Option<users::Model>> {
    Ok(users::Entity::find()
        .filter(users::Column::Email.eq(email.trim().to_lowercase()))
        .one(database)
        .await?)
}

/// Finds a user by username or, when the login contains `@`, by email address.
pub async fn find_by_login(
    database: &impl ConnectionTrait,
    login: &str,
) -> Result<Option<users::Model>> {
    if login.contains('@') {
        find_by_email(database, login).await
    } else {
        find_by_username(database, login).await
    }
}

pub async fn record_login(database: &impl ConnectionTrait, user_id: i64) -> Result<()> {
    users::ActiveModel {
        id: Set(user_id),
        last_login_at: Set(Some(Utc::now().fixed_offset())),
        ..Default::default()
    }
    .update(database)
    .await?;
    Ok(())
}

/// Every user, for instance administrators.
pub async fn list(database: &impl ConnectionTrait, actor: &Actor) -> Result<Vec<users::Model>> {
    actor.require_instance_administrator()?;
    Ok(users::Entity::find()
        .order_by_asc(users::Column::Username)
        .all(database)
        .await?)
}

async fn administered_user(
    database: &impl ConnectionTrait,
    actor: &Actor,
    user_id: i64,
) -> Result<users::Model> {
    actor.require_instance_administrator()?;
    if actor.user_id == user_id {
        return Err(Error::invalid(
            "instance administrators cannot change their own account status",
        ));
    }
    find_by_id(database, user_id).await?.ok_or(Error::NotFound)
}

/// Disables or re-enables a user. Disabled users cannot sign in and their sessions stop working.
pub async fn set_disabled(
    database: &impl ConnectionTrait,
    actor: &Actor,
    user_id: i64,
    disabled: bool,
) -> Result<()> {
    let user = administered_user(database, actor, user_id).await?;
    let mut user: users::ActiveModel = user.into();
    user.is_disabled = Set(disabled);
    user.update(database).await?;
    Ok(())
}

/// Grants or removes instance administration.
pub async fn set_instance_administrator(
    database: &impl ConnectionTrait,
    actor: &Actor,
    user_id: i64,
    administrator: bool,
) -> Result<()> {
    let user = administered_user(database, actor, user_id).await?;
    let mut user: users::ActiveModel = user.into();
    user.is_instance_administrator = Set(administrator);
    user.update(database).await?;
    Ok(())
}

/// Sets the password hash of a local account: instance administrators reset anyone's password,
/// and users change their own.
pub async fn set_password_hash(
    database: &impl ConnectionTrait,
    actor: &Actor,
    user_id: i64,
    password_hash: String,
) -> Result<()> {
    if actor.user_id != user_id {
        actor.require_instance_administrator()?;
    }
    let user = find_by_id(database, user_id)
        .await?
        .ok_or(Error::NotFound)?;
    let mut user: users::ActiveModel = user.into();
    user.password_hash = Set(Some(password_hash));
    user.update(database).await?;
    Ok(())
}

/// Updates the instance administrator flag from an identity provider, without an actor: the
/// provider is the authority for users it manages.
pub async fn synchronize_instance_administrator(
    database: &impl ConnectionTrait,
    user: users::Model,
    administrator: bool,
) -> Result<users::Model> {
    if user.is_instance_administrator == administrator {
        return Ok(user);
    }
    let mut user: users::ActiveModel = user.into();
    user.is_instance_administrator = Set(administrator);
    Ok(user.update(database).await?)
}
