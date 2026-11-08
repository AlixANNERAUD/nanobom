//! User accounts. Local accounts have a password hash; accounts created through OpenID Connect
//! have an identity instead, and may have both.
//!
//! Usernames and email addresses are unique and stored in lower case. There is no self sign-up:
//! accounts are created by instance administrators, by the command line, or at a first OpenID
//! Connect sign-in. Users are not deleted, only disabled ([`set_disabled`]). Functions that
//! manage other users require an instance administrator; the ones without an actor serve
//! sign-in and the command line, which authenticate the caller themselves.

use chrono::Utc;
use nanobom_entity::{memberships, organizations, user_identities, users};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    QueryOrder, TransactionSession, TransactionTrait,
};

use crate::{
    access::{Actor, Role},
    error::{Error, Result},
    memberships::Source,
    names,
    problem::{Field, Problem},
};

/// A user to create.
#[derive(Debug, Clone, Default)]
pub struct NewUser {
    /// Normalized with [`names::slug`].
    pub username: String,
    pub email: Option<String>,
    /// Defaults to the username when missing or blank.
    pub display_name: Option<String>,
    /// A hash from [`crate::passwords::hash`], never a plain password; `None` for accounts that
    /// sign in through an identity provider only.
    pub password_hash: Option<String>,
    pub is_instance_administrator: bool,
}

/// Creates a user and, when `personal_organization` is set, an organization they own, named
/// after them (with a numeric suffix if the slug is taken).
///
/// No actor is checked: callers are the command line and identity provider sign-in.
/// [`create_as`] is the variant for administrators. A taken username or email address is a
/// conflict.
pub async fn create(
    database: &(impl ConnectionTrait + TransactionTrait),
    user: NewUser,
    personal_organization: bool,
) -> Result<users::Model> {
    let username = names::slug(Field::Username, &user.username)?;
    let email = user.email.as_deref().map(names::email).transpose()?;
    let display_name = match user.display_name.as_deref() {
        Some(name) if !name.trim().is_empty() => names::display_name(Field::DisplayName, name)?,
        _ => username.clone(),
    };

    let transaction = crate::database::begin_write(database).await?;
    if find_by_username(&transaction, &username).await?.is_some() {
        return Err(Error::conflict(Problem::UsernameTaken { username }));
    }
    if let Some(email) = &email
        && find_by_email(&transaction, email).await?.is_some()
    {
        return Err(Error::conflict(Problem::EmailTaken {
            email: email.clone(),
        }));
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

/// Finds a user by identifier, disabled users included.
pub async fn find_by_id(database: &impl ConnectionTrait, id: i64) -> Result<Option<users::Model>> {
    Ok(users::Entity::find_by_id(id).one(database).await?)
}

/// Finds a user by username, case-insensitively; disabled users included.
pub async fn find_by_username(
    database: &impl ConnectionTrait,
    username: &str,
) -> Result<Option<users::Model>> {
    Ok(users::Entity::find()
        .filter(users::Column::Username.eq(username.trim().to_ascii_lowercase()))
        .one(database)
        .await?)
}

/// Finds a user by email address, case-insensitively; disabled users included.
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

/// Sets `last_login_at` to now.
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
        return Err(Error::invalid(Problem::OwnAccountStatus));
    }
    find_by_id(database, user_id).await?.ok_or(Error::NotFound)
}

/// Disables or re-enables a user. Disabled users cannot sign in and their sessions stop working
/// (see [`Actor::load`]). Instance administrators only, and not on their own account, so the
/// last administrator cannot lock themselves out.
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

/// Grants or removes instance administration. Instance administrators only, and not on their
/// own account. For users managed by an identity provider, the next sign-in may undo the change
/// ([`synchronize_instance_administrator`]).
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

/// Sets the password hash of an account: instance administrators reset anyone's password, and
/// users change their own. This function only stores the hash: the caller checks the
/// [`crate::passwords::PasswordPolicy`] and, if it wants one, the current password. Setting a
/// password on an identity provider account also lets it sign in locally.
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

/// Turns a name from an identity provider into a valid username: lower case, with characters
/// outside `[a-z0-9._-]` replaced by `-`.
fn sanitize_username(value: &str) -> Option<String> {
    let mut name: String = value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || "._-".contains(character) {
                character
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = name.trim_start_matches(|character: char| !character.is_ascii_alphanumeric());
    name = trimmed.to_owned();
    name.truncate(names::MAXIMUM_LENGTH - 4);
    names::slug(Field::Username, &name).ok()
}

/// The first free username derived from the candidates (identity provider claims such as the
/// preferred username or the email address), in order, falling back to `user`. Taken names get
/// a numeric suffix: `alice`, `alice-2`… The result can still be taken by a concurrent sign-in,
/// in which case [`create`] reports a conflict.
pub async fn available_username(
    database: &impl ConnectionTrait,
    candidates: &[&str],
) -> Result<String> {
    let base = candidates
        .iter()
        .find_map(|candidate| sanitize_username(candidate))
        .unwrap_or_else(|| "user".to_owned());
    for suffix in 1.. {
        let candidate = if suffix == 1 {
            base.clone()
        } else {
            format!("{base}-{suffix}")
        };
        if find_by_username(database, &candidate).await?.is_none() {
            return Ok(candidate);
        }
    }
    unreachable!("an unbounded range always yields a free username")
}

/// The user linked to an identity provider account, identified by its issuer and subject
/// claims (never by email address, which a provider may let users change).
pub async fn find_by_identity(
    database: &impl ConnectionTrait,
    issuer: &str,
    subject: &str,
) -> Result<Option<users::Model>> {
    let identity = user_identities::Entity::find()
        .filter(user_identities::Column::Issuer.eq(issuer))
        .filter(user_identities::Column::Subject.eq(subject))
        .one(database)
        .await?;
    match identity {
        Some(identity) => find_by_id(database, identity.user_id).await,
        None => Ok(None),
    }
}

/// Creates a user linked to an identity provider account, in one transaction.
pub async fn create_with_identity(
    database: &(impl ConnectionTrait + TransactionTrait),
    user: NewUser,
    personal_organization: bool,
    issuer: &str,
    subject: &str,
) -> Result<users::Model> {
    let transaction = crate::database::begin_write(database).await?;
    let created = create(&transaction, user, personal_organization).await?;
    user_identities::ActiveModel {
        user_id: Set(created.id),
        issuer: Set(issuer.to_owned()),
        subject: Set(subject.to_owned()),
        created_at: Set(Utc::now().fixed_offset()),
        ..Default::default()
    }
    .insert(&transaction)
    .await?;
    transaction.commit().await?;
    Ok(created)
}
