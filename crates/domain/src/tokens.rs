//! Upload tokens, used by CI to send SBOMs. A token is scoped to one project, or to a whole
//! organization, in which case it may also create projects on their first upload.
//!
//! Tokens are 256-bit random values shown once at creation. Only their SHA-256 digest is stored:
//! a slow password hash is unnecessary for random secrets of this length and would slow every
//! upload down.

use chrono::Utc;
use nanobom_entity::{organizations, projects, upload_tokens};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    QueryOrder,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    access::{Actor, Permission},
    error::{Error, Result},
    names,
    problem::{Field, Problem},
};

/// Every token starts with this prefix, so leaked tokens are easy to recognize and search for.
pub const PREFIX: &str = "nanobom_";
const DISPLAYED_CHARACTERS: usize = PREFIX.len() + 6;

/// An upload token as shown in the interface; the secret itself is never stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadToken {
    pub id: i64,
    pub name: String,
    /// The first characters of the token (the prefix and six hexadecimal digits), to recognize
    /// it.
    pub prefix: String,
    /// The project the token is limited to, or `None` for an organization-wide token.
    pub project_slug: Option<String>,
    pub created_at: chrono::DateTime<chrono::FixedOffset>,
    pub last_used_at: Option<chrono::DateTime<chrono::FixedOffset>>,
    pub revoked_at: Option<chrono::DateTime<chrono::FixedOffset>>,
}

/// A token that was just created, with its secret value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedToken {
    pub token: UploadToken,
    /// The full token, to show once: it cannot be recovered later.
    pub secret: String,
}

fn generate_secret() -> String {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).expect("the operating system provides random numbers");
    format!("{PREFIX}{}", hexadecimal(&bytes))
}

fn hexadecimal(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The stored form of a secret: its SHA-256 digest in hexadecimal.
pub(crate) fn digest(secret: &str) -> String {
    hexadecimal(&Sha256::digest(secret.as_bytes()))
}

fn view(model: upload_tokens::Model, project_slug: Option<String>) -> UploadToken {
    UploadToken {
        id: model.id,
        name: model.name,
        prefix: model.token_prefix,
        project_slug,
        created_at: model.created_at,
        last_used_at: model.last_used_at,
        revoked_at: model.revoked_at,
    }
}

/// Creates a token for an organization, or for one of its projects when `project_slug` is set.
/// Requires [`Permission::ManageUploadTokens`]; an unknown project is
/// [`Problem::UnknownProject`].
pub async fn create(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
    project_slug: Option<&str>,
    name: &str,
) -> Result<CreatedToken> {
    actor
        .authorize(database, organization_id, Permission::ManageUploadTokens)
        .await?;
    insert(
        database,
        organization_id,
        project_slug,
        name,
        Some(actor.user_id),
    )
    .await
}

async fn insert(
    database: &impl ConnectionTrait,
    organization_id: i64,
    project_slug: Option<&str>,
    name: &str,
    created_by: Option<i64>,
) -> Result<CreatedToken> {
    let name = names::display_name(Field::TokenName, name)?;
    let project = match project_slug {
        Some(slug) => Some(
            crate::projects::find_model(database, organization_id, slug)
                .await?
                .ok_or_else(|| {
                    Error::invalid(Problem::UnknownProject {
                        slug: slug.to_owned(),
                    })
                })?,
        ),
        None => None,
    };
    let secret = generate_secret();
    let model = upload_tokens::ActiveModel {
        organization_id: Set(organization_id),
        project_id: Set(project.as_ref().map(|project| project.id)),
        name: Set(name),
        token_hash: Set(digest(&secret)),
        token_prefix: Set(secret[..DISPLAYED_CHARACTERS].to_owned()),
        created_by_user_id: Set(created_by),
        created_at: Set(Utc::now().fixed_offset()),
        last_used_at: Set(None),
        revoked_at: Set(None),
        ..Default::default()
    }
    .insert(database)
    .await?;
    Ok(CreatedToken {
        token: view(model, project.map(|project| project.slug)),
        secret,
    })
}

async fn organization_by_slug(
    database: &impl ConnectionTrait,
    slug: &str,
) -> Result<organizations::Model> {
    organizations::Entity::find()
        .filter(organizations::Column::Slug.eq(slug.trim().to_ascii_lowercase()))
        .one(database)
        .await?
        .ok_or_else(|| {
            Error::invalid(Problem::UnknownOrganization {
                slug: slug.to_owned(),
            })
        })
}

/// Creates a token from the command line, which has direct access to the database: no actor
/// is checked and the token has no creator.
pub async fn create_from_command_line(
    database: &impl ConnectionTrait,
    organization_slug: &str,
    project_slug: Option<&str>,
    name: &str,
) -> Result<CreatedToken> {
    let organization = organization_by_slug(database, organization_slug).await?;
    insert(database, organization.id, project_slug, name, None).await
}

/// Lists the tokens of an organization from the command line.
pub async fn list_from_command_line(
    database: &impl ConnectionTrait,
    organization_slug: &str,
) -> Result<Vec<UploadToken>> {
    let organization = organization_by_slug(database, organization_slug).await?;
    list_models(database, organization.id).await
}

/// Revokes a token from the command line.
pub async fn revoke_from_command_line(
    database: &impl ConnectionTrait,
    token_id: i64,
) -> Result<()> {
    let token = upload_tokens::Entity::find_by_id(token_id)
        .one(database)
        .await?
        .ok_or(Error::NotFound)?;
    mark_revoked(database, token).await
}

/// The tokens of an organization, newest first, including revoked ones. Requires
/// [`Permission::ManageUploadTokens`]: viewers and members do not see them.
pub async fn list(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
) -> Result<Vec<UploadToken>> {
    actor
        .authorize(database, organization_id, Permission::ManageUploadTokens)
        .await?;
    list_models(database, organization_id).await
}

async fn list_models(
    database: &impl ConnectionTrait,
    organization_id: i64,
) -> Result<Vec<UploadToken>> {
    let rows = upload_tokens::Entity::find()
        .filter(upload_tokens::Column::OrganizationId.eq(organization_id))
        .find_also_related(projects::Entity)
        .order_by_desc(upload_tokens::Column::CreatedAt)
        .order_by_desc(upload_tokens::Column::Id)
        .all(database)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(token, project)| view(token, project.map(|project| project.slug)))
        .collect())
}

/// Revokes a token; it stops working immediately and stays listed for the record. Revoking a
/// revoked token does nothing. Requires [`Permission::ManageUploadTokens`] in the token's
/// organization.
pub async fn revoke(database: &impl ConnectionTrait, actor: &Actor, token_id: i64) -> Result<()> {
    let token = upload_tokens::Entity::find_by_id(token_id)
        .one(database)
        .await?
        .ok_or(Error::NotFound)?;
    actor
        .authorize(
            database,
            token.organization_id,
            Permission::ManageUploadTokens,
        )
        .await?;
    mark_revoked(database, token).await
}

async fn mark_revoked(database: &impl ConnectionTrait, token: upload_tokens::Model) -> Result<()> {
    if token.revoked_at.is_some() {
        return Ok(());
    }
    let mut token: upload_tokens::ActiveModel = token.into();
    token.revoked_at = Set(Some(Utc::now().fixed_offset()));
    token.update(database).await?;
    Ok(())
}

/// Finds the active token matching a secret and records its use in `last_used_at`.
///
/// Returns `None` for anything that is not an active token, without saying why, so callers
/// answer every failure the same way. The lookup is by digest, so it does not compare secrets
/// in a timing-sensitive way. The token only authenticates the caller: what it may upload to is
/// checked by [`crate::inventory::ingest`].
pub async fn authenticate(
    database: &impl ConnectionTrait,
    secret: &str,
) -> Result<Option<upload_tokens::Model>> {
    if !secret.starts_with(PREFIX) {
        return Ok(None);
    }
    let Some(token) = upload_tokens::Entity::find()
        .filter(upload_tokens::Column::TokenHash.eq(digest(secret)))
        .filter(upload_tokens::Column::RevokedAt.is_null())
        .one(database)
        .await?
    else {
        return Ok(None);
    };
    let mut active: upload_tokens::ActiveModel = token.clone().into();
    active.last_used_at = Set(Some(Utc::now().fixed_offset()));
    Ok(Some(active.update(database).await?))
}
