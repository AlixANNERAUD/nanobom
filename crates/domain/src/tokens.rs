//! API tokens. A token reaches one project, or a whole organization, and has a [`Scope`]:
//!
//! - [`Scope::Upload`] tokens are used by CI to send SBOMs and VEX documents; an organization
//!   token may also create projects on their first upload. They can read too.
//! - [`Scope::Read`] tokens only read, through the read API: scripts and dashboards get a
//!   token that cannot change anything.
//!
//! Whatever the scope, a token reads like a viewer of what it reaches
//! ([`crate::access::Reader`]). The table keeps its historical name, `upload_tokens`.
//!
//! Tokens are 256-bit random values shown once at creation, except [project
//! tokens](#project-tokens). Their SHA-256 digest is what authenticates: a slow password hash is
//! unnecessary for random secrets of this length and would slow every upload down.
//!
//! # Project tokens
//!
//! Every project comes with one upload token of its own, created with the project by every path
//! that creates one ([`crate::projects`]), so a project created in the interface can be uploaded
//! to at once. It is an ordinary project token of scope [`Scope::Upload`] (same row, same
//! authentication, same reach), with two differences:
//!
//! - its clear value is kept, in `project_tokens.secret`, so the project's settings show it again
//!   to those who manage tokens ([`project_token`]). This is the trade-off a CI service such as
//!   Codecov makes, and the one nanobom already makes for webhook URLs (which may embed a secret)
//!   and badge keys: whoever reads the database can upload SBOMs to the project. Named tokens
//!   keep only their digest.
//! - it cannot be revoked, only renewed ([`renew_project_token`]): the old row is revoked and a
//!   new one takes its place, so a project always has exactly one.

use std::collections::HashSet;

use chrono::Utc;
use nanobom_entity::{organizations, project_tokens, projects, upload_tokens};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DbErr, EntityTrait,
    QueryFilter, QueryOrder, TransactionSession, TransactionTrait,
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

/// What a token may do within its reach. Stored as [`Scope::as_str`] in `upload_tokens.scope`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Uploads SBOMs and VEX documents, and reads.
    #[default]
    Upload,
    /// Reads only.
    Read,
}

impl Scope {
    /// Every scope, the default first.
    pub const ALL: [Scope; 2] = [Scope::Upload, Scope::Read];

    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Upload => "upload",
            Scope::Read => "read",
        }
    }

    /// Parses a name produced by [`Scope::as_str`]; anything else is
    /// [`Problem::UnknownTokenScope`].
    pub fn parse(value: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|scope| scope.as_str() == value.trim())
            .ok_or_else(|| {
                Error::invalid(Problem::UnknownTokenScope {
                    scope: value.to_owned(),
                })
            })
    }

    /// The scope of a stored token. An unknown value, never written, reads as
    /// [`Scope::Read`], so it can never upload.
    pub fn of(token: &upload_tokens::Model) -> Self {
        Self::parse(&token.scope).unwrap_or(Scope::Read)
    }
}

/// Refuses tokens that may not upload with [`Error::Forbidden`]. Every path through which a
/// token changes data calls it: SBOM uploads (which may also create projects) and VEX imports.
pub(crate) fn require_upload_scope(token: &upload_tokens::Model) -> Result<()> {
    match Scope::of(token) {
        Scope::Upload => Ok(()),
        Scope::Read => Err(Error::Forbidden),
    }
}

/// A token as shown in lists. It never carries the secret, not even a project token's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadToken {
    pub id: i64,
    pub name: String,
    pub scope: Scope,
    /// The first characters of the token (the prefix and six hexadecimal digits), to recognize
    /// it.
    pub prefix: String,
    /// The project the token is limited to, or `None` for an organization-wide token.
    pub project_slug: Option<String>,
    pub created_at: chrono::DateTime<chrono::FixedOffset>,
    pub last_used_at: Option<chrono::DateTime<chrono::FixedOffset>>,
    pub revoked_at: Option<chrono::DateTime<chrono::FixedOffset>>,
    /// Whether this is the current upload token of its project (see [Project
    /// tokens](self#project-tokens)), which is renewed from the project rather than revoked.
    pub project_token: bool,
}

/// A token with its secret value: a token just created, shown once, or a project's own token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedToken {
    pub token: UploadToken,
    /// The full token. Only a project token's can be read again later.
    pub secret: String,
}

/// The name of every project token, in lists and in the history of what a token changed.
pub const PROJECT_TOKEN_NAME: &str = "Project token";

fn generate_secret() -> String {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).expect("the operating system provides random numbers");
    format!("{PREFIX}{}", hexadecimal(&bytes))
}

pub(crate) fn hexadecimal(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The stored form of a secret: its SHA-256 digest in hexadecimal.
pub(crate) fn digest(secret: &str) -> String {
    hexadecimal(&Sha256::digest(secret.as_bytes()))
}

fn view(
    model: upload_tokens::Model,
    project_slug: Option<String>,
    project_token: bool,
) -> UploadToken {
    UploadToken {
        project_token,
        id: model.id,
        scope: Scope::of(&model),
        name: model.name,
        prefix: model.token_prefix,
        project_slug,
        created_at: model.created_at,
        last_used_at: model.last_used_at,
        revoked_at: model.revoked_at,
    }
}

/// Creates an upload token; see [`create_with_scope`].
pub async fn create(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
    project_slug: Option<&str>,
    name: &str,
) -> Result<CreatedToken> {
    create_with_scope(
        database,
        actor,
        organization_id,
        project_slug,
        name,
        Scope::Upload,
    )
    .await
}

/// Creates a token for an organization, or for one of its projects when `project_slug` is set.
/// Requires [`Permission::ManageUploadTokens`], for read tokens too: a read token sees
/// everything its reach covers; an unknown project is [`Problem::UnknownProject`].
pub async fn create_with_scope(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
    project_slug: Option<&str>,
    name: &str,
    scope: Scope,
) -> Result<CreatedToken> {
    actor
        .authorize(database, organization_id, Permission::ManageUploadTokens)
        .await?;
    insert(
        database,
        organization_id,
        project_slug,
        name,
        scope,
        Some(actor.user_id),
    )
    .await
}

async fn insert(
    database: &impl ConnectionTrait,
    organization_id: i64,
    project_slug: Option<&str>,
    name: &str,
    scope: Scope,
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
    let (model, secret) = insert_row(
        database,
        organization_id,
        project.as_ref().map(|project| project.id),
        name,
        scope,
        created_by,
    )
    .await?;
    Ok(CreatedToken {
        token: view(model, project.map(|project| project.slug), false),
        secret,
    })
}

async fn insert_row(
    database: &impl ConnectionTrait,
    organization_id: i64,
    project_id: Option<i64>,
    name: String,
    scope: Scope,
    created_by: Option<i64>,
) -> std::result::Result<(upload_tokens::Model, String), DbErr> {
    let secret = generate_secret();
    let model = upload_tokens::ActiveModel {
        organization_id: Set(organization_id),
        project_id: Set(project_id),
        name: Set(name),
        scope: Set(scope.as_str().to_owned()),
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
    Ok((model, secret))
}

/// Gives a new project its upload token. Called by [`crate::projects::insert`], inside the
/// transaction that creates the project, so no project is ever seen without one.
pub(crate) async fn issue_project_token(
    database: &impl ConnectionTrait,
    project: &projects::Model,
    created_by: Option<i64>,
) -> std::result::Result<(), DbErr> {
    let (token, secret) = insert_row(
        database,
        project.organization_id,
        Some(project.id),
        PROJECT_TOKEN_NAME.to_owned(),
        Scope::Upload,
        created_by,
    )
    .await?;
    project_tokens::Entity::insert(project_tokens::ActiveModel {
        project_id: Set(project.id),
        upload_token_id: Set(token.id),
        secret: Set(secret),
    })
    .exec(database)
    .await?;
    Ok(())
}

/// Gives every project that has no upload token of its own one; returns how many it issued.
/// [`crate::database::migrate`] calls it after the migrations, for projects created before
/// project tokens existed (a migration cannot draw random values or hash them). It does nothing
/// once every project has its token.
///
/// Several processes may migrate at once (replicas, or `serve` next to a command). The missing
/// projects are read inside the write transaction, which serializes them on SQLite; on PostgreSQL
/// two of them can still race, and the loser's insert fails on the primary key (or on the foreign
/// key of a project deleted meanwhile). A failure after which no project lacks a token is that
/// race, lost to a process that did the work: it is not an error.
pub async fn issue_missing_project_tokens(
    database: &(impl ConnectionTrait + TransactionTrait),
) -> std::result::Result<u64, DbErr> {
    match issue_missing(database).await {
        Ok(issued) => Ok(issued),
        Err(error) => {
            if missing_project_tokens(database).await?.is_empty() {
                Ok(0)
            } else {
                Err(error)
            }
        }
    }
}

async fn issue_missing(
    database: &(impl ConnectionTrait + TransactionTrait),
) -> std::result::Result<u64, DbErr> {
    let transaction = crate::database::begin_write(database).await?;
    let missing = missing_project_tokens(&transaction).await?;
    if missing.is_empty() {
        return Ok(0);
    }
    for project in &missing {
        issue_project_token(&transaction, project, None).await?;
    }
    transaction.commit().await?;
    tracing::info!(
        projects = missing.len(),
        "upload tokens issued to existing projects"
    );
    Ok(missing.len() as u64)
}

/// The projects without a row in `project_tokens`, by an anti-join so that the tokens' secrets
/// are never read.
async fn missing_project_tokens(
    database: &impl ConnectionTrait,
) -> std::result::Result<Vec<projects::Model>, DbErr> {
    projects::Entity::find()
        .filter(
            projects::Column::Id.not_in_subquery(
                sea_orm::sea_query::Query::select()
                    .column(project_tokens::Column::ProjectId)
                    .from(project_tokens::Entity)
                    .to_owned(),
            ),
        )
        .order_by_asc(projects::Column::Id)
        .all(database)
        .await
}

/// The upload token of a project, with its value: what the project's settings show. Requires
/// [`Permission::ManageUploadTokens`]; another organization's project is [`Error::NotFound`].
pub async fn project_token(
    database: &impl ConnectionTrait,
    actor: &Actor,
    project_id: i64,
) -> Result<CreatedToken> {
    let project =
        crate::projects::authorize(database, actor, project_id, Permission::ManageUploadTokens)
            .await?;
    load_project_token(database, project).await
}

async fn load_project_token(
    database: &impl ConnectionTrait,
    project: projects::Model,
) -> Result<CreatedToken> {
    let (row, token) = project_tokens::Entity::find_by_id(project.id)
        .find_also_related(upload_tokens::Entity)
        .one(database)
        .await?
        .ok_or(Error::NotFound)?;
    let token = token.ok_or(Error::NotFound)?;
    Ok(CreatedToken {
        token: view(token, Some(project.slug), true),
        secret: row.secret,
    })
}

/// Replaces a project's upload token and returns the new one: the old value stops working at
/// once (its row is revoked and stays listed, for the record). Requires
/// [`Permission::ManageUploadTokens`]; another organization's project is [`Error::NotFound`].
pub async fn renew_project_token(
    database: &(impl ConnectionTrait + TransactionTrait),
    actor: &Actor,
    project_id: i64,
) -> Result<CreatedToken> {
    let project =
        crate::projects::authorize(database, actor, project_id, Permission::ManageUploadTokens)
            .await?;
    let renewed = renew(database, project, Some(actor.user_id)).await?;
    tracing::info!(
        project = %renewed.token.project_slug.as_deref().unwrap_or_default(),
        user = actor.user_id,
        id = renewed.token.id,
        "project token renewed"
    );
    Ok(renewed)
}

/// Swaps the project's token for a new one in one transaction. The swap only applies if the
/// project still points at the token read first: on PostgreSQL, a renewal running at the same
/// time holds the row until it commits, after which this one matches nothing, rolls back, and
/// returns the token the other one issued, so a project never ends up with two active tokens.
async fn renew(
    database: &(impl ConnectionTrait + TransactionTrait),
    project: projects::Model,
    created_by: Option<i64>,
) -> Result<CreatedToken> {
    use sea_orm::sea_query::Expr;
    let transaction = crate::database::begin_write(database).await?;
    let current = project_tokens::Entity::find_by_id(project.id)
        .one(&transaction)
        .await?
        .ok_or(Error::NotFound)?;
    let (token, secret) = insert_row(
        &transaction,
        project.organization_id,
        Some(project.id),
        PROJECT_TOKEN_NAME.to_owned(),
        Scope::Upload,
        created_by,
    )
    .await?;
    let swapped = project_tokens::Entity::update_many()
        .col_expr(project_tokens::Column::UploadTokenId, Expr::value(token.id))
        .col_expr(project_tokens::Column::Secret, Expr::value(secret.clone()))
        .filter(project_tokens::Column::ProjectId.eq(project.id))
        .filter(project_tokens::Column::UploadTokenId.eq(current.upload_token_id))
        .exec(&transaction)
        .await?;
    if swapped.rows_affected == 0 {
        transaction.rollback().await?;
        return load_project_token(database, project).await;
    }
    upload_tokens::Entity::update_many()
        .col_expr(
            upload_tokens::Column::RevokedAt,
            Expr::value(Utc::now().fixed_offset()),
        )
        .filter(upload_tokens::Column::Id.eq(current.upload_token_id))
        .filter(upload_tokens::Column::RevokedAt.is_null())
        .exec(&transaction)
        .await?;
    transaction.commit().await?;
    Ok(CreatedToken {
        token: view(token, Some(project.slug), true),
        secret,
    })
}

/// Shows a project's upload token from the command line, after renewing it when `renew` is
/// set. Like the other command line functions, it checks no actor.
pub async fn project_token_from_command_line(
    database: &(impl ConnectionTrait + TransactionTrait),
    organization_slug: &str,
    project_slug: &str,
    renew: bool,
) -> Result<CreatedToken> {
    let organization = organization_by_slug(database, organization_slug).await?;
    let project = crate::projects::find_model(database, organization.id, project_slug)
        .await?
        .ok_or_else(|| {
            Error::invalid(Problem::UnknownProject {
                slug: project_slug.to_owned(),
            })
        })?;
    if renew {
        self::renew(database, project, None).await
    } else {
        load_project_token(database, project).await
    }
}

pub(crate) async fn organization_by_slug(
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
    scope: Scope,
) -> Result<CreatedToken> {
    let organization = organization_by_slug(database, organization_slug).await?;
    insert(database, organization.id, project_slug, name, scope, None).await
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
    let project_tokens: HashSet<i64> = project_tokens::Entity::find()
        .filter(
            project_tokens::Column::UploadTokenId
                .is_in(rows.iter().map(|(token, _)| token.id).collect::<Vec<_>>()),
        )
        .all(database)
        .await?
        .into_iter()
        .map(|row| row.upload_token_id)
        .collect();
    Ok(rows
        .into_iter()
        .map(|(token, project)| {
            let project_token = project_tokens.contains(&token.id);
            view(token, project.map(|project| project.slug), project_token)
        })
        .collect())
}

/// Revokes a token; it stops working immediately and stays listed for the record. Revoking a
/// revoked token does nothing. Requires [`Permission::ManageUploadTokens`] in the token's
/// organization. A project's own token is [`Problem::ProjectTokenRevoke`]: it is renewed
/// instead, so the project keeps one.
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
    let is_project_token = project_tokens::Entity::find()
        .filter(project_tokens::Column::UploadTokenId.eq(token.id))
        .one(database)
        .await?
        .is_some();
    if is_project_token {
        return Err(Error::conflict(Problem::ProjectTokenRevoke));
    }
    let mut token: upload_tokens::ActiveModel = token.into();
    token.revoked_at = Set(Some(Utc::now().fixed_offset()));
    token.update(database).await?;
    Ok(())
}

/// How stale `last_used_at` may get before [`authenticate`] writes it again.
///
/// The read API authenticates every request: writing each time would turn reads into writes,
/// which contend for SQLite's single writer lock. The settings page shows the value to the
/// minute at best, so a minute of imprecision costs nothing.
const LAST_USED_RESOLUTION: chrono::Duration = chrono::Duration::minutes(1);

/// Finds the active token matching a secret and records its use in `last_used_at`, when the
/// stored value is a minute old or more (or unset).
///
/// Returns `None` for anything that is not an active token, without saying why, so callers
/// answer every failure the same way. The lookup is by digest, so it does not compare secrets
/// in a timing-sensitive way. The token only authenticates the caller: what it may upload to is
/// checked by [`crate::inventory::ingest`], what it may read by [`crate::access::Reader`].
///
/// Failing to record the use does not fail the request: it is bookkeeping, and a busy database
/// should not turn a valid token away.
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
    let now = Utc::now();
    let recent = token
        .last_used_at
        .is_some_and(|used| now.signed_duration_since(used) < LAST_USED_RESOLUTION);
    if recent {
        return Ok(Some(token));
    }
    let mut active: upload_tokens::ActiveModel = token.clone().into();
    active.last_used_at = Set(Some(now.fixed_offset()));
    match active.update(database).await {
        Ok(updated) => Ok(Some(updated)),
        Err(error) => {
            tracing::warn!(%error, token = token.id, "cannot record the use of a token");
            Ok(Some(token))
        }
    }
}

/// Whether a token returned by [`authenticate`] is still active: not revoked since, nor deleted
/// with its organization or project.
///
/// A request that holds a token for a long time, such as an upload waiting for its evaluation,
/// asks again before answering, so a token revoked meanwhile is not answered with data.
pub async fn is_active(database: &impl ConnectionTrait, token_id: i64) -> Result<bool> {
    Ok(upload_tokens::Entity::find_by_id(token_id)
        .filter(upload_tokens::Column::RevokedAt.is_null())
        .one(database)
        .await?
        .is_some())
}
