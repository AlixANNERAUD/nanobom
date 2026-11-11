//! Project badges: a small public image of a project version's open findings, for a README.
//!
//! nanobom data is private, so a badge is off until someone who manages projects turns it on
//! ([`enable`]). Turning it on draws a random **key**; the badge is served at an address made of
//! the key alone, with no organization or project name, so the address tells nothing beyond the
//! counts it shows. Whoever holds the key reads [`summary`] and nothing else. [`enable`] again
//! replaces the key, so the old address stops working at once; [`disable`] removes it, and
//! deleting the project removes it too.
//!
//! The key is stored in clear, unlike upload tokens: it only unlocks what the badge shows anyway,
//! and the settings must show the address again later.

use chrono::Utc;
use nanobom_entity::project_badges;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, sea_query::OnConflict,
};
use serde::{Deserialize, Serialize};

use crate::{
    access::{Actor, Permission},
    error::{Error, Result},
    findings::OpenSummary,
};

/// Random bytes in a key: 128 bits, written as 32 lowercase hexadecimal digits.
const KEY_BYTES: usize = 16;

/// What a badge shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Summary {
    /// The version has never received an SBOM: a project created in the interface and not
    /// uploaded to yet. Its zero counts would read as "no vulnerabilities", which is not known.
    NoSbom,
    /// The open findings of the version, as [`crate::findings::open_summary_in_version`] counts
    /// them: ignored and fixed findings do not count.
    Findings(OpenSummary),
}

fn generate_key() -> String {
    let mut bytes = [0_u8; KEY_BYTES];
    getrandom::fill(&mut bytes).expect("the operating system provides random numbers");
    crate::tokens::hexadecimal(&bytes)
}

/// The key of a project's badge, `None` while it is off. Requires
/// [`Permission::ManageProjects`]: the key gives the badge's address, which those who manage
/// the project decide to publish.
pub async fn key(
    database: &impl ConnectionTrait,
    actor: &Actor,
    project_id: i64,
) -> Result<Option<String>> {
    crate::projects::authorize(database, actor, project_id, Permission::ManageProjects).await?;
    Ok(project_badges::Entity::find_by_id(project_id)
        .one(database)
        .await?
        .map(|badge| badge.key))
}

/// Turns a project's badge on with a new key and returns it; when it is already on, the new key
/// replaces the old one, whose address stops working at once. Requires
/// [`Permission::ManageProjects`].
pub async fn enable(
    database: &impl ConnectionTrait,
    actor: &Actor,
    project_id: i64,
) -> Result<String> {
    let project =
        crate::projects::authorize(database, actor, project_id, Permission::ManageProjects).await?;
    let replaced = project_badges::Entity::find_by_id(project_id)
        .one(database)
        .await?
        .is_some();
    let key = generate_key();
    // An upsert, so two concurrent requests both succeed and the last key wins.
    project_badges::Entity::insert(project_badges::ActiveModel {
        project_id: Set(project_id),
        key: Set(key.clone()),
        created_at: Set(Utc::now().fixed_offset()),
    })
    .on_conflict(
        OnConflict::column(project_badges::Column::ProjectId)
            .update_columns([
                project_badges::Column::Key,
                project_badges::Column::CreatedAt,
            ])
            .to_owned(),
    )
    .exec(database)
    .await?;
    // The key itself is never logged: it is the badge's only authorization.
    if replaced {
        tracing::info!(project = %project.slug, user = actor.user_id, "badge address replaced");
    } else {
        tracing::info!(project = %project.slug, user = actor.user_id, "badge turned on");
    }
    Ok(key)
}

/// Turns a project's badge off: its address stops working. Turning off a badge that is off
/// does nothing. Requires [`Permission::ManageProjects`].
pub async fn disable(
    database: &impl ConnectionTrait,
    actor: &Actor,
    project_id: i64,
) -> Result<()> {
    let project =
        crate::projects::authorize(database, actor, project_id, Permission::ManageProjects).await?;
    let deleted = project_badges::Entity::delete_by_id(project_id)
        .exec(database)
        .await?;
    if deleted.rows_affected > 0 {
        tracing::info!(project = %project.slug, user = actor.user_id, "badge turned off");
    }
    Ok(())
}

/// What the badge with this key shows for the version named `version` (`None`: the latest).
///
/// Takes no actor: like an upload token, the key is the caller's authorization, and it only
/// unlocks this summary. An unknown key and an unknown version are both [`Error::NotFound`], so
/// a caller cannot tell which part was wrong.
pub async fn summary(
    database: &impl ConnectionTrait,
    key: &str,
    version: Option<&str>,
) -> Result<Summary> {
    // Anything that is not a key cannot match one; this spares the database a lookup.
    let well_formed = key.len() == KEY_BYTES * 2
        && key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !well_formed {
        return Err(Error::NotFound);
    }
    let badge = project_badges::Entity::find()
        .filter(project_badges::Column::Key.eq(key))
        .one(database)
        .await?
        .ok_or(Error::NotFound)?;
    let version = crate::versions::select(database, badge.project_id, version).await?;
    if version.last_upload_at.is_none() {
        return Ok(Summary::NoSbom);
    }
    Ok(Summary::Findings(
        crate::findings::open_summary_of(database, version.id).await?,
    ))
}
