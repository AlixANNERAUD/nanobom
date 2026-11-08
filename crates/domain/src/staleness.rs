//! Stale projects: those whose SBOM stopped coming. A project is stale when its last upload
//! (or its creation, when nothing was uploaded yet) is older than the configured number of
//! days; 0 disables the feature.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, FixedOffset, Utc};
use nanobom_entity::{organization_webhooks, projects};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};

use crate::error::Result;

/// Identifiers per database query, below SQLite's limit on bound variables.
const QUERY_CHUNK: usize = 500;

/// Whether a project with these dates is stale at `now`.
pub fn is_stale(
    created_at: DateTime<FixedOffset>,
    last_upload_at: Option<DateTime<FixedOffset>>,
    now: DateTime<FixedOffset>,
    stale_after_days: u32,
) -> bool {
    if stale_after_days == 0 {
        return false;
    }
    let reference = last_upload_at.unwrap_or(created_at);
    now - reference > Duration::days(i64::from(stale_after_days))
}

fn project_is_stale(project: &projects::Model, now: DateTime<FixedOffset>, days: u32) -> bool {
    is_stale(project.created_at, project.last_upload_at, now, days)
}

/// Every stale project of the instance.
pub async fn stale_projects(
    database: &impl ConnectionTrait,
    stale_after_days: u32,
) -> Result<Vec<projects::Model>> {
    if stale_after_days == 0 {
        return Ok(Vec::new());
    }
    let now = Utc::now().fixed_offset();
    Ok(projects::Entity::find()
        .all(database)
        .await?
        .into_iter()
        .filter(|project| project_is_stale(project, now, stale_after_days))
        .collect())
}

/// How many projects are stale, for the metrics.
pub async fn stale_count(database: &impl ConnectionTrait, stale_after_days: u32) -> Result<usize> {
    Ok(stale_projects(database, stale_after_days).await?.len())
}

/// The stale projects not yet notified for their current stale period (never notified, or
/// notified before their latest upload), grouped by organization, for the organizations with
/// an enabled webhook.
pub async fn newly_stale(
    database: &impl ConnectionTrait,
    stale_after_days: u32,
) -> Result<BTreeMap<i64, Vec<projects::Model>>> {
    let mut by_organization: BTreeMap<i64, Vec<projects::Model>> = BTreeMap::new();
    for project in stale_projects(database, stale_after_days).await? {
        let pending = match (project.stale_notified_at, project.last_upload_at) {
            (None, _) => true,
            (Some(notified), Some(uploaded)) => notified < uploaded,
            (Some(_), None) => false,
        };
        if pending {
            by_organization
                .entry(project.organization_id)
                .or_default()
                .push(project);
        }
    }
    let identifiers: Vec<i64> = by_organization.keys().copied().collect();
    let mut enabled = Vec::new();
    for chunk in identifiers.chunks(QUERY_CHUNK) {
        enabled.extend(
            organization_webhooks::Entity::find()
                .filter(organization_webhooks::Column::OrganizationId.is_in(chunk.to_vec()))
                .filter(organization_webhooks::Column::Enabled.eq(true))
                .all(database)
                .await?
                .into_iter()
                .map(|webhook| webhook.organization_id),
        );
    }
    by_organization.retain(|organization_id, _| enabled.contains(organization_id));
    Ok(by_organization)
}

/// Records that projects were notified as stale.
pub async fn mark_notified(database: &impl ConnectionTrait, ids: &[i64]) -> Result<()> {
    let now = Utc::now().fixed_offset();
    for chunk in ids.chunks(QUERY_CHUNK) {
        projects::Entity::update_many()
            .col_expr(
                projects::Column::StaleNotifiedAt,
                sea_orm::sea_query::Expr::value(now),
            )
            .filter(projects::Column::Id.is_in(chunk.to_vec()))
            .exec(database)
            .await?;
    }
    Ok(())
}
