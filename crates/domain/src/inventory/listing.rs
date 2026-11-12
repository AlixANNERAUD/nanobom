//! The components of a project version a page at a time, filtered and sorted by the database,
//! for the interface's components view: an SBOM may list thousands of components, which a
//! page must never load whole.
//!
//! Components are sorted by their worst open finding (components without one last), then by
//! name, version and identifier, so pages never overlap or skip a row. The order and the
//! filters are SQL, through subqueries correlated with each component: findings and components
//! of a version share their package URL.

use std::collections::{HashMap, HashSet};

use nanobom_entity::{
    component_dependencies, components, findings, project_versions, sbom_uploads,
};
use nanobom_osv::Severity;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, ExprTrait, Order, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect,
    sea_query::{Expr, Func, Query, SelectStatement},
};
use serde::{Deserialize, Serialize};

use super::contains_text;
use crate::{access::Reader, error::Result, findings::Status};

/// How many components the interface shows per page.
pub const COMPONENTS_PER_PAGE: u64 = 100;

/// A larger page size asked for is reduced to this.
pub const MAXIMUM_COMPONENTS_PER_PAGE: u64 = 500;

/// A later page asked for is this one, empty unless a version holds half a billion components.
const LAST_PAGE: u64 = 1_000_000;

/// Which components to list, besides the name filter.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentFilter {
    #[default]
    All,
    /// Components with at least one open finding; ignored and fixed ones do not count.
    WithOpenFindings,
    /// Components whose SBOM entry gives no license.
    WithoutLicense,
}

/// A page of a version's components to list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ComponentQuery {
    /// Kept when the name contains this text, case-insensitively (`%` and `_` taken literally,
    /// like [`super::search`]); blank keeps every name.
    pub name: String,
    pub filter: ComponentFilter,
    /// The page, from 1; 0 is the first page too, and pages past the millionth are the
    /// millionth.
    pub page: u64,
    /// Components per page, from 1 to [`MAXIMUM_COMPONENTS_PER_PAGE`]; 0 is
    /// [`COMPONENTS_PER_PAGE`].
    pub per_page: u64,
}

/// How the project depends on a component, per the dependency graph of the version's SBOM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    /// The SBOM lists it among the project's own dependencies.
    Direct,
    /// The SBOM names the project's direct dependencies, and this is not one of them.
    Transitive,
    /// The SBOM does not say which components the project depends on directly (see
    /// [`crate::dependencies`]).
    Unknown,
}

/// A component as listed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListedComponent {
    pub purl: String,
    pub ecosystem: String,
    /// The package name, with its namespace when it has one.
    pub name: String,
    pub version: Option<String>,
    pub license: Option<String>,
    /// Open findings of the component; ignored and fixed ones are left out.
    pub open_findings: u64,
    /// The severity of the worst open finding; `None` without one.
    pub worst_severity: Option<Severity>,
    /// The identifier of the open finding when there is exactly one, to link to it.
    pub only_open_finding: Option<i64>,
    pub dependency: DependencyKind,
}

/// A page of a version's components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentPage {
    pub version: project_versions::Model,
    pub components: Vec<ListedComponent>,
    /// Components of the version matching the query, on every page.
    pub matching: u64,
    /// Components of the version, whatever the query.
    pub total: u64,
    /// Components of the version's latest upload that had no usable package URL, and were
    /// therefore not stored: the SBOM held them, the list cannot.
    pub without_purl: u64,
    /// The page listed, from 1.
    pub page: u64,
    pub per_page: u64,
}

impl ComponentPage {
    /// Whether components matching the query come after this page.
    pub fn has_next(&self) -> bool {
        self.page.saturating_mul(self.per_page) < self.matching
    }
}

/// A page of the components of the version named `version` of a project (`None`: the latest),
/// most severe open finding first, then by name. Requires
/// [`Permission::View`](crate::access::Permission::View); a missing version, or a project the
/// reader cannot see, is [`Error::NotFound`](crate::Error::NotFound).
pub async fn list_components(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    project_id: i64,
    version: Option<&str>,
    query: &ComponentQuery,
) -> Result<ComponentPage> {
    let version = crate::versions::find(database, reader, project_id, version).await?;
    let per_page = match query.per_page {
        0 => COMPONENTS_PER_PAGE,
        size => std::cmp::min(size, MAXIMUM_COMPONENTS_PER_PAGE),
    };
    // Bounded, so that the offset fits the 64-bit signed integers databases take.
    let page = query.page.clamp(1, LAST_PAGE);
    let of_version =
        components::Entity::find().filter(components::Column::VersionId.eq(version.id));
    let total = of_version.clone().count(database).await?;
    let mut select = of_version;
    let name = query.name.trim();
    if !name.is_empty() {
        select = select.filter(contains_text(components::Column::Name, name));
    }
    select = match query.filter {
        ComponentFilter::All => select,
        ComponentFilter::WithOpenFindings => {
            select.filter(Expr::exists(open_findings().expr(Expr::val(1)).to_owned()))
        }
        ComponentFilter::WithoutLicense => select.filter(components::Column::License.is_null()),
    };
    let matching = select.clone().count(database).await?;
    // A page past the last shows the last one, not an empty table that reads as "no match".
    let page = std::cmp::min(page, std::cmp::max(matching.div_ceil(per_page), 1));
    let models = select
        .order_by(worst_rank(), Order::Desc)
        .order_by_asc(components::Column::Name)
        .order_by_asc(components::Column::Version)
        .order_by_asc(components::Column::Id)
        .limit(per_page)
        .offset((page - 1).saturating_mul(per_page))
        .all(database)
        .await?;
    let without_purl = sbom_uploads::Entity::find()
        .filter(sbom_uploads::Column::VersionId.eq(version.id))
        .order_by_desc(sbom_uploads::Column::UploadedAt)
        .order_by_desc(sbom_uploads::Column::Id)
        .one(database)
        .await?
        .map_or(0, |upload| {
            u64::try_from(upload.components_without_purl).unwrap_or_default()
        });
    let components = describe(database, version.id, models).await?;
    Ok(ComponentPage {
        version,
        components,
        matching,
        total,
        without_purl,
        page,
        per_page,
    })
}

/// The open findings of the component of the enclosing query, with nothing selected yet.
fn open_findings() -> SelectStatement {
    Query::select()
        .from(findings::Entity)
        .and_where(
            Expr::col((findings::Entity, findings::Column::VersionId))
                .equals((components::Entity, components::Column::VersionId)),
        )
        .and_where(
            Expr::col((findings::Entity, findings::Column::Purl))
                .equals((components::Entity, components::Column::Purl)),
        )
        .and_where(
            Expr::col((findings::Entity, findings::Column::Status)).eq(Status::Open.as_str()),
        )
        .to_owned()
}

/// The rank of the component's worst open finding: 0 without one, then 1 (unknown severity) to
/// 5 (critical). Severities are stored as text, which does not sort by gravity.
fn worst_rank() -> Expr {
    let severity = || Expr::col((findings::Entity, findings::Column::Severity));
    let rank = Expr::case(severity().eq(Severity::Critical.as_str()), 5)
        .case(severity().eq(Severity::High.as_str()), 4)
        .case(severity().eq(Severity::Medium.as_str()), 3)
        .case(severity().eq(Severity::Low.as_str()), 2)
        .finally(1);
    let worst = open_findings().expr(Func::max(rank)).to_owned();
    Func::coalesce([Expr::SubQuery(None, Box::new(worst.into())), Expr::val(0)]).into()
}

/// The open findings and the place in the dependency graph of a page of components.
///
/// These are separate reads from the page's: an upload between them replaces the components,
/// whose rows then match no edge, and the page shows them as transitive until it is reloaded.
async fn describe(
    database: &impl ConnectionTrait,
    version_id: i64,
    models: Vec<components::Model>,
) -> Result<Vec<ListedComponent>> {
    if models.is_empty() {
        return Ok(Vec::new());
    }
    let mut open: HashMap<String, (u64, Severity, i64)> = HashMap::new();
    let rows = findings::Entity::find()
        .filter(findings::Column::VersionId.eq(version_id))
        .filter(findings::Column::Status.eq(Status::Open.as_str()))
        .filter(findings::Column::Purl.is_in(models.iter().map(|model| model.purl.as_str())))
        .order_by_asc(findings::Column::Id)
        .all(database)
        .await?;
    for finding in rows {
        let severity = finding.severity.parse().unwrap_or(Severity::Unknown);
        open.entry(finding.purl)
            .and_modify(|(count, worst, _)| {
                *count += 1;
                *worst = std::cmp::max(*worst, severity);
            })
            .or_insert((1, severity, finding.id));
    }
    let direct_edges = component_dependencies::Entity::find()
        .filter(component_dependencies::Column::VersionId.eq(version_id))
        .filter(component_dependencies::Column::ParentComponentId.is_null());
    let known = direct_edges.clone().one(database).await?.is_some();
    let direct: HashSet<i64> = if known {
        direct_edges
            .filter(
                component_dependencies::Column::ChildComponentId
                    .is_in(models.iter().map(|model| model.id)),
            )
            .all(database)
            .await?
            .into_iter()
            .map(|edge| edge.child_component_id)
            .collect()
    } else {
        HashSet::new()
    };
    Ok(models
        .into_iter()
        .map(|model| {
            let open = open.get(&model.purl);
            ListedComponent {
                open_findings: open.map_or(0, |(count, _, _)| *count),
                worst_severity: open.map(|(_, worst, _)| *worst),
                only_open_finding: open
                    .filter(|(count, _, _)| *count == 1)
                    .map(|(_, _, id)| *id),
                dependency: if !known {
                    DependencyKind::Unknown
                } else if direct.contains(&model.id) {
                    DependencyKind::Direct
                } else {
                    DependencyKind::Transitive
                },
                purl: model.purl,
                ecosystem: model.ecosystem,
                name: model.name,
                version: model.version,
                license: model.license,
            }
        })
        .collect())
}
