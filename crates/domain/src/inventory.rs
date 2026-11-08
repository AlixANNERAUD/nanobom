//! The component inventory: parsing CycloneDX SBOMs and replacing a project's components with
//! each new upload, keeping the upload history.
//!
//! An upload is a full snapshot: [`ingest`] deletes the project's components and inserts the
//! new ones in one transaction, so a project's components are always those of exactly one SBOM.
//! Findings are not touched here; the next run ([`crate::evaluation`]) compares them with the
//! new components.
//!
//! Components are identified by their package URL (purl), the only identifier OSV can match.
//! Components without a valid purl are counted and reported back to CI as skipped; files and
//! the operating system entry are ignored altogether. Two components with the same purl are
//! stored once.
//!
//! The SBOM's dependency graph is kept with the components, between the components stored: see
//! [`crate::dependencies`] for what is derived from it and how incomplete graphs are handled.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    str::FromStr,
};

use chrono::Utc;
use cyclonedx_bom::{
    models::{
        bom::SpecVersion,
        component::{Classification, Component},
        dependency::Dependency,
    },
    prelude::Bom,
};
use nanobom_entity::{
    component_dependencies, components, organizations, projects, sbom_uploads, upload_tokens,
};
use packageurl::PackageUrl;
use sea_orm::{
    ActiveModelTrait,
    ActiveValue::Set,
    ColumnTrait, ConnectionTrait, EntityTrait, ExprTrait, QueryFilter, QueryOrder, QuerySelect,
    TransactionSession, TransactionTrait,
    sea_query::{Expr, Func, LikeExpr},
};
use serde::{Deserialize, Serialize};

use crate::{
    access::{Actor, Permission},
    error::{Error, Result},
    problem::{Field, Problem},
};

/// Specification versions accepted at upload.
pub const SUPPORTED_SPECIFICATION_VERSIONS: [&str; 5] = ["1.3", "1.4", "1.5", "1.6", "1.7"];

/// At most this many skipped components are listed in an upload's response; all are counted.
const MAXIMUM_LISTED_SKIPPED_COMPONENTS: usize = 100;

/// A component of an SBOM, identified by its package URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryComponent {
    /// The package URL in canonical form, qualifiers included.
    pub purl: String,
    /// The package URL sent to OSV: without qualifiers or subpath.
    pub query_purl: String,
    /// The package URL type: `cargo`, `npm`, `pypi`, `deb`…
    pub ecosystem: String,
    /// The package name, with its namespace when it has one (`@scope/name`, `group/name`).
    pub name: String,
    /// The purl's version; components without one are kept but never matched.
    pub version: Option<String>,
}

/// A component that cannot be tracked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedComponent {
    pub name: String,
    pub version: Option<String>,
    /// Why, in English: no package URL, or why it did not parse.
    pub reason: String,
}

/// The parts of an SBOM nanobom keeps.
#[derive(Debug, Clone)]
pub struct ParsedSbom {
    pub specification_version: String,
    pub serial_number: Option<String>,
    pub components: Vec<InventoryComponent>,
    /// Components without a usable package URL, which cannot be matched against OSV.
    pub skipped_count: usize,
    /// The first skipped components, for the upload's response.
    pub skipped: Vec<SkippedComponent>,
    /// The edges of the SBOM's dependency graph between the components kept, sorted and
    /// without duplicates. Edges to or from a component that is not kept are dropped.
    pub dependencies: Vec<DependencyEdge>,
}

/// An edge of an SBOM's dependency graph, between package URLs in canonical form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DependencyEdge {
    /// The component that depends on `child`; `None` for the project itself (the SBOM's
    /// `metadata.component`).
    pub parent: Option<String>,
    pub child: String,
}

#[derive(Deserialize)]
struct Header {
    #[serde(rename = "bomFormat")]
    format: Option<String>,
    #[serde(rename = "specVersion")]
    specification_version: Option<String>,
}

/// Parses a CycloneDX JSON document. The document is deserialized once, straight into the model
/// of its specification version, to keep memory use low on large SBOMs.
///
/// Errors are [`Error::Invalid`] with a problem that tells CI what is wrong: not JSON, not
/// CycloneDX, a specification version outside [`SUPPORTED_SPECIFICATION_VERSIONS`], or a
/// document that does not follow it. Nested components are flattened.
///
/// The dependency graph is read from `dependencies`, whose references are the `bom-ref` of
/// components; a reference to `metadata.component` is the project.
pub fn parse(document: &[u8]) -> Result<ParsedSbom> {
    let header: Header = serde_json::from_slice(document).map_err(|error| {
        Error::invalid(Problem::SbomNotJson {
            detail: error.to_string(),
        })
    })?;
    if header.format.as_deref() != Some("CycloneDX") {
        return Err(Error::invalid(Problem::SbomNotCycloneDx));
    }
    let specification_version = header.specification_version.unwrap_or_default();
    if !SUPPORTED_SPECIFICATION_VERSIONS.contains(&specification_version.as_str()) {
        return Err(Error::invalid(Problem::UnsupportedSpecificationVersion {
            version: specification_version,
        }));
    }
    let version = SpecVersion::from_str(&specification_version).map_err(|_| {
        Error::invalid(Problem::UnsupportedSpecificationVersion {
            version: specification_version.clone(),
        })
    })?;
    let bom = Bom::parse_from_json_with_version(document, version).map_err(|error| {
        Error::invalid(Problem::InvalidCycloneDx {
            detail: error.to_string(),
        })
    })?;

    let mut parsed = ParsedSbom {
        specification_version,
        serial_number: bom.serial_number.as_ref().map(ToString::to_string),
        components: Vec::new(),
        skipped_count: 0,
        skipped: Vec::new(),
        dependencies: Vec::new(),
    };
    let mut by_purl = BTreeMap::new();
    let mut references = HashMap::new();
    if let Some(components) = &bom.components {
        collect(&components.0, &mut by_purl, &mut references, &mut parsed);
    }
    parsed.components = by_purl.into_values().collect();
    let project = bom
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.component.as_ref())
        .and_then(|component| component.bom_ref.as_ref())
        .map(String::as_str);
    if let Some(dependencies) = &bom.dependencies {
        parsed.dependencies = dependency_edges(&dependencies.0, project, &references);
    }
    Ok(parsed)
}

/// The edges between known components, `references` mapping each kept component's `bom-ref`
/// to its package URL and `project` being the `bom-ref` of the project.
fn dependency_edges(
    dependencies: &[Dependency],
    project: Option<&str>,
    references: &HashMap<String, String>,
) -> Vec<DependencyEdge> {
    let mut edges = BTreeSet::new();
    for dependency in dependencies {
        let parent = if Some(dependency.dependency_ref.as_str()) == project {
            None
        } else {
            match references.get(&dependency.dependency_ref) {
                Some(purl) => Some(purl.clone()),
                None => continue,
            }
        };
        for child in &dependency.dependencies {
            if Some(child.as_str()) == project {
                continue;
            }
            let Some(child) = references.get(child) else {
                continue;
            };
            // Two references can share a package URL, and a package can list itself.
            if parent.as_ref() != Some(child) {
                edges.insert(DependencyEdge {
                    parent: parent.clone(),
                    child: child.clone(),
                });
            }
        }
    }
    edges.into_iter().collect()
}

fn collect(
    components: &[Component],
    by_purl: &mut BTreeMap<String, InventoryComponent>,
    references: &mut HashMap<String, String>,
    parsed: &mut ParsedSbom,
) {
    for component in components {
        // Files and the operating system describe what was scanned; they are not packages.
        let is_package = !matches!(
            component.component_type,
            Classification::File | Classification::OperatingSystem
        );
        if is_package {
            match inventory_component(component) {
                Ok(inventory) => {
                    if let Some(reference) = &component.bom_ref {
                        references.insert(reference.clone(), inventory.purl.clone());
                    }
                    by_purl.entry(inventory.purl.clone()).or_insert(inventory);
                }
                Err(reason) => {
                    parsed.skipped_count += 1;
                    if parsed.skipped.len() < MAXIMUM_LISTED_SKIPPED_COMPONENTS {
                        parsed.skipped.push(SkippedComponent {
                            name: component.name.to_string(),
                            version: component.version.as_ref().map(ToString::to_string),
                            reason,
                        });
                    }
                }
            }
        }
        if let Some(children) = &component.components {
            collect(&children.0, by_purl, references, parsed);
        }
    }
}

fn inventory_component(component: &Component) -> std::result::Result<InventoryComponent, String> {
    let purl = component
        .purl
        .as_ref()
        .ok_or_else(|| "no package URL".to_owned())?;
    let purl = purl.to_string();
    let parsed = PackageUrl::from_str(&purl)
        .map_err(|error| format!("invalid package URL {purl:?}: {error}"))?;
    let mut query = parsed.clone();
    query.clear_qualifiers().without_subpath();
    let name = match parsed.namespace() {
        Some(namespace) => format!("{namespace}/{}", parsed.name()),
        None => parsed.name().to_owned(),
    };
    Ok(InventoryComponent {
        purl: parsed.to_string(),
        query_purl: query.to_string(),
        ecosystem: parsed.ty().to_owned(),
        name,
        version: parsed.version().map(str::to_owned),
    })
}

/// Where an upload comes from, as given by CI. Both labels are free text kept for display: at
/// most 300 characters without control characters; blank values are dropped.
#[derive(Debug, Clone, Default)]
pub struct UploadSource {
    pub source_commit: Option<String>,
    pub image_tag: Option<String>,
}

/// The result of an upload, returned to CI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadOutcome {
    /// The organization slug, normalized.
    pub organization: String,
    /// The project slug, normalized.
    pub project: String,
    pub project_id: i64,
    /// Whether this upload created the project (organization-wide tokens only).
    pub project_created: bool,
    pub upload_id: i64,
    /// Components stored, after removing duplicates.
    pub component_count: usize,
    /// Components skipped for lack of a usable package URL.
    pub components_without_purl: usize,
    /// The first skipped components (at most 100), with the reason.
    pub skipped: Vec<SkippedComponent>,
}

fn optional_label(field: Field, value: Option<String>) -> Result<Option<String>> {
    match value.map(|value| value.trim().to_owned()) {
        Some(value) if value.is_empty() => Ok(None),
        Some(value) if value.chars().count() > 300 || value.chars().any(char::is_control) => {
            Err(Error::invalid(Problem::InvalidLabel(field)))
        }
        other => Ok(other),
    }
}

/// Replaces the components of a project with those of an SBOM uploaded with `token`, creating
/// the project first when the token is organization-wide.
///
/// The token, already authenticated by [`crate::tokens::authenticate`], is the only
/// authorization:
///
/// - an organization other than the token's is [`Error::NotFound`], like a missing one;
/// - a project-scoped token may upload to its own project only: another existing project is
///   [`Error::Forbidden`], a missing one [`Error::NotFound`] (it cannot create projects);
/// - an organization-wide token may upload to any project of its organization and creates
///   missing ones, with the slug as name.
///
/// No run is started; the caller decides whether to evaluate the project now.
pub async fn ingest(
    database: &(impl ConnectionTrait + TransactionTrait),
    token: &upload_tokens::Model,
    organization_slug: &str,
    project_slug: &str,
    sbom: ParsedSbom,
    source: UploadSource,
) -> Result<UploadOutcome> {
    let organization = organizations::Entity::find()
        .filter(organizations::Column::Slug.eq(organization_slug.trim().to_ascii_lowercase()))
        .one(database)
        .await?
        .filter(|organization| organization.id == token.organization_id)
        .ok_or(Error::NotFound)?;
    store(
        database,
        token,
        organization,
        project_slug,
        sbom,
        source,
        true,
    )
    .await
}

/// Like [`ingest`], into the token's own organization, for clients that do not name one (the
/// Dependency-Track API). With `create_missing` false, a missing project is
/// [`Error::NotFound`] even for an organization-wide token.
pub async fn ingest_into_token_organization(
    database: &(impl ConnectionTrait + TransactionTrait),
    token: &upload_tokens::Model,
    project_slug: &str,
    sbom: ParsedSbom,
    source: UploadSource,
    create_missing: bool,
) -> Result<UploadOutcome> {
    let organization = organizations::Entity::find_by_id(token.organization_id)
        .one(database)
        .await?
        .ok_or(Error::NotFound)?;
    store(
        database,
        token,
        organization,
        project_slug,
        sbom,
        source,
        create_missing,
    )
    .await
}

/// The common part of [`ingest`] and [`ingest_into_token_organization`], once the
/// organization is known to be the token's.
async fn store(
    database: &(impl ConnectionTrait + TransactionTrait),
    token: &upload_tokens::Model,
    organization: organizations::Model,
    project_slug: &str,
    sbom: ParsedSbom,
    source: UploadSource,
    create_missing: bool,
) -> Result<UploadOutcome> {
    let source_commit = optional_label(Field::SourceCommit, source.source_commit)?;
    let image_tag = optional_label(Field::ImageTag, source.image_tag)?;
    let transaction = crate::database::begin_write(database).await?;
    let existing = crate::projects::find_model(&transaction, organization.id, project_slug).await?;
    let (project, project_created) = match (existing, token.project_id) {
        (Some(project), None) => (project, false),
        (Some(project), Some(allowed)) if project.id == allowed => (project, false),
        (Some(_), Some(_)) => return Err(Error::Forbidden),
        (None, None) if create_missing => (
            crate::projects::insert(&transaction, organization.id, project_slug, None).await?,
            true,
        ),
        (None, _) => return Err(Error::NotFound),
    };

    let now = Utc::now().fixed_offset();
    // Before the components, which the edges reference.
    component_dependencies::Entity::delete_many()
        .filter(component_dependencies::Column::ProjectId.eq(project.id))
        .exec(&transaction)
        .await?;
    components::Entity::delete_many()
        .filter(components::Column::ProjectId.eq(project.id))
        .exec(&transaction)
        .await?;
    let component_count = sbom.components.len();
    let rows: Vec<components::ActiveModel> = sbom
        .components
        .into_iter()
        .map(|component| components::ActiveModel {
            project_id: Set(project.id),
            purl: Set(component.purl),
            query_purl: Set(component.query_purl),
            ecosystem: Set(component.ecosystem),
            name: Set(component.name),
            version: Set(component.version),
            ..Default::default()
        })
        .collect();
    // Bounded batches stay under the bind parameter limits of every database.
    for batch in rows.chunks(500) {
        components::Entity::insert_many(batch.to_vec())
            .exec(&transaction)
            .await?;
    }
    store_dependencies(&transaction, project.id, &sbom.dependencies).await?;
    let upload = sbom_uploads::ActiveModel {
        project_id: Set(project.id),
        upload_token_id: Set(Some(token.id)),
        uploaded_at: Set(now),
        specification_version: Set(sbom.specification_version),
        serial_number: Set(sbom.serial_number),
        source_commit: Set(source_commit),
        image_tag: Set(image_tag),
        component_count: Set(i64::try_from(component_count).unwrap_or(i64::MAX)),
        components_without_purl: Set(i64::try_from(sbom.skipped_count).unwrap_or(i64::MAX)),
        ..Default::default()
    }
    .insert(&transaction)
    .await?;
    let mut updated: projects::ActiveModel = project.clone().into();
    updated.last_upload_at = Set(Some(now));
    updated.update(&transaction).await?;
    transaction.commit().await?;

    tracing::info!(
        organization = %organization.slug,
        project = %project.slug,
        components = component_count,
        without_purl = sbom.skipped_count,
        "SBOM uploaded"
    );
    Ok(UploadOutcome {
        organization: organization.slug,
        project: project.slug,
        project_id: project.id,
        project_created,
        upload_id: upload.id,
        component_count,
        components_without_purl: sbom.skipped_count,
        skipped: sbom.skipped,
    })
}

/// Stores the dependency graph of a project whose components were just inserted.
async fn store_dependencies(
    database: &impl ConnectionTrait,
    project_id: i64,
    dependencies: &[DependencyEdge],
) -> Result<()> {
    if dependencies.is_empty() {
        return Ok(());
    }
    // Multi-row inserts do not return every identifier on all databases: read them back.
    let identifiers: HashMap<String, i64> = components::Entity::find()
        .filter(components::Column::ProjectId.eq(project_id))
        .all(database)
        .await?
        .into_iter()
        .map(|component| (component.purl, component.id))
        .collect();
    let rows: Vec<component_dependencies::ActiveModel> = dependencies
        .iter()
        .filter_map(|edge| {
            let child = *identifiers.get(&edge.child)?;
            let parent = match &edge.parent {
                Some(purl) => Some(*identifiers.get(purl)?),
                None => None,
            };
            Some(component_dependencies::ActiveModel {
                project_id: Set(project_id),
                parent_component_id: Set(parent),
                child_component_id: Set(child),
                ..Default::default()
            })
        })
        .collect();
    for batch in rows.chunks(1000) {
        component_dependencies::Entity::insert_many(batch.to_vec())
            .exec(database)
            .await?;
    }
    Ok(())
}

/// The upload history of a project, newest first. Requires [`Permission::View`].
pub async fn uploads(
    database: &impl ConnectionTrait,
    actor: &Actor,
    project_id: i64,
) -> Result<Vec<sbom_uploads::Model>> {
    crate::projects::authorize(database, actor, project_id, Permission::View).await?;
    Ok(sbom_uploads::Entity::find()
        .filter(sbom_uploads::Column::ProjectId.eq(project_id))
        .order_by_desc(sbom_uploads::Column::UploadedAt)
        .order_by_desc(sbom_uploads::Column::Id)
        .all(database)
        .await?)
}

/// The current components of a project, sorted by package URL. Requires
/// [`Permission::View`].
pub async fn components(
    database: &impl ConnectionTrait,
    actor: &Actor,
    project_id: i64,
) -> Result<Vec<components::Model>> {
    crate::projects::authorize(database, actor, project_id, Permission::View).await?;
    Ok(components::Entity::find()
        .filter(components::Column::ProjectId.eq(project_id))
        .order_by_asc(components::Column::Purl)
        .all(database)
        .await?)
}

/// A component found by a search.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentMatch {
    pub organization_slug: String,
    pub project_slug: String,
    pub purl: String,
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
}

/// At most this many components are returned by a search.
pub const MAXIMUM_SEARCH_RESULTS: usize = 200;

/// Finds components by name across the organizations the actor can see: `openssl` matches
/// names containing it, `openssl 3.` (or `openssl@3.`) also requires the version to start with
/// `3.`. Names and versions match case-insensitively; `%` and `_` are taken literally.
/// Results are sorted by name then version and capped at [`MAXIMUM_SEARCH_RESULTS`]; an empty
/// name returns nothing rather than every component.
pub async fn search(
    database: &impl ConnectionTrait,
    actor: &Actor,
    query: &str,
) -> Result<Vec<ComponentMatch>> {
    let query = query.trim();
    let (name, version) = match query.split_once(['@', ' ']) {
        Some((name, version)) => (name.trim(), Some(version.trim())),
        None => (query, None),
    };
    if name.is_empty() {
        return Ok(Vec::new());
    }
    let organizations: std::collections::HashMap<i64, String> =
        crate::organizations::list(database, actor)
            .await?
            .into_iter()
            .map(|organization| (organization.id, organization.slug))
            .collect();
    let projects: std::collections::HashMap<i64, (String, String)> = projects::Entity::find()
        .filter(projects::Column::OrganizationId.is_in(organizations.keys().copied()))
        .all(database)
        .await?
        .into_iter()
        .map(|project| {
            let organization = organizations[&project.organization_id].clone();
            (project.id, (organization, project.slug))
        })
        .collect();
    // Names and versions keep their case in package URLs (Maven, Go, `1.0-RC1`), and `LIKE` is
    // case-sensitive on PostgreSQL (and on SQLite for non-ASCII letters), so both sides are
    // compared in lower case.
    let mut select = components::Entity::find()
        .filter(components::Column::ProjectId.is_in(projects.keys().copied()))
        .filter(
            Expr::expr(Func::lower(Expr::col(components::Column::Name))).like(
                LikeExpr::new(format!("%{}%", escape_like(&name.to_lowercase()))).escape('\\'),
            ),
        );
    if let Some(version) = version.filter(|version| !version.is_empty()) {
        select = select.filter(
            Expr::expr(Func::lower(Expr::col(components::Column::Version))).like(
                LikeExpr::new(format!("{}%", escape_like(&version.to_lowercase()))).escape('\\'),
            ),
        );
    }
    let models = select
        .order_by_asc(components::Column::Name)
        .order_by_asc(components::Column::Version)
        // The identifier breaks ties, or which rows the limit keeps would be arbitrary.
        .order_by_asc(components::Column::Id)
        .limit(MAXIMUM_SEARCH_RESULTS as u64)
        .all(database)
        .await?;
    Ok(models
        .into_iter()
        .map(|component| {
            let (organization_slug, project_slug) = projects[&component.project_id].clone();
            ComponentMatch {
                organization_slug,
                project_slug,
                purl: component.purl,
                ecosystem: component.ecosystem,
                name: component.name,
                version: component.version,
            }
        })
        .collect())
}

/// Escapes the wildcards of a `LIKE` pattern, so `_` in a package name matches itself.
fn escape_like(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '%' | '_' | '\\') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}
