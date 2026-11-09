//! Versions of a project (`project_versions`): components, dependency edges, uploads and
//! findings belong to one version of their project rather than to the project itself.
//!
//! Every existing project gets one unnamed version (name `""`), flagged latest, which takes over
//! its last upload time and its partial-graph flag; every row of the four tables is then
//! attached to it. The project keeps `last_upload_at` (the last upload to any of its versions,
//! which staleness is computed from) and loses `dependencies_partial`, which describes one SBOM
//! and so one version.
//!
//! `version_id` is nullable and has no foreign key: SQLite can neither add a `NOT NULL` column
//! without a default nor add a foreign key to an existing table. The domain sets it on every
//! insert (a test checks no row lacks it), and the rows still go with their project through the
//! existing `project_id` cascades.
//!
//! Uniqueness moves from the project to the version: a component is stored once per version,
//! and a finding is one vulnerability of one component in one version. The index on findings'
//! `(project_id, vulnerability_id)` serves views of a vulnerability across a project's
//! versions.

use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum ProjectVersions {
    Table,
    Id,
    ProjectId,
    Name,
    Latest,
    Active,
    CreatedAt,
    LastUploadAt,
    DependenciesPartial,
}

#[derive(DeriveIden)]
enum Projects {
    Table,
    Id,
    DependenciesPartial,
}

/// The tables whose rows belong to a version, with the index each gets on `version_id`.
/// Components and findings get theirs through their unique index instead.
const VERSIONED: [(&str, Option<&str>); 4] = [
    ("components", None),
    (
        "component_dependencies",
        Some("index_component_dependencies_version"),
    ),
    ("sbom_uploads", Some("index_sbom_uploads_version")),
    ("findings", None),
];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ProjectVersions::Table)
                    .col(big_pk_auto(ProjectVersions::Id))
                    .col(big_integer(ProjectVersions::ProjectId))
                    .col(string(ProjectVersions::Name))
                    .col(boolean(ProjectVersions::Latest).default(false))
                    .col(boolean(ProjectVersions::Active).default(true))
                    .col(timestamp_with_time_zone(ProjectVersions::CreatedAt))
                    .col(timestamp_with_time_zone_null(ProjectVersions::LastUploadAt))
                    .col(boolean(ProjectVersions::DependenciesPartial).default(false))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_project_versions_project")
                            .from(ProjectVersions::Table, ProjectVersions::ProjectId)
                            .to(Projects::Table, Projects::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("index_project_versions_project_name")
                    .table(ProjectVersions::Table)
                    .col(ProjectVersions::ProjectId)
                    .col(ProjectVersions::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;

        let connection = manager.get_connection();
        connection
            .execute_unprepared(
                "INSERT INTO project_versions \
                 (project_id, name, latest, active, created_at, last_upload_at, \
                 dependencies_partial) \
                 SELECT id, '', TRUE, TRUE, created_at, last_upload_at, dependencies_partial \
                 FROM projects",
            )
            .await?;

        for (table, index) in VERSIONED {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new(table))
                        .add_column(big_integer_null(Alias::new("version_id")))
                        .to_owned(),
                )
                .await?;
            // Each project has exactly one version at this point.
            connection
                .execute_unprepared(&format!(
                    "UPDATE {table} SET version_id = (SELECT project_versions.id \
                     FROM project_versions WHERE project_versions.project_id = {table}.project_id)"
                ))
                .await?;
            if let Some(index) = index {
                manager
                    .create_index(index_on(index, table, &["version_id"]))
                    .await?;
            }
        }

        manager
            .drop_index(
                Index::drop()
                    .name("index_components_project_purl")
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                index_on(
                    "index_components_version_purl",
                    "components",
                    &["version_id", "purl"],
                )
                .unique()
                .to_owned(),
            )
            .await?;
        // Lookups by project alone used the unique index this replaces.
        manager
            .create_index(index_on(
                "index_components_project",
                "components",
                &["project_id"],
            ))
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("index_findings_project_purl_vulnerability")
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                index_on(
                    "index_findings_version_purl_vulnerability",
                    "findings",
                    &["version_id", "purl", "vulnerability_id"],
                )
                .unique()
                .to_owned(),
            )
            .await?;
        manager
            .create_index(index_on(
                "index_findings_project_vulnerability",
                "findings",
                &["project_id", "vulnerability_id"],
            ))
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Projects::Table)
                    .drop_column(Projects::DependenciesPartial)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        manager
            .alter_table(
                Table::alter()
                    .table(Projects::Table)
                    .add_column(boolean(Projects::DependenciesPartial).default(false))
                    .to_owned(),
            )
            .await?;
        connection
            .execute_unprepared(
                "UPDATE projects SET dependencies_partial = COALESCE((SELECT \
                 project_versions.dependencies_partial FROM project_versions \
                 WHERE project_versions.project_id = projects.id AND project_versions.latest), \
                 FALSE)",
            )
            .await?;
        // A project keeps the rows of its latest version only: the unique indexes restored below
        // allow one component and one finding per project. Edges and finding events go with
        // their components and findings through their foreign keys; uploads have no unique
        // index and are kept.
        for table in ["components", "findings"] {
            connection
                .execute_unprepared(&format!(
                    "DELETE FROM {table} WHERE version_id IS NULL OR version_id NOT IN \
                     (SELECT id FROM project_versions WHERE latest)"
                ))
                .await?;
        }

        for name in [
            "index_findings_project_vulnerability",
            "index_findings_version_purl_vulnerability",
            "index_components_project",
            "index_components_version_purl",
        ] {
            manager
                .drop_index(Index::drop().name(name).to_owned())
                .await?;
        }
        manager
            .create_index(
                index_on(
                    "index_findings_project_purl_vulnerability",
                    "findings",
                    &["project_id", "purl", "vulnerability_id"],
                )
                .unique()
                .to_owned(),
            )
            .await?;
        manager
            .create_index(
                index_on(
                    "index_components_project_purl",
                    "components",
                    &["project_id", "purl"],
                )
                .unique()
                .to_owned(),
            )
            .await?;

        for (table, index) in VERSIONED.into_iter().rev() {
            if let Some(index) = index {
                manager
                    .drop_index(Index::drop().name(index).to_owned())
                    .await?;
            }
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new(table))
                        .drop_column(Alias::new("version_id"))
                        .to_owned(),
                )
                .await?;
        }
        manager
            .drop_table(Table::drop().table(ProjectVersions::Table).to_owned())
            .await
    }
}

fn index_on(name: &str, table: &str, columns: &[&str]) -> IndexCreateStatement {
    let mut statement = Index::create()
        .name(name)
        .table(Alias::new(table))
        .to_owned();
    for column in columns {
        statement.col(Alias::new(*column));
    }
    statement
}
