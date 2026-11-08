//! The dependency graph of each project's latest SBOM: which component depends on which, and
//! which components the project itself depends on directly.
//!
//! An edge with a null parent starts at the project (the SBOM's `metadata.component`). The
//! edges are replaced with the components at each upload, so they always describe exactly the
//! components of the `components` table. The component foreign keys are indexed: PostgreSQL
//! looks up the referencing edges of every component it deletes.

use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum ComponentDependencies {
    Table,
    Id,
    ProjectId,
    ParentComponentId,
    ChildComponentId,
}

#[derive(DeriveIden)]
enum Projects {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Components {
    Table,
    Id,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ComponentDependencies::Table)
                    .col(big_pk_auto(ComponentDependencies::Id))
                    .col(big_integer(ComponentDependencies::ProjectId))
                    // Null: the project itself depends on the child.
                    .col(big_integer_null(ComponentDependencies::ParentComponentId))
                    .col(big_integer(ComponentDependencies::ChildComponentId))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_component_dependencies_project")
                            .from(
                                ComponentDependencies::Table,
                                ComponentDependencies::ProjectId,
                            )
                            .to(Projects::Table, Projects::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_component_dependencies_parent")
                            .from(
                                ComponentDependencies::Table,
                                ComponentDependencies::ParentComponentId,
                            )
                            .to(Components::Table, Components::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_component_dependencies_child")
                            .from(
                                ComponentDependencies::Table,
                                ComponentDependencies::ChildComponentId,
                            )
                            .to(Components::Table, Components::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        for (name, column) in [
            (
                "index_component_dependencies_project",
                ComponentDependencies::ProjectId,
            ),
            (
                "index_component_dependencies_parent",
                ComponentDependencies::ParentComponentId,
            ),
            (
                "index_component_dependencies_child",
                ComponentDependencies::ChildComponentId,
            ),
        ] {
            manager
                .create_index(
                    Index::create()
                        .name(name)
                        .table(ComponentDependencies::Table)
                        .col(column)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ComponentDependencies::Table).to_owned())
            .await
    }
}
