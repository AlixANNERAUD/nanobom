//! Whether a project's dependency graph lost links when its SBOM was uploaded.
//!
//! Edges through a component nanobom does not store (no package URL) or through a `bom-ref`
//! shared by several packages are dropped, so the paths derived from the graph may be missing.
//! The flag is replaced with the graph at each upload and tells the finding page about it. It
//! is a column of its own, in a new migration, because the graph table was already released.

use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Projects {
    Table,
    DependenciesPartial,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Projects::Table)
                    .add_column(boolean(Projects::DependenciesPartial).default(false))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Projects::Table)
                    .drop_column(Projects::DependenciesPartial)
                    .to_owned(),
            )
            .await
    }
}
