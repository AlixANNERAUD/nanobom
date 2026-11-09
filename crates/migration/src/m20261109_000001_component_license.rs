//! The license of each component, as one SPDX license expression read from the SBOM (see
//! `nanobom_domain::inventory`). `NULL` when the SBOM does not give one, and for the components
//! stored before this migration until their project's next upload replaces them.

use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Components {
    Table,
    License,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Components::Table)
                    .add_column(text_null(Components::License))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Components::Table)
                    .drop_column(Components::License)
                    .to_owned(),
            )
            .await
    }
}
