//! The format of an organization's webhook: `json` (the generic document), `slack` or `teams`.
//! Stored as text like the other enumerations; existing webhooks keep sending JSON.

use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum OrganizationWebhooks {
    Table,
    Format,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(OrganizationWebhooks::Table)
                    .add_column(text(OrganizationWebhooks::Format).default("json"))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(OrganizationWebhooks::Table)
                    .drop_column(OrganizationWebhooks::Format)
                    .to_owned(),
            )
            .await
    }
}
