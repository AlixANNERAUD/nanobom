//! Machine-readable ignore justifications and ignores made by upload tokens, for VEX.
//!
//! A justification is one of the CycloneDX impact analysis justifications, stored as text and
//! NULL when the member gave only a free-text reason. Findings and their events also record the
//! upload token that ignored them when a VEX document was imported, since no user did.
//!
//! The token columns have no foreign key: SQLite cannot add one to an existing table. A token
//! is only deleted with its organization or project, which deletes the findings and events
//! that name it, so the reference cannot dangle.

use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Findings {
    Table,
    IgnoreJustification,
    IgnoredByUploadTokenId,
}

#[derive(DeriveIden)]
enum FindingEvents {
    Table,
    Justification,
    UploadTokenId,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // One column per statement: SQLite adds a single column per `ALTER TABLE`.
        manager
            .alter_table(
                Table::alter()
                    .table(Findings::Table)
                    .add_column(string_null(Findings::IgnoreJustification))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Findings::Table)
                    .add_column(big_integer_null(Findings::IgnoredByUploadTokenId))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(FindingEvents::Table)
                    .add_column(string_null(FindingEvents::Justification))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(FindingEvents::Table)
                    .add_column(big_integer_null(FindingEvents::UploadTokenId))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(FindingEvents::Table)
                    .drop_column(FindingEvents::UploadTokenId)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(FindingEvents::Table)
                    .drop_column(FindingEvents::Justification)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Findings::Table)
                    .drop_column(Findings::IgnoredByUploadTokenId)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Findings::Table)
                    .drop_column(Findings::IgnoreJustification)
                    .to_owned(),
            )
            .await
    }
}
