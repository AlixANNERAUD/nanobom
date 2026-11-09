//! Token scopes: what a token may do within its reach (its organization, or one project).
//!
//! `upload` is what every token did so far (upload SBOMs, import VEX documents, read), so it is
//! the default for existing rows; `read` tokens only read, through the read API.

use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum UploadTokens {
    Table,
    Scope,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(UploadTokens::Table)
                    .add_column(string(UploadTokens::Scope).default("upload"))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(UploadTokens::Table)
                    .drop_column(UploadTokens::Scope)
                    .to_owned(),
            )
            .await
    }
}
