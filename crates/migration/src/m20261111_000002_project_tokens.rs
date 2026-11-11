//! Project upload tokens (see `nanobom_domain::tokens`): the one upload token each project
//! comes with, which its settings show again.
//!
//! A table of its own rather than columns on `upload_tokens`: the primary key makes "one per
//! project" a constraint, which SQLite cannot add to an existing table, and the clear value
//! exists only for these tokens, so it lives only here. The token itself stays an ordinary row of
//! `upload_tokens` (hash, scope, project, last use), so it authenticates like any project token.
//! Renewing it revokes that row and points this one at a new token.
//!
//! The migration creates the table only: the tokens of existing projects need random values and
//! their digests, which `nanobom_domain::database::migrate` issues right after the migrations.

use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Projects {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum UploadTokens {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum ProjectTokens {
    Table,
    ProjectId,
    UploadTokenId,
    Secret,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ProjectTokens::Table)
                    .col(big_integer(ProjectTokens::ProjectId).primary_key())
                    .col(big_integer_uniq(ProjectTokens::UploadTokenId))
                    .col(string(ProjectTokens::Secret))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_project_tokens_project")
                            .from(ProjectTokens::Table, ProjectTokens::ProjectId)
                            .to(Projects::Table, Projects::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_project_tokens_upload_token")
                            .from(ProjectTokens::Table, ProjectTokens::UploadTokenId)
                            .to(UploadTokens::Table, UploadTokens::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ProjectTokens::Table).to_owned())
            .await
    }
}
