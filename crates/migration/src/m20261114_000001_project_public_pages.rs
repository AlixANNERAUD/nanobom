//! Public pages of projects (see `nanobom_domain::public_pages`): the key of each project's
//! public page.
//!
//! A table of its own, like `project_badges`, rather than a second key on that table: the page
//! and the badge are published independently, so turning one on, renewing or revoking it never
//! touches the other. A row exists only while the page is on, and the foreign key drops it with
//! its project. The key is stored in clear: the settings must show the address again.

use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Projects {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum ProjectPublicPages {
    Table,
    ProjectId,
    Key,
    CreatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ProjectPublicPages::Table)
                    .col(big_integer(ProjectPublicPages::ProjectId).primary_key())
                    .col(string(ProjectPublicPages::Key))
                    .col(timestamp_with_time_zone(ProjectPublicPages::CreatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_project_public_pages_project")
                            .from(ProjectPublicPages::Table, ProjectPublicPages::ProjectId)
                            .to(Projects::Table, Projects::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("index_project_public_pages_key")
                    .table(ProjectPublicPages::Table)
                    .col(ProjectPublicPages::Key)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ProjectPublicPages::Table).to_owned())
            .await
    }
}
