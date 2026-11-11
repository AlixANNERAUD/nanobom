//! Project badges (see `nanobom_domain::badges`): the key of each project's public badge.
//!
//! A table of its own rather than a nullable column on `projects`: SQLite cannot add a unique
//! column to an existing table, and a row exists only while the badge is on, so turning it off
//! is a delete and the foreign key drops the badge with its project. The key is stored in clear,
//! unlike upload tokens: it only unlocks counts the badge shows anyway, and the settings must
//! show the address again.

use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Projects {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum ProjectBadges {
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
                    .table(ProjectBadges::Table)
                    .col(big_integer(ProjectBadges::ProjectId).primary_key())
                    .col(string(ProjectBadges::Key))
                    .col(timestamp_with_time_zone(ProjectBadges::CreatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_project_badges_project")
                            .from(ProjectBadges::Table, ProjectBadges::ProjectId)
                            .to(Projects::Table, Projects::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("index_project_badges_key")
                    .table(ProjectBadges::Table)
                    .col(ProjectBadges::Key)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ProjectBadges::Table).to_owned())
            .await
    }
}
