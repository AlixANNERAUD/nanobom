//! Exploitation data (CISA KEV, FIRST EPSS), exploited-only webhooks and stale project alerts.
//!
//! The `exploitation` table is keyed by CVE identifier, without a foreign key: CVEs come from
//! the aliases of cached vulnerability records, and one CVE can back several records. The
//! `*_notified_at` columns remember what webhooks already announced, so each event is sent once.

use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Exploitation {
    Table,
    CveId,
    KnownExploited,
    KevDateAdded,
    KevDueDate,
    KevRansomware,
    EpssScore,
    EpssPercentile,
    EpssDate,
    KevCheckedAt,
    EpssCheckedAt,
}

#[derive(DeriveIden)]
enum Findings {
    Table,
    ExploitedNotifiedAt,
}

#[derive(DeriveIden)]
enum OrganizationWebhooks {
    Table,
    ExploitedOnly,
}

#[derive(DeriveIden)]
enum Projects {
    Table,
    StaleNotifiedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Exploitation::Table)
                    .col(text(Exploitation::CveId).primary_key())
                    .col(boolean(Exploitation::KnownExploited).default(false))
                    .col(text_null(Exploitation::KevDateAdded))
                    .col(text_null(Exploitation::KevDueDate))
                    .col(boolean(Exploitation::KevRansomware).default(false))
                    .col(double_null(Exploitation::EpssScore))
                    .col(double_null(Exploitation::EpssPercentile))
                    .col(text_null(Exploitation::EpssDate))
                    .col(timestamp_with_time_zone_null(Exploitation::KevCheckedAt))
                    .col(timestamp_with_time_zone_null(Exploitation::EpssCheckedAt))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Findings::Table)
                    .add_column(timestamp_with_time_zone_null(Findings::ExploitedNotifiedAt))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(OrganizationWebhooks::Table)
                    .add_column(boolean(OrganizationWebhooks::ExploitedOnly).default(false))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Projects::Table)
                    .add_column(timestamp_with_time_zone_null(Projects::StaleNotifiedAt))
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Projects::Table)
                    .drop_column(Projects::StaleNotifiedAt)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(OrganizationWebhooks::Table)
                    .drop_column(OrganizationWebhooks::ExploitedOnly)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Findings::Table)
                    .drop_column(Findings::ExploitedNotifiedAt)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(Exploitation::Table).to_owned())
            .await
    }
}
