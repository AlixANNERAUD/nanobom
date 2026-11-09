//! Email notifications (see `nanobom_domain::email`): the recipients of each organization, and
//! a channel on each queued delivery.
//!
//! Recipients are one text column, one address per line: a list bounded by the domain (20
//! addresses) that is always read and replaced as a whole. Email deliveries share the webhook
//! delivery queue and its lease, claim and backoff logic; `channel` (`webhook` or `email`) tells
//! them apart, and existing rows are webhook deliveries.

use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Organizations {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum OrganizationEmails {
    Table,
    OrganizationId,
    Recipients,
    Language,
    MinimumSeverity,
    ExploitedOnly,
}

#[derive(DeriveIden)]
enum WebhookDeliveries {
    Table,
    Channel,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(OrganizationEmails::Table)
                    .col(big_integer(OrganizationEmails::OrganizationId).primary_key())
                    .col(text(OrganizationEmails::Recipients))
                    .col(string(OrganizationEmails::Language).default("en"))
                    .col(string(OrganizationEmails::MinimumSeverity))
                    .col(boolean(OrganizationEmails::ExploitedOnly).default(false))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_organization_emails_organization")
                            .from(
                                OrganizationEmails::Table,
                                OrganizationEmails::OrganizationId,
                            )
                            .to(Organizations::Table, Organizations::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(WebhookDeliveries::Table)
                    .add_column(string(WebhookDeliveries::Channel).default("webhook"))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(WebhookDeliveries::Table)
                    .drop_column(WebhookDeliveries::Channel)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(OrganizationEmails::Table).to_owned())
            .await
    }
}
