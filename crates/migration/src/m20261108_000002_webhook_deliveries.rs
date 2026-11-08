//! Webhook deliveries: each document is recorded before it is sent, so that failed deliveries
//! can be retried and shown in the organization's settings. The last delivery columns of
//! `organization_webhooks` are replaced by these rows.

use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum WebhookDeliveries {
    Table,
    Id,
    OrganizationId,
    Url,
    Event,
    Payload,
    Attempts,
    NextAttemptAt,
    LastAttemptAt,
    LastStatus,
    DeliveredAt,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Organizations {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum OrganizationWebhooks {
    Table,
    LastDeliveryAt,
    LastDeliveryStatus,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(WebhookDeliveries::Table)
                    .col(big_pk_auto(WebhookDeliveries::Id))
                    // Null for the instance's failure webhook.
                    .col(big_integer_null(WebhookDeliveries::OrganizationId))
                    .col(text(WebhookDeliveries::Url))
                    .col(string(WebhookDeliveries::Event))
                    .col(text(WebhookDeliveries::Payload))
                    .col(big_integer(WebhookDeliveries::Attempts).default(0))
                    // Null once the delivery succeeded or was abandoned.
                    .col(timestamp_with_time_zone_null(
                        WebhookDeliveries::NextAttemptAt,
                    ))
                    .col(timestamp_with_time_zone_null(
                        WebhookDeliveries::LastAttemptAt,
                    ))
                    .col(text_null(WebhookDeliveries::LastStatus))
                    .col(timestamp_with_time_zone_null(
                        WebhookDeliveries::DeliveredAt,
                    ))
                    .col(timestamp_with_time_zone(WebhookDeliveries::CreatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_webhook_deliveries_organization")
                            .from(WebhookDeliveries::Table, WebhookDeliveries::OrganizationId)
                            .to(Organizations::Table, Organizations::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("index_webhook_deliveries_next_attempt_at")
                    .table(WebhookDeliveries::Table)
                    .col(WebhookDeliveries::NextAttemptAt)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("index_webhook_deliveries_organization_created_at")
                    .table(WebhookDeliveries::Table)
                    .col(WebhookDeliveries::OrganizationId)
                    .col(WebhookDeliveries::CreatedAt)
                    .to_owned(),
            )
            .await?;
        // One column per statement: SQLite drops a single column at a time.
        for column in [
            OrganizationWebhooks::LastDeliveryAt,
            OrganizationWebhooks::LastDeliveryStatus,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(OrganizationWebhooks::Table)
                        .drop_column(column)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(OrganizationWebhooks::Table)
                    .add_column(timestamp_with_time_zone_null(
                        OrganizationWebhooks::LastDeliveryAt,
                    ))
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(OrganizationWebhooks::Table)
                    .add_column(string_null(OrganizationWebhooks::LastDeliveryStatus))
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(WebhookDeliveries::Table).to_owned())
            .await
    }
}
