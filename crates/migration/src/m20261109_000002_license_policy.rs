//! License policy of each organization (see `nanobom_domain::licenses`): one rule per SPDX
//! license identifier, and two defaults on the organization, for licenses no rule lists and for
//! components whose license is unknown.
//!
//! The defaults are `allow`, so existing organizations have no policy until an administrator
//! sets one. Rule identifiers are stored in their canonical spelling (`MIT`, `GPL-3.0-only`,
//! `LicenseRef-…`); matching is case-insensitive, and the domain refuses two rules whose
//! identifiers differ only by case, which the unique index cannot express on every database.

use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Organizations {
    Table,
    Id,
    LicenseUnlistedAction,
    LicenseUnknownAction,
}

#[derive(DeriveIden)]
enum LicenseRules {
    Table,
    Id,
    OrganizationId,
    License,
    Action,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // One column per statement: SQLite adds a single column per `ALTER TABLE`.
        for column in [
            Organizations::LicenseUnlistedAction,
            Organizations::LicenseUnknownAction,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Organizations::Table)
                        .add_column(string(column).default("allow"))
                        .to_owned(),
                )
                .await?;
        }
        manager
            .create_table(
                Table::create()
                    .table(LicenseRules::Table)
                    .col(big_pk_auto(LicenseRules::Id))
                    .col(big_integer(LicenseRules::OrganizationId))
                    .col(string(LicenseRules::License))
                    .col(string(LicenseRules::Action))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_license_rules_organization")
                            .from(LicenseRules::Table, LicenseRules::OrganizationId)
                            .to(Organizations::Table, Organizations::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("index_license_rules_organization_license")
                    .table(LicenseRules::Table)
                    .col(LicenseRules::OrganizationId)
                    .col(LicenseRules::License)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(LicenseRules::Table).to_owned())
            .await?;
        for column in [
            Organizations::LicenseUnknownAction,
            Organizations::LicenseUnlistedAction,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Organizations::Table)
                        .drop_column(column)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
