//! The initial schema. Enumerations are stored as text and timestamps with their time zone so the
//! same schema works on SQLite and PostgreSQL.
//!
//! Foreign keys cascade from organizations to projects, memberships, tokens and runs, and from
//! projects to components, uploads, runs and findings, so deleting an organization or a project
//! removes everything under it. References that only record who or what did something (the
//! creator of a token, the token of an upload, the user or run behind a finding event) are set
//! to null instead, keeping the history.

use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    Username,
    Email,
    DisplayName,
    PasswordHash,
    IsInstanceAdministrator,
    IsDisabled,
    CreatedAt,
    LastLoginAt,
}

#[derive(DeriveIden)]
enum UserIdentities {
    Table,
    Id,
    UserId,
    Issuer,
    Subject,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Organizations {
    Table,
    Id,
    Slug,
    Name,
    IsPersonal,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Memberships {
    Table,
    Id,
    OrganizationId,
    UserId,
    Role,
    Source,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Projects {
    Table,
    Id,
    OrganizationId,
    Slug,
    Name,
    CreatedAt,
    LastUploadAt,
}

#[derive(DeriveIden)]
enum UploadTokens {
    Table,
    Id,
    OrganizationId,
    ProjectId,
    Name,
    TokenHash,
    TokenPrefix,
    CreatedByUserId,
    CreatedAt,
    LastUsedAt,
    RevokedAt,
}

#[derive(DeriveIden)]
enum SbomUploads {
    Table,
    Id,
    ProjectId,
    UploadTokenId,
    UploadedAt,
    SpecificationVersion,
    SerialNumber,
    SourceCommit,
    ImageTag,
    ComponentCount,
    ComponentsWithoutPurl,
}

#[derive(DeriveIden)]
enum Components {
    Table,
    Id,
    ProjectId,
    Purl,
    QueryPurl,
    Ecosystem,
    Name,
    Version,
}

#[derive(DeriveIden)]
enum Vulnerabilities {
    Table,
    Id,
    Modified,
    Published,
    Withdrawn,
    Summary,
    Details,
    Aliases,
    Severity,
    CvssScore,
    CvssVersion,
    CvssVector,
    Record,
    FetchedAt,
}

#[derive(DeriveIden)]
enum Runs {
    Table,
    Id,
    Trigger,
    Scope,
    OrganizationId,
    ProjectId,
    TriggeredByUserId,
    StartedAt,
    FinishedAt,
    Status,
    Error,
    ComponentCount,
    VulnerabilityCount,
    NewFindings,
    FixedFindings,
}

#[derive(DeriveIden)]
enum Findings {
    Table,
    Id,
    ProjectId,
    Purl,
    Ecosystem,
    VulnerabilityId,
    Status,
    Severity,
    FirstSeenAt,
    LastSeenAt,
    FixedAt,
    IgnoreReason,
    IgnoreExpiresAt,
    IgnoredByUserId,
    IgnoredAt,
}

#[derive(DeriveIden)]
enum FindingEvents {
    Table,
    Id,
    FindingId,
    CreatedAt,
    Kind,
    ActorUserId,
    Reason,
    RunId,
}

#[derive(DeriveIden)]
enum OrganizationWebhooks {
    Table,
    OrganizationId,
    Url,
    MinimumSeverity,
    Enabled,
    LastDeliveryAt,
    LastDeliveryStatus,
}

#[derive(DeriveIden)]
enum Sessions {
    Table,
    Id,
    Data,
    ExpiryDate,
}

fn foreign_key(
    name: &str,
    from: (impl IntoIden, impl IntoIden),
    to: (impl IntoIden, impl IntoIden),
    on_delete: ForeignKeyAction,
) -> ForeignKeyCreateStatement {
    ForeignKey::create()
        .name(name)
        .from(from.0, from.1)
        .to(to.0, to.1)
        .on_delete(on_delete)
        .to_owned()
}

fn index(name: &str, table: impl IntoIden, columns: &[&'static str]) -> IndexCreateStatement {
    let mut statement = Index::create().name(name).table(table).to_owned();
    for column in columns {
        statement.col(Alias::new(*column));
    }
    statement
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .col(big_pk_auto(Users::Id))
                    .col(string_uniq(Users::Username))
                    .col(string_null(Users::Email).unique_key())
                    .col(string(Users::DisplayName))
                    .col(string_null(Users::PasswordHash))
                    .col(boolean(Users::IsInstanceAdministrator).default(false))
                    .col(boolean(Users::IsDisabled).default(false))
                    .col(timestamp_with_time_zone(Users::CreatedAt))
                    .col(timestamp_with_time_zone_null(Users::LastLoginAt))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(UserIdentities::Table)
                    .col(big_pk_auto(UserIdentities::Id))
                    .col(big_integer(UserIdentities::UserId))
                    .col(string(UserIdentities::Issuer))
                    .col(string(UserIdentities::Subject))
                    .col(timestamp_with_time_zone(UserIdentities::CreatedAt))
                    .foreign_key(&mut foreign_key(
                        "fk_user_identities_user",
                        (UserIdentities::Table, UserIdentities::UserId),
                        (Users::Table, Users::Id),
                        ForeignKeyAction::Cascade,
                    ))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                index(
                    "index_user_identities_issuer_subject",
                    UserIdentities::Table,
                    &["issuer", "subject"],
                )
                .unique()
                .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Organizations::Table)
                    .col(big_pk_auto(Organizations::Id))
                    .col(string_uniq(Organizations::Slug))
                    .col(string(Organizations::Name))
                    .col(boolean(Organizations::IsPersonal).default(false))
                    .col(timestamp_with_time_zone(Organizations::CreatedAt))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Memberships::Table)
                    .col(big_pk_auto(Memberships::Id))
                    .col(big_integer(Memberships::OrganizationId))
                    .col(big_integer(Memberships::UserId))
                    .col(string(Memberships::Role))
                    .col(string(Memberships::Source))
                    .col(timestamp_with_time_zone(Memberships::CreatedAt))
                    .foreign_key(&mut foreign_key(
                        "fk_memberships_organization",
                        (Memberships::Table, Memberships::OrganizationId),
                        (Organizations::Table, Organizations::Id),
                        ForeignKeyAction::Cascade,
                    ))
                    .foreign_key(&mut foreign_key(
                        "fk_memberships_user",
                        (Memberships::Table, Memberships::UserId),
                        (Users::Table, Users::Id),
                        ForeignKeyAction::Cascade,
                    ))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                index(
                    "index_memberships_organization_user_source",
                    Memberships::Table,
                    &["organization_id", "user_id", "source"],
                )
                .unique()
                .to_owned(),
            )
            .await?;
        manager
            .create_index(index(
                "index_memberships_user",
                Memberships::Table,
                &["user_id"],
            ))
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Projects::Table)
                    .col(big_pk_auto(Projects::Id))
                    .col(big_integer(Projects::OrganizationId))
                    .col(string(Projects::Slug))
                    .col(string(Projects::Name))
                    .col(timestamp_with_time_zone(Projects::CreatedAt))
                    .col(timestamp_with_time_zone_null(Projects::LastUploadAt))
                    .foreign_key(&mut foreign_key(
                        "fk_projects_organization",
                        (Projects::Table, Projects::OrganizationId),
                        (Organizations::Table, Organizations::Id),
                        ForeignKeyAction::Cascade,
                    ))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                index(
                    "index_projects_organization_slug",
                    Projects::Table,
                    &["organization_id", "slug"],
                )
                .unique()
                .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(UploadTokens::Table)
                    .col(big_pk_auto(UploadTokens::Id))
                    .col(big_integer(UploadTokens::OrganizationId))
                    .col(big_integer_null(UploadTokens::ProjectId))
                    .col(string(UploadTokens::Name))
                    .col(string_uniq(UploadTokens::TokenHash))
                    .col(string(UploadTokens::TokenPrefix))
                    .col(big_integer_null(UploadTokens::CreatedByUserId))
                    .col(timestamp_with_time_zone(UploadTokens::CreatedAt))
                    .col(timestamp_with_time_zone_null(UploadTokens::LastUsedAt))
                    .col(timestamp_with_time_zone_null(UploadTokens::RevokedAt))
                    .foreign_key(&mut foreign_key(
                        "fk_upload_tokens_organization",
                        (UploadTokens::Table, UploadTokens::OrganizationId),
                        (Organizations::Table, Organizations::Id),
                        ForeignKeyAction::Cascade,
                    ))
                    .foreign_key(&mut foreign_key(
                        "fk_upload_tokens_project",
                        (UploadTokens::Table, UploadTokens::ProjectId),
                        (Projects::Table, Projects::Id),
                        ForeignKeyAction::Cascade,
                    ))
                    .foreign_key(&mut foreign_key(
                        "fk_upload_tokens_created_by",
                        (UploadTokens::Table, UploadTokens::CreatedByUserId),
                        (Users::Table, Users::Id),
                        ForeignKeyAction::SetNull,
                    ))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(SbomUploads::Table)
                    .col(big_pk_auto(SbomUploads::Id))
                    .col(big_integer(SbomUploads::ProjectId))
                    .col(big_integer_null(SbomUploads::UploadTokenId))
                    .col(timestamp_with_time_zone(SbomUploads::UploadedAt))
                    .col(string(SbomUploads::SpecificationVersion))
                    .col(string_null(SbomUploads::SerialNumber))
                    .col(string_null(SbomUploads::SourceCommit))
                    .col(string_null(SbomUploads::ImageTag))
                    .col(big_integer(SbomUploads::ComponentCount))
                    .col(big_integer(SbomUploads::ComponentsWithoutPurl))
                    .foreign_key(&mut foreign_key(
                        "fk_sbom_uploads_project",
                        (SbomUploads::Table, SbomUploads::ProjectId),
                        (Projects::Table, Projects::Id),
                        ForeignKeyAction::Cascade,
                    ))
                    .foreign_key(&mut foreign_key(
                        "fk_sbom_uploads_upload_token",
                        (SbomUploads::Table, SbomUploads::UploadTokenId),
                        (UploadTokens::Table, UploadTokens::Id),
                        ForeignKeyAction::SetNull,
                    ))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(index(
                "index_sbom_uploads_project",
                SbomUploads::Table,
                &["project_id"],
            ))
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Components::Table)
                    .col(big_pk_auto(Components::Id))
                    .col(big_integer(Components::ProjectId))
                    .col(string(Components::Purl))
                    .col(string(Components::QueryPurl))
                    .col(string(Components::Ecosystem))
                    .col(string(Components::Name))
                    .col(string_null(Components::Version))
                    .foreign_key(&mut foreign_key(
                        "fk_components_project",
                        (Components::Table, Components::ProjectId),
                        (Projects::Table, Projects::Id),
                        ForeignKeyAction::Cascade,
                    ))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                index(
                    "index_components_project_purl",
                    Components::Table,
                    &["project_id", "purl"],
                )
                .unique()
                .to_owned(),
            )
            .await?;
        manager
            .create_index(index(
                "index_components_query_purl",
                Components::Table,
                &["query_purl"],
            ))
            .await?;
        manager
            .create_index(index("index_components_name", Components::Table, &["name"]))
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Vulnerabilities::Table)
                    .col(string(Vulnerabilities::Id).primary_key())
                    .col(timestamp_with_time_zone(Vulnerabilities::Modified))
                    .col(timestamp_with_time_zone_null(Vulnerabilities::Published))
                    .col(timestamp_with_time_zone_null(Vulnerabilities::Withdrawn))
                    .col(text_null(Vulnerabilities::Summary))
                    .col(text_null(Vulnerabilities::Details))
                    .col(text(Vulnerabilities::Aliases))
                    .col(string(Vulnerabilities::Severity))
                    .col(double_null(Vulnerabilities::CvssScore))
                    .col(string_null(Vulnerabilities::CvssVersion))
                    .col(string_null(Vulnerabilities::CvssVector))
                    .col(text(Vulnerabilities::Record))
                    .col(timestamp_with_time_zone(Vulnerabilities::FetchedAt))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Runs::Table)
                    .col(big_pk_auto(Runs::Id))
                    .col(string(Runs::Trigger))
                    .col(string(Runs::Scope))
                    .col(big_integer_null(Runs::OrganizationId))
                    .col(big_integer_null(Runs::ProjectId))
                    .col(big_integer_null(Runs::TriggeredByUserId))
                    .col(timestamp_with_time_zone(Runs::StartedAt))
                    .col(timestamp_with_time_zone_null(Runs::FinishedAt))
                    .col(string(Runs::Status))
                    .col(text_null(Runs::Error))
                    .col(big_integer(Runs::ComponentCount).default(0))
                    .col(big_integer(Runs::VulnerabilityCount).default(0))
                    .col(big_integer(Runs::NewFindings).default(0))
                    .col(big_integer(Runs::FixedFindings).default(0))
                    .foreign_key(&mut foreign_key(
                        "fk_runs_organization",
                        (Runs::Table, Runs::OrganizationId),
                        (Organizations::Table, Organizations::Id),
                        ForeignKeyAction::Cascade,
                    ))
                    .foreign_key(&mut foreign_key(
                        "fk_runs_project",
                        (Runs::Table, Runs::ProjectId),
                        (Projects::Table, Projects::Id),
                        ForeignKeyAction::Cascade,
                    ))
                    .foreign_key(&mut foreign_key(
                        "fk_runs_triggered_by",
                        (Runs::Table, Runs::TriggeredByUserId),
                        (Users::Table, Users::Id),
                        ForeignKeyAction::SetNull,
                    ))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(index("index_runs_started_at", Runs::Table, &["started_at"]))
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Findings::Table)
                    .col(big_pk_auto(Findings::Id))
                    .col(big_integer(Findings::ProjectId))
                    .col(string(Findings::Purl))
                    .col(string(Findings::Ecosystem))
                    .col(string(Findings::VulnerabilityId))
                    .col(string(Findings::Status))
                    .col(string(Findings::Severity))
                    .col(timestamp_with_time_zone(Findings::FirstSeenAt))
                    .col(timestamp_with_time_zone(Findings::LastSeenAt))
                    .col(timestamp_with_time_zone_null(Findings::FixedAt))
                    .col(text_null(Findings::IgnoreReason))
                    .col(timestamp_with_time_zone_null(Findings::IgnoreExpiresAt))
                    .col(big_integer_null(Findings::IgnoredByUserId))
                    .col(timestamp_with_time_zone_null(Findings::IgnoredAt))
                    .foreign_key(&mut foreign_key(
                        "fk_findings_project",
                        (Findings::Table, Findings::ProjectId),
                        (Projects::Table, Projects::Id),
                        ForeignKeyAction::Cascade,
                    ))
                    .foreign_key(&mut foreign_key(
                        "fk_findings_vulnerability",
                        (Findings::Table, Findings::VulnerabilityId),
                        (Vulnerabilities::Table, Vulnerabilities::Id),
                        ForeignKeyAction::Restrict,
                    ))
                    .foreign_key(&mut foreign_key(
                        "fk_findings_ignored_by",
                        (Findings::Table, Findings::IgnoredByUserId),
                        (Users::Table, Users::Id),
                        ForeignKeyAction::SetNull,
                    ))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                index(
                    "index_findings_project_purl_vulnerability",
                    Findings::Table,
                    &["project_id", "purl", "vulnerability_id"],
                )
                .unique()
                .to_owned(),
            )
            .await?;
        manager
            .create_index(index(
                "index_findings_vulnerability",
                Findings::Table,
                &["vulnerability_id"],
            ))
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(FindingEvents::Table)
                    .col(big_pk_auto(FindingEvents::Id))
                    .col(big_integer(FindingEvents::FindingId))
                    .col(timestamp_with_time_zone(FindingEvents::CreatedAt))
                    .col(string(FindingEvents::Kind))
                    .col(big_integer_null(FindingEvents::ActorUserId))
                    .col(text_null(FindingEvents::Reason))
                    .col(big_integer_null(FindingEvents::RunId))
                    .foreign_key(&mut foreign_key(
                        "fk_finding_events_finding",
                        (FindingEvents::Table, FindingEvents::FindingId),
                        (Findings::Table, Findings::Id),
                        ForeignKeyAction::Cascade,
                    ))
                    .foreign_key(&mut foreign_key(
                        "fk_finding_events_actor",
                        (FindingEvents::Table, FindingEvents::ActorUserId),
                        (Users::Table, Users::Id),
                        ForeignKeyAction::SetNull,
                    ))
                    .foreign_key(&mut foreign_key(
                        "fk_finding_events_run",
                        (FindingEvents::Table, FindingEvents::RunId),
                        (Runs::Table, Runs::Id),
                        ForeignKeyAction::SetNull,
                    ))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(index(
                "index_finding_events_finding",
                FindingEvents::Table,
                &["finding_id"],
            ))
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(OrganizationWebhooks::Table)
                    .col(big_integer(OrganizationWebhooks::OrganizationId).primary_key())
                    .col(text(OrganizationWebhooks::Url))
                    .col(string(OrganizationWebhooks::MinimumSeverity))
                    .col(boolean(OrganizationWebhooks::Enabled).default(true))
                    .col(timestamp_with_time_zone_null(
                        OrganizationWebhooks::LastDeliveryAt,
                    ))
                    .col(string_null(OrganizationWebhooks::LastDeliveryStatus))
                    .foreign_key(&mut foreign_key(
                        "fk_organization_webhooks_organization",
                        (
                            OrganizationWebhooks::Table,
                            OrganizationWebhooks::OrganizationId,
                        ),
                        (Organizations::Table, Organizations::Id),
                        ForeignKeyAction::Cascade,
                    ))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Sessions::Table)
                    .col(string(Sessions::Id).primary_key())
                    .col(text(Sessions::Data))
                    .col(timestamp_with_time_zone(Sessions::ExpiryDate))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(index(
                "index_sessions_expiry_date",
                Sessions::Table,
                &["expiry_date"],
            ))
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in [
            Sessions::Table.into_iden(),
            OrganizationWebhooks::Table.into_iden(),
            FindingEvents::Table.into_iden(),
            Findings::Table.into_iden(),
            Runs::Table.into_iden(),
            Vulnerabilities::Table.into_iden(),
            Components::Table.into_iden(),
            SbomUploads::Table.into_iden(),
            UploadTokens::Table.into_iden(),
            Projects::Table.into_iden(),
            Memberships::Table.into_iden(),
            Organizations::Table.into_iden(),
            UserIdentities::Table.into_iden(),
            Users::Table.into_iden(),
        ] {
            manager
                .drop_table(Table::drop().table(table).to_owned())
                .await?;
        }
        Ok(())
    }
}
