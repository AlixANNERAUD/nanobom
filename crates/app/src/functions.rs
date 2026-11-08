//! Server functions: page data, and the actions behind the interface's forms.
//!
//! Actions are sent by plain HTML forms, so the interface works without JavaScript: each
//! action redirects back to the page it came from with a `notice` or `error` message.

use leptos::prelude::*;

use crate::model::*;
#[cfg(feature = "ssr")]
use crate::server::{actor, back, context, failure, finish, redirect_with};

// ----- Pages -----

#[server(endpoint = "current_user")]
pub async fn load_current_user() -> Result<Option<CurrentUser>, ServerFnError> {
    use nanobom_domain::{organizations, users};
    let context = context()?;
    let Some(user) = crate::server::session().await?.user else {
        return Ok(None);
    };
    let Some(model) = users::find_by_id(&context.database, user.id)
        .await
        .map_err(failure)?
        .filter(|user| !user.is_disabled)
    else {
        return Ok(None);
    };
    let actor = nanobom_domain::access::Actor::from_user(&model);
    let organizations = organizations::list(&context.database, &actor)
        .await
        .map_err(failure)?;
    Ok(Some(CurrentUser {
        username: model.username,
        display_name: model.display_name,
        is_instance_administrator: model.is_instance_administrator,
        organizations: organizations
            .into_iter()
            .map(crate::server::organization)
            .collect(),
    }))
}

#[server(endpoint = "sign_in_options")]
pub async fn load_sign_in_options() -> Result<SignInOptions, ServerFnError> {
    let context = context()?;
    let signed_in = crate::server::session().await?.user.is_some();
    Ok(SignInOptions {
        local_accounts: context.settings.local_accounts,
        openid_button: context.settings.openid_button.clone(),
        signed_in,
    })
}

#[server(endpoint = "organizations")]
pub async fn load_organizations() -> Result<Vec<Organization>, ServerFnError> {
    let actor = actor().await?;
    let context = context()?;
    Ok(
        nanobom_domain::organizations::list(&context.database, &actor)
            .await
            .map_err(failure)?
            .into_iter()
            .map(crate::server::organization)
            .collect(),
    )
}

#[server(endpoint = "organization_page")]
pub async fn load_organization(organization: String) -> Result<OrganizationData, ServerFnError> {
    use nanobom_domain::{evaluation, findings, organizations};
    let actor = actor().await?;
    let database = &context()?.database;
    let found = organizations::find(database, &actor, &organization)
        .await
        .map_err(failure)?;
    let projects = findings::overview(database, &actor, found.id)
        .await
        .map_err(failure)?;
    let runs = evaluation::recent_runs(database, &actor, found.id, 5)
        .await
        .map_err(failure)?;
    Ok(OrganizationData {
        organization: crate::server::organization(found),
        projects: projects
            .into_iter()
            .map(|project| ProjectRow {
                slug: project.slug,
                name: project.name,
                last_upload_at: project.last_upload_at,
                open: crate::server::counts(project.open),
                ignored: project.ignored,
            })
            .collect(),
        runs: runs.into_iter().map(run).collect(),
    })
}

#[cfg(feature = "ssr")]
fn run(run: nanobom_domain::evaluation::RunSummary) -> Run {
    Run {
        id: run.id,
        trigger: run.trigger,
        scope: run.scope,
        status: run.status,
        started_at: run.started_at,
        finished_at: run.finished_at,
        error: run.error,
        new_findings: run.new_findings,
        fixed_findings: run.fixed_findings,
    }
}

#[server(endpoint = "project_page")]
pub async fn load_project(
    organization: String,
    project: String,
    filter: FindingFilter,
) -> Result<ProjectData, ServerFnError> {
    use nanobom_domain::{findings, inventory, organizations, projects};
    let actor = actor().await?;
    let database = &context()?.database;
    let found = organizations::find(database, &actor, &organization)
        .await
        .map_err(failure)?;
    let model = projects::find(database, &actor, found.id, &project)
        .await
        .map_err(failure)?;
    let domain_filter = findings::Filter {
        severities: filter
            .severity
            .as_deref()
            .and_then(Severity::parse)
            .map(|severity| vec![crate::server::domain_severity(severity)])
            .unwrap_or_default(),
        statuses: match filter.status.as_deref() {
            Some("all") => Vec::new(),
            Some(value) => value.parse().map(|status| vec![status]).unwrap_or_default(),
            None => vec![findings::Status::Open, findings::Status::Ignored],
        },
        ecosystem: filter.ecosystem.filter(|ecosystem| !ecosystem.is_empty()),
    };
    let list = findings::list(database, &actor, model.id, &domain_filter)
        .await
        .map_err(failure)?;
    let ecosystems = findings::ecosystems(database, &actor, model.id)
        .await
        .map_err(failure)?;
    let uploads = inventory::uploads(database, &actor, model.id)
        .await
        .map_err(failure)?;
    // The latest upload replaced the project's components, so its count is theirs.
    let component_count = uploads.first().map_or(0, |upload| {
        usize::try_from(upload.component_count).unwrap_or_default()
    });
    Ok(ProjectData {
        organization: crate::server::organization(found),
        slug: model.slug,
        name: model.name,
        findings: list.into_iter().map(crate::server::finding).collect(),
        ecosystems,
        uploads: uploads
            .into_iter()
            .take(10)
            .map(|upload| Upload {
                uploaded_at: upload.uploaded_at,
                specification_version: upload.specification_version,
                source_commit: upload.source_commit,
                image_tag: upload.image_tag,
                component_count: upload.component_count,
                components_without_purl: upload.components_without_purl,
            })
            .collect(),
        component_count,
    })
}

#[server(endpoint = "finding_page")]
pub async fn load_finding(finding: i64) -> Result<FindingData, ServerFnError> {
    use nanobom_domain::findings;
    let actor = actor().await?;
    let database = &context()?.database;
    let detail = findings::detail(database, &actor, finding)
        .await
        .map_err(failure)?;
    Ok(FindingData {
        organization_slug: detail.organization_slug,
        project_slug: detail.finding.project_slug.clone(),
        can_triage: detail.can_triage,
        details: detail.details,
        published: detail.published,
        modified: detail.modified,
        cvss_version: detail.cvss_version,
        cvss_vector: detail.cvss_vector,
        fixed_versions: detail.fixed_versions,
        references: detail
            .references
            .into_iter()
            .map(|reference| Reference {
                kind: reference.kind,
                url: reference.url,
            })
            .collect(),
        ignored_by: detail.ignored_by,
        affected_components: detail
            .affected_components
            .into_iter()
            .map(|component| AffectedComponent {
                finding_id: component.finding_id,
                organization_slug: component.organization_slug,
                project_slug: component.project_slug,
                purl: component.purl,
                status: crate::server::status(component.status),
            })
            .collect(),
        events: detail
            .events
            .into_iter()
            .map(|event| FindingEvent {
                created_at: event.created_at,
                kind: event.kind.as_str().to_owned(),
                actor: event.actor,
                reason: event.reason,
            })
            .collect(),
        finding: crate::server::finding(detail.finding),
    })
}

#[server(endpoint = "search_components")]
pub async fn search_components(query: String) -> Result<Vec<ComponentMatch>, ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    Ok(nanobom_domain::inventory::search(database, &actor, &query)
        .await
        .map_err(failure)?
        .into_iter()
        .map(|component| ComponentMatch {
            organization_slug: component.organization_slug,
            project_slug: component.project_slug,
            purl: component.purl,
            ecosystem: component.ecosystem,
            name: component.name,
            version: component.version,
        })
        .collect())
}

/// Session key of a token created by the previous request, shown once on the settings page.
#[cfg(feature = "ssr")]
const NEW_TOKEN: &str = "settings.new_token";

#[server(endpoint = "settings_page")]
pub async fn load_settings(organization: String) -> Result<SettingsData, ServerFnError> {
    use nanobom_domain::{
        access::Permission, memberships, notifications, organizations, projects, tokens,
    };
    let actor = actor().await?;
    let database = &context()?.database;
    let found = organizations::find(database, &actor, &organization)
        .await
        .map_err(failure)?;
    actor
        .authorize(database, found.id, Permission::ManageMembers)
        .await
        .map_err(failure)?;
    let members = memberships::list(database, &actor, found.id)
        .await
        .map_err(failure)?;
    let tokens = tokens::list(database, &actor, found.id)
        .await
        .map_err(failure)?;
    let projects = projects::list(database, &actor, found.id)
        .await
        .map_err(failure)?;
    let webhook = notifications::get(database, &actor, found.id)
        .await
        .map_err(failure)?;
    let session = crate::server::session().await?.session;
    let new_token: Option<String> = session.remove(NEW_TOKEN).await.ok().flatten();
    Ok(SettingsData {
        current_user_id: actor.user_id,
        organization: crate::server::organization(found),
        members: members
            .into_iter()
            .map(|member| Member {
                user_id: member.user_id,
                username: member.username,
                display_name: member.display_name,
                email: member.email,
                role: crate::server::role(member.role),
                manual_role: member.manual_role.map(crate::server::role),
                synchronized_role: member.synchronized_role.map(crate::server::role),
            })
            .collect(),
        tokens: tokens
            .into_iter()
            .map(|token| UploadToken {
                id: token.id,
                name: token.name,
                prefix: token.prefix,
                project_slug: token.project_slug,
                created_at: token.created_at,
                last_used_at: token.last_used_at,
                revoked: token.revoked_at.is_some(),
            })
            .collect(),
        projects: projects.into_iter().map(|project| project.slug).collect(),
        webhook: webhook.map(|webhook| Webhook {
            url: webhook.url,
            minimum_severity: crate::server::severity(webhook.minimum_severity),
            enabled: webhook.enabled,
            last_delivery_at: webhook.last_delivery_at,
            last_delivery_status: webhook.last_delivery_status,
        }),
        new_token,
    })
}

#[server(endpoint = "administration_page")]
pub async fn load_administration() -> Result<AdministrationData, ServerFnError> {
    use nanobom_domain::{organizations, users};
    let actor = actor().await?;
    let context = context()?;
    let database = &context.database;
    let users = users::list(database, &actor).await.map_err(failure)?;
    let organizations = organizations::list(database, &actor)
        .await
        .map_err(failure)?;
    Ok(AdministrationData {
        current_user_id: actor.user_id,
        users: users
            .into_iter()
            .map(|user| UserRow {
                id: user.id,
                username: user.username,
                display_name: user.display_name,
                email: user.email,
                is_instance_administrator: user.is_instance_administrator,
                is_disabled: user.is_disabled,
                has_password: user.password_hash.is_some(),
                last_login_at: user.last_login_at,
            })
            .collect(),
        organizations: organizations
            .into_iter()
            .map(crate::server::organization)
            .collect(),
        local_accounts: context.settings.local_accounts,
        password_minimum_length: context.settings.password_minimum_length,
    })
}

// ----- Actions -----

#[server(endpoint = "create_organization")]
pub async fn create_organization(slug: String, name: String) -> Result<(), ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    match nanobom_domain::organizations::create(database, &actor, &slug, &name).await {
        Ok(organization) => redirect_with(
            &format!("/organizations/{}", organization.slug),
            Ok("Organization created."),
        ),
        Err(error) => back(Err(crate::server::message(error)), "/organizations"),
    }
    Ok(())
}

#[server(endpoint = "trigger_run")]
pub async fn trigger_run(
    organization: String,
    project: Option<String>,
) -> Result<(), ServerFnError> {
    use nanobom_domain::{
        evaluation::{self, Scope, Trigger},
        organizations, projects,
    };
    let actor = actor().await?;
    let context = context()?;
    let database = &context.database;
    let result = async {
        let found = organizations::find(database, &actor, &organization).await?;
        let scope = match project.as_deref().filter(|project| !project.is_empty()) {
            Some(project) => Scope::Project(
                projects::find(database, &actor, found.id, project)
                    .await?
                    .id,
            ),
            None => Scope::Organization(found.id),
        };
        evaluation::authorize(database, &actor, scope).await?;
        (context.request_run)(Trigger::Manual, scope, Some(actor.user_id));
        Ok("Run started; refresh the page in a moment to see its results.".to_owned())
    }
    .await;
    finish(result, &format!("/organizations/{organization}"));
    Ok(())
}

#[server(endpoint = "ignore_finding")]
pub async fn ignore_finding(
    finding: i64,
    reason: String,
    expires_on: Option<String>,
) -> Result<(), ServerFnError> {
    use chrono::{NaiveDate, NaiveTime};
    let actor = actor().await?;
    let database = &context()?.database;
    let expires_at = match expires_on
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => match NaiveDate::parse_from_str(value, "%Y-%m-%d") {
            Ok(date) => Some(date.and_time(NaiveTime::MIN).and_utc().fixed_offset()),
            Err(_) => {
                back(
                    Err("The expiry date must be a date (YYYY-MM-DD).".to_owned()),
                    "/",
                );
                return Ok(());
            }
        },
        None => None,
    };
    let result = nanobom_domain::findings::ignore(database, &actor, finding, &reason, expires_at)
        .await
        .map(|()| "Finding ignored.".to_owned());
    finish(result, &format!("/findings/{finding}"));
    Ok(())
}

#[server(endpoint = "restore_finding")]
pub async fn restore_finding(finding: i64) -> Result<(), ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    let result = nanobom_domain::findings::restore(database, &actor, finding)
        .await
        .map(|()| "Finding restored.".to_owned());
    finish(result, &format!("/findings/{finding}"));
    Ok(())
}

#[cfg(feature = "ssr")]
async fn organization_id(
    database: &sea_orm::DatabaseConnection,
    actor: &nanobom_domain::access::Actor,
    slug: &str,
) -> Result<i64, nanobom_domain::Error> {
    Ok(nanobom_domain::organizations::find(database, actor, slug)
        .await?
        .id)
}

#[cfg(feature = "ssr")]
fn parse_role(value: &str) -> Result<nanobom_domain::access::Role, nanobom_domain::Error> {
    nanobom_domain::access::Role::parse(value)
}

#[server(endpoint = "add_member")]
pub async fn add_member(
    organization: String,
    login: String,
    role: String,
) -> Result<(), ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    let result = async {
        let id = organization_id(database, &actor, &organization).await?;
        let member =
            nanobom_domain::memberships::add(database, &actor, id, &login, parse_role(&role)?)
                .await?;
        Ok(format!("{} added.", member.username))
    }
    .await;
    finish(result, &format!("/organizations/{organization}/settings"));
    Ok(())
}

#[server(endpoint = "set_member_role")]
pub async fn set_member_role(
    organization: String,
    user: i64,
    role: String,
) -> Result<(), ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    let result = async {
        let id = organization_id(database, &actor, &organization).await?;
        let member =
            nanobom_domain::memberships::set_role(database, &actor, id, user, parse_role(&role)?)
                .await?;
        Ok(format!("{} is now {}.", member.username, member.role))
    }
    .await;
    finish(result, &format!("/organizations/{organization}/settings"));
    Ok(())
}

#[server(endpoint = "remove_member")]
pub async fn remove_member(organization: String, user: i64) -> Result<(), ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    let result = async {
        let id = organization_id(database, &actor, &organization).await?;
        nanobom_domain::memberships::remove(database, &actor, id, user).await?;
        Ok("Member removed.".to_owned())
    }
    .await;
    if result.is_ok() && user == actor.user_id {
        redirect_with("/organizations", Ok("You left the organization."));
        return Ok(());
    }
    finish(result, &format!("/organizations/{organization}/settings"));
    Ok(())
}

#[server(endpoint = "create_token")]
pub async fn create_token(
    organization: String,
    name: String,
    project: Option<String>,
) -> Result<(), ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    let result = async {
        let id = organization_id(database, &actor, &organization).await?;
        let project = project.as_deref().filter(|project| !project.is_empty());
        nanobom_domain::tokens::create(database, &actor, id, project, &name).await
    }
    .await;
    match result {
        Ok(created) => {
            let session = crate::server::session().await?.session;
            session
                .insert(NEW_TOKEN, created.secret)
                .await
                .map_err(|error| ServerFnError::new(error.to_string()))?;
            back(
                Ok("Token created. Copy it now: it will not be shown again."),
                &format!("/organizations/{organization}/settings"),
            );
        }
        Err(error) => back(
            Err(crate::server::message(error)),
            &format!("/organizations/{organization}/settings"),
        ),
    }
    Ok(())
}

#[server(endpoint = "revoke_token")]
pub async fn revoke_token(organization: String, token: i64) -> Result<(), ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    let result = nanobom_domain::tokens::revoke(database, &actor, token)
        .await
        .map(|()| "Token revoked.".to_owned());
    finish(result, &format!("/organizations/{organization}/settings"));
    Ok(())
}

#[server(endpoint = "save_webhook")]
pub async fn save_webhook(
    organization: String,
    url: String,
    minimum_severity: String,
    enabled: Option<String>,
) -> Result<(), ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    let result = async {
        let id = organization_id(database, &actor, &organization).await?;
        let severity = Severity::parse(&minimum_severity)
            .ok_or_else(|| nanobom_domain::Error::invalid("unknown severity"))?;
        nanobom_domain::notifications::set(
            database,
            &actor,
            id,
            &url,
            crate::server::domain_severity(severity),
            enabled.is_some(),
        )
        .await?;
        Ok("Webhook saved.".to_owned())
    }
    .await;
    finish(result, &format!("/organizations/{organization}/settings"));
    Ok(())
}

#[server(endpoint = "delete_webhook")]
pub async fn delete_webhook(organization: String) -> Result<(), ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    let result = async {
        let id = organization_id(database, &actor, &organization).await?;
        nanobom_domain::notifications::delete(database, &actor, id).await?;
        Ok("Webhook removed.".to_owned())
    }
    .await;
    finish(result, &format!("/organizations/{organization}/settings"));
    Ok(())
}

#[server(endpoint = "rename_organization")]
pub async fn rename_organization(organization: String, name: String) -> Result<(), ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    let result = async {
        let id = organization_id(database, &actor, &organization).await?;
        nanobom_domain::organizations::rename(database, &actor, id, &name).await?;
        Ok("Organization renamed.".to_owned())
    }
    .await;
    finish(result, &format!("/organizations/{organization}/settings"));
    Ok(())
}

#[server(endpoint = "delete_organization")]
pub async fn delete_organization(
    organization: String,
    confirmation: String,
) -> Result<(), ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    if confirmation.trim() != organization {
        back(
            Err("Type the organization's slug to confirm its deletion.".to_owned()),
            "/organizations",
        );
        return Ok(());
    }
    let result = async {
        let id = organization_id(database, &actor, &organization).await?;
        nanobom_domain::organizations::delete(database, &actor, id).await
    }
    .await;
    match result {
        Ok(()) => redirect_with("/organizations", Ok("Organization deleted.")),
        Err(error) => back(Err(crate::server::message(error)), "/organizations"),
    }
    Ok(())
}

#[server(endpoint = "delete_project")]
pub async fn delete_project(
    organization: String,
    project: String,
    confirmation: String,
) -> Result<(), ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    if confirmation.trim() != project {
        back(
            Err("Type the project's slug to confirm its deletion.".to_owned()),
            "/organizations",
        );
        return Ok(());
    }
    let result = async {
        let id = organization_id(database, &actor, &organization).await?;
        let found = nanobom_domain::projects::find(database, &actor, id, &project).await?;
        nanobom_domain::projects::delete(database, &actor, found.id).await
    }
    .await;
    match result {
        Ok(()) => redirect_with(
            &format!("/organizations/{organization}"),
            Ok("Project deleted."),
        ),
        Err(error) => back(Err(crate::server::message(error)), "/organizations"),
    }
    Ok(())
}

#[server(endpoint = "create_user")]
pub async fn create_user(
    username: String,
    email: Option<String>,
    password: String,
    administrator: Option<String>,
) -> Result<(), ServerFnError> {
    use nanobom_domain::{
        passwords::{self, PasswordPolicy},
        users::{self, NewUser},
    };
    let actor = actor().await?;
    let context = context()?;
    let result = async {
        PasswordPolicy {
            minimum_length: context.settings.password_minimum_length,
        }
        .validate(&password)?;
        let user = users::create_as(
            &context.database,
            &actor,
            NewUser {
                username,
                email: email.filter(|email| !email.trim().is_empty()),
                display_name: None,
                password_hash: Some(passwords::hash(password).await),
                is_instance_administrator: administrator.is_some(),
            },
            context.settings.personal_organizations,
        )
        .await?;
        Ok(format!("{} created.", user.username))
    }
    .await;
    finish(result, "/administration");
    Ok(())
}

#[server(endpoint = "set_user_disabled")]
pub async fn set_user_disabled(user: i64, disabled: bool) -> Result<(), ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    let result = nanobom_domain::users::set_disabled(database, &actor, user, disabled)
        .await
        .map(|()| {
            if disabled {
                "User disabled.".to_owned()
            } else {
                "User enabled.".to_owned()
            }
        });
    finish(result, "/administration");
    Ok(())
}

#[server(endpoint = "set_user_administrator")]
pub async fn set_user_administrator(user: i64, administrator: bool) -> Result<(), ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    let result =
        nanobom_domain::users::set_instance_administrator(database, &actor, user, administrator)
            .await
            .map(|()| "Administration rights updated.".to_owned());
    finish(result, "/administration");
    Ok(())
}

#[server(endpoint = "reset_password")]
pub async fn reset_password(user: i64, password: String) -> Result<(), ServerFnError> {
    use nanobom_domain::passwords::{self, PasswordPolicy};
    let actor = actor().await?;
    let context = context()?;
    let result = async {
        PasswordPolicy {
            minimum_length: context.settings.password_minimum_length,
        }
        .validate(&password)?;
        nanobom_domain::users::set_password_hash(
            &context.database,
            &actor,
            user,
            passwords::hash(password).await,
        )
        .await?;
        Ok("Password changed.".to_owned())
    }
    .await;
    finish(result, "/administration");
    Ok(())
}
