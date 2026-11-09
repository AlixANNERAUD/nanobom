//! Server functions: page data, and the actions behind the interface's forms.
//!
//! Actions are sent by plain HTML forms, so the interface works without JavaScript: each
//! action redirects back to the page it came from with a `notice` or `error` message.
//!
//! Each function is served at `/api/{endpoint}` and follows the same shape: [`actor`] (which
//! sends anonymous visitors to the sign-in page), then domain calls with that actor, which do
//! every permission check. Page loaders (`load_*`) return a [`crate::model`] type and turn domain
//! errors into an error status with [`failure`]. Actions return `Ok(())` even when the domain
//! refused: the outcome travels in the redirect ([`finish`], [`back`]), so the browser always
//! lands on a page. Cross-site posts are refused before they get here, by the server's CSRF
//! middleware.
//!
//! A few choices are not visible from the signatures:
//!
//! - a new upload token's secret goes through the session (`NEW_TOKEN`), never through a URL,
//!   and is shown once by the next settings page;
//! - deleting an organization or a project requires typing its slug, checked here before the
//!   domain is called;
//! - starting a run only queues it, after [`nanobom_domain::evaluation::authorize`]: the page
//!   comes back at once and shows the run when it is recorded.

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

#[server(endpoint = "load_organizations")]
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
    let projects = findings::overview(
        database,
        &actor,
        found.id,
        context()?.settings.stale_after_days,
    )
    .await
    .map_err(failure)?;
    let runs = evaluation::recent_runs(database, &actor, found.id, 5)
        .await
        .map_err(failure)?;
    let licenses = nanobom_domain::licenses::counts_by_project(database, &actor, found.id)
        .await
        .map_err(failure)?
        .unwrap_or_default();
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
                known_exploited: project.known_exploited,
                stale: project.stale,
                licenses: licenses
                    .get(&project.id)
                    .copied()
                    .map(crate::server::license_counts)
                    .unwrap_or_default(),
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
        exploited_only: filter.exploited,
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
    let stale = nanobom_domain::staleness::is_stale(
        model.created_at,
        model.last_upload_at,
        chrono::Utc::now().fixed_offset(),
        context()?.settings.stale_after_days,
    );
    let violations = nanobom_domain::licenses::violations(
        database,
        &actor,
        model.id,
        0,
        LicenseViolations::LISTED,
    )
    .await
    .map_err(failure)?;
    let licenses = violations.active.then(|| LicenseViolations {
        counts: crate::server::license_counts(violations.counts),
        items: violations
            .items
            .into_iter()
            .map(|violation| LicenseViolation {
                purl: violation.purl,
                name: violation.name,
                version: violation.version,
                license: violation.license,
                verdict: crate::server::license_action(violation.verdict),
                licenses: violation.licenses,
            })
            .collect(),
    });
    Ok(ProjectData {
        last_upload_at: model.last_upload_at,
        created_at: model.created_at,
        stale,
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
        licenses,
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
        ignored_by_token: detail.ignored_by_token,
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
                token: event.token,
                reason: event.reason,
                justification: event
                    .justification
                    .map(|justification| justification.as_str().to_owned()),
            })
            .collect(),
        dependency_paths: detail
            .dependency_paths
            .map(|paths| crate::model::DependencyPaths {
                paths: paths
                    .paths
                    .into_iter()
                    .map(|path| {
                        path.into_iter()
                            .map(crate::server::dependency_component)
                            .collect()
                    })
                    .collect(),
                more: paths.more,
                partial: paths.partial,
            }),
        finding: crate::server::finding(detail.finding),
    })
}

#[server(endpoint = "search_components")]
pub async fn search_components(
    query: String,
    license: String,
) -> Result<Vec<ComponentMatch>, ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    Ok(
        nanobom_domain::inventory::search_by_license(database, &actor, &query, &license)
            .await
            .map_err(failure)?
            .matches
            .into_iter()
            .map(|component| ComponentMatch {
                organization_slug: component.organization_slug,
                project_slug: component.project_slug,
                purl: component.purl,
                ecosystem: component.ecosystem,
                name: component.name,
                version: component.version,
                license: component.license,
            })
            .collect(),
    )
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
    let email = nanobom_domain::email::get(database, &actor, found.id)
        .await
        .map_err(failure)?;
    let deliveries = nanobom_domain::deliveries::recent(database, &actor, found.id, 10)
        .await
        .map_err(failure)?;
    let policy = nanobom_domain::licenses::policy(database, &actor, found.id)
        .await
        .map_err(failure)?;
    let rules = |action: nanobom_domain::licenses::Action| -> Vec<String> {
        policy
            .rules
            .iter()
            .filter(|rule| rule.action == action)
            .map(|rule| rule.license.clone())
            .collect()
    };
    let license_policy = LicensePolicy {
        unlisted: crate::server::license_action(policy.unlisted),
        unknown: crate::server::license_action(policy.unknown),
        allowed: rules(nanobom_domain::licenses::Action::Allow),
        warned: rules(nanobom_domain::licenses::Action::Warn),
        forbidden: rules(nanobom_domain::licenses::Action::Forbid),
    };
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
                read_only: token.scope == tokens::Scope::Read,
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
            exploited_only: webhook.exploited_only,
            format: webhook.format.as_str().to_owned(),
        }),
        email: email.map(|email| EmailSettings {
            recipients: email.recipients,
            language: email.language.as_str().to_owned(),
            minimum_severity: crate::server::severity(email.minimum_severity),
            exploited_only: email.exploited_only,
        }),
        email_available: context()?.mailer.is_some(),
        deliveries: deliveries
            .into_iter()
            .map(|delivery| WebhookDelivery {
                id: delivery.id,
                recipient: delivery.recipient,
                event: delivery.event,
                state: crate::server::delivery_state(delivery.state),
                attempts: delivery.attempts,
                created_at: delivery.created_at,
                last_attempt_at: delivery.last_attempt_at,
                last_status: delivery.last_status,
                next_attempt_at: delivery.next_attempt_at,
            })
            .collect(),
        license_policy,
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

/// Remembers the interface's language for a year, then returns to the page.
#[server(endpoint = "set_language")]
pub async fn set_language(locale: String) -> Result<(), ServerFnError> {
    use axum::http::{HeaderValue, header};
    if let Some(index) = embedded_i18n::match_locale(&locale)
        && let Some(response) = use_context::<leptos_axum::ResponseOptions>()
    {
        let cookie = format!(
            "{}={}; Path=/; Max-Age=31536000; SameSite=Lax",
            crate::i18n::COOKIE,
            crate::i18n::tag(index)
        );
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.append_header(header::SET_COOKIE, value);
        }
    }
    crate::server::back_quietly("/");
    Ok(())
}

#[server(endpoint = "create_organization")]
pub async fn create_organization(slug: String, name: String) -> Result<(), ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    match nanobom_domain::organizations::create(database, &actor, &slug, &name).await {
        Ok(organization) => redirect_with(
            &format!("/organizations/{}", organization.slug),
            Ok(crate::t!("notices.organization_created")),
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
        Ok(crate::t!("notices.run_started").to_owned())
    }
    .await;
    finish(result, &format!("/organizations/{organization}"));
    Ok(())
}

#[server(endpoint = "ignore_finding")]
pub async fn ignore_finding(
    finding: i64,
    reason: String,
    justification: Option<String>,
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
                back(Err(crate::t!("notices.invalid_expiry").to_owned()), "/");
                return Ok(());
            }
        },
        None => None,
    };
    let justification = match justification
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(nanobom_domain::findings::Justification::parse)
        .transpose()
    {
        Ok(justification) => justification,
        Err(error) => {
            finish(Err(error), &format!("/findings/{finding}"));
            return Ok(());
        }
    };
    let result = nanobom_domain::findings::ignore(
        database,
        &actor,
        finding,
        &reason,
        justification,
        expires_at,
    )
    .await
    .map(|()| crate::t!("notices.finding_ignored").to_owned());
    finish(result, &format!("/findings/{finding}"));
    Ok(())
}

#[server(endpoint = "restore_finding")]
pub async fn restore_finding(finding: i64) -> Result<(), ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    let result = nanobom_domain::findings::restore(database, &actor, finding)
        .await
        .map(|()| crate::t!("notices.finding_restored").to_owned());
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
        Ok(crate::tf!(
            "notices.member_added",
            username = member.username
        ))
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
        Ok(crate::tf!(
            "notices.member_role",
            username = member.username,
            role = crate::server::role(member.role).label().to_lowercase()
        ))
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
        Ok(crate::t!("notices.member_removed").to_owned())
    }
    .await;
    if result.is_ok() && user == actor.user_id {
        redirect_with("/organizations", Ok(crate::t!("notices.left_organization")));
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
    scope: Option<String>,
) -> Result<(), ServerFnError> {
    use nanobom_domain::tokens::{self, Scope};
    let actor = actor().await?;
    let database = &context()?.database;
    let result = async {
        let id = organization_id(database, &actor, &organization).await?;
        let project = project.as_deref().filter(|project| !project.is_empty());
        let scope = match scope.as_deref() {
            None | Some("") => Scope::Upload,
            Some(scope) => Scope::parse(scope)?,
        };
        tokens::create_with_scope(database, &actor, id, project, &name, scope).await
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
                Ok(crate::t!("notices.token_created")),
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
        .map(|()| crate::t!("notices.token_revoked").to_owned());
    finish(result, &format!("/organizations/{organization}/settings"));
    Ok(())
}

#[server(endpoint = "save_webhook")]
pub async fn save_webhook(
    organization: String,
    url: String,
    minimum_severity: String,
    enabled: Option<String>,
    exploited_only: Option<String>,
    format: Option<String>,
) -> Result<(), ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    let result = async {
        let id = organization_id(database, &actor, &organization).await?;
        let severity = Severity::parse(&minimum_severity).ok_or(nanobom_domain::Error::invalid(
            nanobom_domain::Problem::UnknownSeverity,
        ))?;
        // A form that predates the setting does not send it: JSON, as before.
        let format = match format.as_deref() {
            None | Some("") => nanobom_domain::notifications::Format::Json,
            Some(name) => nanobom_domain::notifications::Format::parse(name).ok_or(
                nanobom_domain::Error::invalid(nanobom_domain::Problem::UnknownWebhookFormat),
            )?,
        };
        nanobom_domain::notifications::set(
            database,
            &actor,
            id,
            &nanobom_domain::notifications::Webhook {
                url,
                minimum_severity: crate::server::domain_severity(severity),
                enabled: enabled.is_some(),
                exploited_only: exploited_only.is_some(),
                format,
            },
        )
        .await?;
        Ok(crate::t!("notices.webhook_saved").to_owned())
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
        Ok(crate::t!("notices.webhook_removed").to_owned())
    }
    .await;
    finish(result, &format!("/organizations/{organization}/settings"));
    Ok(())
}

/// Saves where the organization's notifications are emailed. Recipients are typed in one
/// field, separated by line breaks, commas or semicolons.
#[server(endpoint = "save_email")]
pub async fn save_email(
    organization: String,
    recipients: String,
    language: String,
    minimum_severity: String,
    exploited_only: Option<String>,
) -> Result<(), ServerFnError> {
    use nanobom_domain::email::{self, Language};
    let actor = actor().await?;
    let database = &context()?.database;
    let result = async {
        let id = organization_id(database, &actor, &organization).await?;
        let severity = Severity::parse(&minimum_severity).ok_or(nanobom_domain::Error::invalid(
            nanobom_domain::Problem::UnknownSeverity,
        ))?;
        let language = Language::parse(&language).ok_or(nanobom_domain::Error::invalid(
            nanobom_domain::Problem::UnknownEmailLanguage,
        ))?;
        email::set(
            database,
            &actor,
            id,
            &email::EmailSettings {
                recipients: email::split_recipients(&recipients)
                    .map(str::to_owned)
                    .collect(),
                language,
                minimum_severity: crate::server::domain_severity(severity),
                exploited_only: exploited_only.is_some(),
            },
        )
        .await?;
        Ok(crate::t!("notices.email_saved").to_owned())
    }
    .await;
    finish(result, &format!("/organizations/{organization}/settings"));
    Ok(())
}

#[server(endpoint = "delete_email")]
pub async fn delete_email(organization: String) -> Result<(), ServerFnError> {
    let actor = actor().await?;
    let database = &context()?.database;
    let result = async {
        let id = organization_id(database, &actor, &organization).await?;
        nanobom_domain::email::delete(database, &actor, id).await?;
        Ok(crate::t!("notices.email_removed").to_owned())
    }
    .await;
    finish(result, &format!("/organizations/{organization}/settings"));
    Ok(())
}

/// Sends a test email to the saved recipients at once; the page shows the SMTP server's reply
/// when it refuses.
#[server(endpoint = "send_test_email")]
pub async fn send_test_email(organization: String) -> Result<(), ServerFnError> {
    let actor = actor().await?;
    let context = context()?;
    let database = &context.database;
    let result = async {
        let id = organization_id(database, &actor, &organization).await?;
        nanobom_domain::email::send_test(
            database,
            &actor,
            id,
            context.mailer.as_ref(),
            &context.settings.public_url,
        )
        .await?;
        Ok(crate::t!("notices.test_email_sent").to_owned())
    }
    .await;
    finish(result, &format!("/organizations/{organization}/settings"));
    Ok(())
}

/// Replaces the license policy: the two defaults, and the rules typed in three lists (allowed,
/// warned, forbidden identifiers, separated by whitespace or commas).
#[server(endpoint = "save_license_policy")]
pub async fn save_license_policy(
    organization: String,
    unlisted: String,
    unknown: String,
    allowed: String,
    warned: String,
    forbidden: String,
) -> Result<(), ServerFnError> {
    use nanobom_domain::licenses::{self, Action, Policy, Rule};
    let actor = actor().await?;
    let database = &context()?.database;
    let result = async {
        let id = organization_id(database, &actor, &organization).await?;
        let mut rules = Vec::new();
        for (list, action) in [
            (&allowed, Action::Allow),
            (&warned, Action::Warn),
            (&forbidden, Action::Forbid),
        ] {
            rules.extend(licenses::split_identifiers(list).map(|license| Rule {
                license: license.to_owned(),
                action,
            }));
        }
        licenses::set_policy(
            database,
            &actor,
            id,
            &Policy {
                unlisted: Action::parse(&unlisted)?,
                unknown: Action::parse(&unknown)?,
                rules,
            },
        )
        .await?;
        Ok(crate::t!("notices.license_policy_saved").to_owned())
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
        Ok(crate::t!("notices.organization_renamed").to_owned())
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
            Err(crate::t!("notices.confirm_organization").to_owned()),
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
        Ok(()) => redirect_with(
            "/organizations",
            Ok(crate::t!("notices.organization_deleted")),
        ),
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
            Err(crate::t!("notices.confirm_project").to_owned()),
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
            Ok(crate::t!("notices.project_deleted")),
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
        Ok(crate::tf!("notices.user_created", username = user.username))
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
                crate::t!("notices.user_disabled").to_owned()
            } else {
                crate::t!("notices.user_enabled").to_owned()
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
            .map(|()| crate::t!("notices.administrator_updated").to_owned());
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
        Ok(crate::t!("notices.password_changed").to_owned())
    }
    .await;
    finish(result, "/administration");
    Ok(())
}
