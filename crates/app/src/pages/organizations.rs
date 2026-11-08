//! Sign-in, the list of organizations and an organization's projects.

use leptos::prelude::*;
use leptos_meta::Title;
use leptos_router::hooks::{use_params_map, use_query_map};

use crate::{
    components::{Empty, Heading, Loaded, Page, SeverityBadge, action, format_time, ui::*},
    functions::{
        CreateOrganization, TriggerRun, load_organization, load_organizations, load_sign_in_options,
    },
    model::{Organization, OrganizationData, Run, Severity, SeverityCounts, SignInOptions},
    t, tf, tp,
};

fn sign_in_error(code: &str) -> &'static str {
    match code {
        "invalid" => t!("sign_in.error_invalid"),
        "unknown" => t!("sign_in.error_unknown"),
        "disabled" => t!("sign_in.error_disabled"),
        "expired" => t!("sign_in.error_expired"),
        "provider" => t!("sign_in.error_provider"),
        _ => t!("sign_in.error_unavailable"),
    }
}

#[component]
pub fn SignInPage() -> impl IntoView {
    let query = use_query_map();
    let next = move || {
        query
            .read()
            .get("next")
            .unwrap_or_else(|| "/organizations".to_owned())
    };
    let error = move || query.read().get("error").map(|code| sign_in_error(&code));
    let options = Resource::new(|| (), |()| load_sign_in_options());
    let title = format!("{} · nanobom", t!("sign_in.title"));
    view! {
        <Title text=title />
        <main id="content" class="mx-auto grid max-w-sm gap-6 px-4 py-16">
            <div class="grid gap-1 text-center">
                <h1 class="text-2xl font-semibold tracking-tight">"nanobom"</h1>
                <p class="text-muted-foreground text-sm">{t!("sign_in.subtitle")}</p>
            </div>
            {move || error().map(|error| view! { <Alert variant=AlertVariant::Destructive>{error}</Alert> })}
            <Loaded
                resource=options
                render={move |options: SignInOptions| {
                    let next = next();
                    view! {
                        <Card>
                            <CardContent>
                                <div class="grid gap-4">
                                    {options
                                        .local_accounts
                                        .then(|| {
                                            view! {
                                                <form method="post" action="/auth/login" class="grid gap-4">
                                                    <input type="hidden" name="next" value=next.clone() />
                                                    <Field label=t!("sign_in.login") input_id="login">
                                                        <input
                                                            id="login"
                                                            name="login"
                                                            class=INPUT
                                                            autocomplete="username"
                                                            required
                                                            autofocus
                                                        />
                                                    </Field>
                                                    <Field label=t!("sign_in.password") input_id="password">
                                                        <input
                                                            id="password"
                                                            name="password"
                                                            type="password"
                                                            class=INPUT
                                                            autocomplete="current-password"
                                                            required
                                                        />
                                                    </Field>
                                                    <Button>{t!("sign_in.submit")}</Button>
                                                </form>
                                            }
                                        })}
                                    {options
                                        .openid_button
                                        .map(|label| {
                                            let href = format!(
                                                "/auth/oidc/login?next={}",
                                                next.replace('%', "%25").replace('&', "%26").replace('?', "%3F"),
                                            );
                                            view! {
                                                <LinkButton href variant=ButtonVariant::Outline>
                                                    {label}
                                                </LinkButton>
                                            }
                                        })}
                                </div>
                            </CardContent>
                        </Card>
                    }
                }}
            />
        </main>
    }
}

#[component]
pub fn OrganizationsPage() -> impl IntoView {
    let list = Resource::new(|| (), |()| load_organizations());
    view! {
        <Page title=t!("organizations.title")>
            <Heading title=t!("organizations.title") subtitle=t!("organizations.subtitle") />
            <Loaded
                resource=list
                render={|organizations: Vec<Organization>| {
                    if organizations.is_empty() {
                        view! {
                            <Empty title=t!("organizations.empty_title")>
                                {t!("organizations.empty_text")}
                            </Empty>
                        }
                            .into_any()
                    } else {
                        view! {
                            <ul class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                                {organizations
                                    .into_iter()
                                    .map(|organization| {
                                        let href = format!("/organizations/{}", organization.slug);
                                        view! {
                                            <li>
                                                <a
                                                    href=href
                                                    class="bg-card hover:bg-accent focus-visible:ring-ring/50 block rounded-xl border p-4 shadow-sm outline-none focus-visible:ring-[3px]"
                                                >
                                                    <span class="font-medium">{organization.name}</span>
                                                    <span class="text-muted-foreground block text-sm">
                                                        {organization.slug} " · " {organization.role.label()}
                                                        {organization.is_personal.then(|| format!(" · {}", t!("common.personal")))}
                                                    </span>
                                                </a>
                                            </li>
                                        }
                                    })
                                    .collect_view()}
                            </ul>
                        }
                            .into_any()
                    }
                }}
            />
            <Card>
                <CardHeader>
                    <CardTitle>{t!("organizations.new_title")}</CardTitle>
                    <CardDescription>{t!("organizations.new_description")}</CardDescription>
                </CardHeader>
                <CardContent>
                    <form
                        method="post"
                        action={action::<CreateOrganization>()}
                        class="grid gap-4 sm:grid-cols-[1fr_1fr_auto] sm:items-end"
                    >
                        <Field label=t!("organizations.name") input_id="organization-name">
                            <input id="organization-name" name="name" class=INPUT required />
                        </Field>
                        <Field label=t!("organizations.slug") input_id="organization-slug">
                            <input
                                id="organization-slug"
                                name="slug"
                                class=INPUT
                                required
                                pattern="[A-Za-z0-9][A-Za-z0-9._\\-]{0,63}"
                                placeholder="acme"
                            />
                        </Field>
                        <Button>{t!("organizations.create")}</Button>
                    </form>
                </CardContent>
            </Card>
        </Page>
    }
}

fn severity_cells(open: SeverityCounts) -> impl IntoView {
    Severity::DESCENDING
        .into_iter()
        .map(move |severity| {
            let count = open.get(severity);
            view! {
                <td class=format!("{TABLE_CELL} text-right tabular-nums")>
                    {if count == 0 {
                        view! { <span class="text-muted-foreground">"0"</span> }.into_any()
                    } else {
                        view! { <span class="font-semibold">{count}</span> }.into_any()
                    }}
                </td>
            }
        })
        .collect_view()
}

fn trigger_label(trigger: &str) -> String {
    match trigger {
        "scheduled" => t!("organization.trigger_scheduled").to_owned(),
        "manual" => t!("organization.trigger_manual").to_owned(),
        "upload" => t!("organization.trigger_upload").to_owned(),
        other => other.to_owned(),
    }
}

fn scope_label(scope: &str) -> String {
    match scope {
        "all" => t!("organization.scope_all").to_owned(),
        "organization" => t!("organization.scope_organization").to_owned(),
        "project" => t!("organization.scope_project").to_owned(),
        other => other.to_owned(),
    }
}

#[component]
fn RunHistory(runs: Vec<Run>) -> impl IntoView {
    if runs.is_empty() {
        return view! {
            <p class="text-muted-foreground text-sm">{t!("organization.no_run")}</p>
        }
        .into_any();
    }
    view! {
        <ul class="grid gap-2 text-sm">
            {runs
                .into_iter()
                .map(|run| {
                    let failed = run.status == "failed";
                    view! {
                        <li class="flex flex-wrap items-baseline gap-x-2">
                            <span class=if failed { "text-destructive font-medium" } else { "font-medium" }>
                                {match run.status.as_str() {
                                    "succeeded" => t!("organization.run_succeeded"),
                                    "failed" => t!("organization.run_failed"),
                                    _ => t!("organization.run_running"),
                                }}
                            </span>
                            <span class="text-muted-foreground">
                                {format_time(run.started_at)} " · " {trigger_label(&run.trigger)} " · "
                                {scope_label(&run.scope)}
                            </span>
                            {(!failed && run.status == "succeeded")
                                .then(|| {
                                    view! {
                                        <span>
                                            {tp!("organization.run_new", run.new_findings)} ", "
                                            {tp!("organization.run_fixed", run.fixed_findings)}
                                        </span>
                                    }
                                })}
                            {run.error.map(|error| view! { <span class="text-destructive">{error}</span> })}
                        </li>
                    }
                })
                .collect_view()}
        </ul>
    }
    .into_any()
}

#[component]
pub fn OrganizationPage() -> impl IntoView {
    let params = use_params_map();
    let slug = move || params.read().get("organization").unwrap_or_default();
    let page = Resource::new(slug, load_organization);
    view! {
        <Page title=t!("organization.title")>
            <Loaded
                resource=page
                render={|page: OrganizationData| {
                    let organization = page.organization.clone();
                    let slug = organization.slug.clone();
                    let check_now = organization.role.can_triage().then({
                        let slug = slug.clone();
                        move || {
                            view! {
                                <form method="post" action={action::<TriggerRun>()}>
                                    <input type="hidden" name="organization" value=slug />
                                    <Button variant=ButtonVariant::Outline>{t!("organization.check_now")}</Button>
                                </form>
                            }
                        }
                    });
                    let settings = organization.role.can_manage().then({
                        let href = format!("/organizations/{slug}/settings");
                        move || {
                            view! {
                                <LinkButton href variant=ButtonVariant::Secondary>
                                    {t!("organization.settings")}
                                </LinkButton>
                            }
                        }
                    });
                    let rows = page
                        .projects
                        .iter()
                        .map(|project| {
                            let href = format!("/organizations/{}/projects/{}", slug, project.slug);
                            let cells = severity_cells(project.open);
                            let ignored = project.ignored;
                            let known_exploited = project.known_exploited;
                            let name = project.name.clone();
                            let last_upload = project
                                .last_upload_at
                                .map_or_else(|| t!("organization.never").to_owned(), format_time);
                            let stale_badge = project.stale.then(|| {
                                let title = match project.last_upload_at {
                                    Some(time) => {
                                        tf!("organization.stale_title", date = format_time(time))
                                    }
                                    None => t!("organization.stale_never_title").to_owned(),
                                };
                                view! {
                                    <Badge variant=BadgeVariant::Outline title=title>
                                        {t!("organization.stale")}
                                    </Badge>
                                }
                            });
                            view! {
                                <tr class=TABLE_ROW>
                                    <th scope="row" class=format!("{TABLE_CELL} text-left font-medium")>
                                        <a class="underline-offset-4 hover:underline" href=href>
                                            {name}
                                        </a>
                                        {stale_badge}
                                    </th>
                                    {cells}
                                    <td class=format!("{TABLE_CELL} text-right tabular-nums")>
                                        {known_exploited}
                                    </td>
                                    <td class=format!("{TABLE_CELL} text-right tabular-nums text-muted-foreground")>
                                        {ignored}
                                    </td>
                                    <td class=format!("{TABLE_CELL} whitespace-nowrap text-muted-foreground")>
                                        {last_upload}
                                    </td>
                                </tr>
                            }
                        })
                        .collect_view();
                    let projects = if page.projects.is_empty() {
                        view! {
                            <Empty title=t!("organization.no_project_title")>
                                {t!("organization.no_project_text")}
                            </Empty>
                        }
                            .into_any()
                    } else {
                        let headers = Severity::DESCENDING
                            .into_iter()
                            .map(|severity| {
                                view! {
                                    <th scope="col" class=format!("{TABLE_HEAD} text-right")>
                                        <SeverityBadge severity />
                                    </th>
                                }
                            })
                            .collect_view();
                        view! {
                            <Table caption=t!("organization.projects_caption")>
                                <thead>
                                    <tr class=TABLE_HEAD_ROW>
                                        <th scope="col" class=TABLE_HEAD>{t!("organization.project")}</th>
                                        {headers}
                                        <th scope="col" class=format!("{TABLE_HEAD} text-right")>{t!("organization.known_exploited")}</th>
                                        <th scope="col" class=format!("{TABLE_HEAD} text-right")>{t!("organization.ignored")}</th>
                                        <th scope="col" class=TABLE_HEAD>{t!("organization.last_upload")}</th>
                                    </tr>
                                </thead>
                                <tbody>{rows}</tbody>
                            </Table>
                        }
                            .into_any()
                    };
                    let subtitle = format!("{} · {}", organization.slug, organization.role.label());
                    view! {
                        <Title text=format!("{} · nanobom", organization.name) />
                        <Heading title=organization.name.clone() subtitle>
                            {check_now}
                            {settings}
                        </Heading>
                        {projects}
                        <Card>
                            <CardHeader>
                                <CardTitle>{t!("organization.runs_title")}</CardTitle>
                                <CardDescription>{t!("organization.runs_description")}</CardDescription>
                            </CardHeader>
                            <CardContent>
                                <RunHistory runs=page.runs />
                            </CardContent>
                        </Card>
                    }
                }}
            />
        </Page>
    }
}
