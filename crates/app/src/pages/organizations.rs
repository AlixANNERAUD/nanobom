//! Sign-in, the list of organizations and an organization's projects.

use leptos::prelude::*;
use leptos_router::hooks::{use_params_map, use_query_map};

use crate::{
    components::{
        Empty, Heading, Loaded, Page, PageTitle, SeverityBadge, action, format_date, format_time,
        ui::*,
    },
    functions::{
        CreateOrganization, CreateProject, TriggerRun, load_organization, load_organizations,
        load_sign_in_options,
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
    view! {
        <PageTitle text=t!("sign_in.title") />
        <main id="content" class="mx-auto grid max-w-sm gap-6 px-4 py-16">
            <div class="grid gap-1 text-center">
                <h1 class="flex items-center justify-center gap-2 text-2xl font-semibold tracking-tight">
                    <Mark class="size-6" />
                    "nanobom"
                </h1>
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
                                                    class="bg-card hover:bg-accent focus-visible:ring-ring/70 block rounded-xl border p-4 shadow-sm outline-none focus-visible:ring-[3px]"
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

/// How much of its track a project's bar fills, as a percentage: its open findings against
/// those of the project that has the most, so the bars of a page compare and the worst project
/// stands out. Rounded up, so a project with any finding shows a bar.
fn bar_share(total: u64, largest: u64) -> u64 {
    (total.saturating_mul(100))
        .div_ceil(largest.max(1))
        .clamp(u64::from(total > 0), 100)
}

pub(crate) fn severity_cells(open: SeverityCounts) -> impl IntoView {
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

/// A count of the runs table; the cell is empty when the run has nothing to count.
fn run_count(count: Option<i64>) -> impl IntoView {
    view! {
        <td class=format!("{TABLE_CELL} text-right tabular-nums")>
            {count
                .map(|count| {
                    if count == 0 {
                        view! { <span class="text-muted-foreground">"0"</span> }.into_any()
                    } else {
                        view! { <span class="font-semibold">{count}</span> }.into_any()
                    }
                })}
        </td>
    }
}

/// The runs of an organization as a table, newest first. Each run is a group of rows
/// (`<tbody>`): its own, and under it the error message of a failed run across the whole width,
/// so the message has room to wrap and the line between runs stays under the pair.
#[component]
fn RunHistory(runs: Vec<Run>) -> impl IntoView {
    if runs.is_empty() {
        return view! {
            <p class="text-muted-foreground text-sm">{t!("organization.no_run")}</p>
        }
        .into_any();
    }
    let groups = runs
        .into_iter()
        .map(|run| {
            let (variant, status) = match run.status.as_str() {
                "succeeded" => (BadgeVariant::Outline, t!("organization.run_succeeded")),
                "failed" => (BadgeVariant::Destructive, t!("organization.run_failed")),
                _ => (BadgeVariant::Muted, t!("organization.run_running")),
            };
            // Only a run that succeeded has counts to show: a failed run changed nothing, and a
            // running one has not counted yet.
            let (new, fixed) = if run.status == "succeeded" {
                (run.new_findings, run.fixed_findings)
            } else {
                (None, None)
            };
            let error = run.error.map(|error| {
                view! {
                    <tr>
                        <td colspan="6" class="text-destructive px-3 pb-2 wrap-anywhere">
                            {error}
                        </td>
                    </tr>
                }
            });
            view! {
                <tbody class=TABLE_ROW>
                    <tr>
                        <td class=TABLE_CELL>
                            <Badge variant>{status}</Badge>
                        </td>
                        <th
                            scope="row"
                            class=format!("{TABLE_CELL} text-left font-normal whitespace-nowrap tabular-nums")
                        >
                            {format_time(run.started_at)}
                        </th>
                        <td class=TABLE_CELL>{trigger_label(&run.trigger)}</td>
                        <td class=TABLE_CELL>{scope_label(&run.scope)}</td>
                        {run_count(new)}
                        {run_count(fixed)}
                    </tr>
                    {error}
                </tbody>
            }
        })
        .collect_view();
    view! {
        // A fixed layout, like the projects table: every column but the scope has a width that
        // fits its longest label in English and in French, and the scope takes what is left.
        // The minimum width keeps the scope readable on a narrow page, where the table scrolls
        // inside its frame.
        <Table caption=t!("organization.runs_title") class="min-w-[55rem] table-fixed">
            <thead>
                <tr class=TABLE_HEAD_ROW>
                    <th scope="col" class=format!("{TABLE_HEAD} w-32")>{t!("organization.run_status")}</th>
                    <th scope="col" class=format!("{TABLE_HEAD} w-[12.5rem]")>{t!("organization.run_started")}</th>
                    <th scope="col" class=format!("{TABLE_HEAD} w-32")>{t!("organization.run_trigger")}</th>
                    <th scope="col" class=TABLE_HEAD>{t!("organization.run_scope")}</th>
                    <th scope="col" class=format!("{TABLE_HEAD} w-28 text-right")>{t!("organization.run_new")}</th>
                    <th scope="col" class=format!("{TABLE_HEAD} w-28 text-right")>{t!("organization.run_fixed")}</th>
                </tr>
            </thead>
            {groups}
        </Table>
    }
    .into_any()
}

/// The head of a severity column of the projects table. Its padding is narrower than
/// `TABLE_HEAD`'s, so the badge fits a column hardly wider than a count needs; the count below
/// then ends where the text of the badge does.
const SEVERITY_HEAD: &str = "h-9 w-[5.5rem] px-1 text-right align-middle whitespace-nowrap";

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
                    let largest = page
                        .projects
                        .iter()
                        .map(|project| project.open.total())
                        .max()
                        .unwrap_or_default();
                    let rows = page
                        .projects
                        .iter()
                        .map(|project| {
                            let href = format!("/organizations/{}/projects/{}", slug, project.slug);
                            let cells = severity_cells(project.open);
                            let ignored = project.ignored;
                            let known_exploited = project.known_exploited;
                            let name = project.name.clone();
                            let counts = project.open;
                            // The day is enough to tell a project that stopped uploading. The
                            // tooltip gives the time to those with a pointer, the project page
                            // to everyone.
                            let last_upload = project
                                .last_upload_at
                                .map_or_else(|| t!("organization.never").to_owned(), format_date);
                            let last_upload_time = project.last_upload_at.map(format_time);
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
                            // Forbidden licenses outrank warnings: one badge, the most severe.
                            let licenses = project.licenses;
                            let license_badge = if licenses.forbidden > 0 {
                                Some(view! {
                                    <Badge variant=BadgeVariant::Destructive>
                                        {tp!("organization.licenses_forbidden", licenses.forbidden)}
                                    </Badge>
                                })
                            } else if licenses.warned > 0 {
                                Some(view! {
                                    <Badge variant=BadgeVariant::Outline>
                                        {tp!("organization.licenses_warned", licenses.warned)}
                                    </Badge>
                                })
                            } else {
                                None
                            };
                            // The bar fills its track as far as the project's findings go
                            // against the largest project's. Its segments keep their minimum
                            // width (`min-w-fit`), so a small project still shows each severity.
                            let bar = if counts.total() == 0 {
                                view! { <SeverityBar counts /> }.into_any()
                            } else {
                                let share = bar_share(counts.total(), largest);
                                view! {
                                    <div class="bg-muted-foreground/20 overflow-hidden rounded-full">
                                        <div class="min-w-fit" style=format!("width:{share}%")>
                                            <SeverityBar counts />
                                        </div>
                                    </div>
                                }
                                    .into_any()
                            };
                            view! {
                                <tr class=TABLE_ROW>
                                    <th scope="row" class=format!("{TABLE_CELL} text-left font-medium")>
                                        // The name is cut when it does not fit, and its tooltip
                                        // keeps all of it. Badges that do not fit next to it go
                                        // under it: they never take the name's room.
                                        <div class="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
                                            <a
                                                class="max-w-full min-w-0 truncate underline-offset-4 hover:underline"
                                                href=href
                                                title=name.clone()
                                            >
                                                {name.clone()}
                                            </a>
                                            {stale_badge}
                                            {license_badge}
                                        </div>
                                    </th>
                                    <td class=TABLE_CELL>{bar}</td>
                                    {cells}
                                    <td class=format!("{TABLE_CELL} text-right tabular-nums")>
                                        {known_exploited}
                                    </td>
                                    <td class=format!("{TABLE_CELL} text-right tabular-nums text-muted-foreground")>
                                        {ignored}
                                    </td>
                                    <td
                                        class=format!("{TABLE_CELL} whitespace-nowrap text-muted-foreground")
                                        title=last_upload_time
                                    >
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
                                    <th scope="col" class=SEVERITY_HEAD>
                                        <SeverityBadge severity />
                                    </th>
                                }
                            })
                            .collect_view();
                        view! {
                            // A fixed layout: every column but the project has a width that fits
                            // its longest label in English and in French, and the project takes
                            // what is left, so the table fits a 1280 px page without scrolling
                            // and a long name is cut instead of widening it. The minimum width
                            // leaves the project as much room as the bar: on a phone the table
                            // scrolls inside its frame, with the name and the bar in view first.
                            <Table caption=t!("organization.projects_caption") class="min-w-[65.5rem] table-fixed">
                                <thead>
                                    <tr class=TABLE_HEAD_ROW>
                                        <th scope="col" class=TABLE_HEAD>{t!("organization.project")}</th>
                                        // The bar is decorative and has no heading: the counts
                                        // after it say the same to everyone.
                                        <td class="w-40"></td>
                                        {headers}
                                        // Short, as on the project page, since the column holds
                                        // a count: the full words are what is read aloud and
                                        // what the tooltip says.
                                        <th
                                            scope="col"
                                            class=format!("{TABLE_HEAD} w-16 text-right")
                                            title=t!("organization.known_exploited")
                                        >
                                            <span class="sr-only">{t!("organization.known_exploited")}</span>
                                            <span aria-hidden="true">{t!("project.known_exploited_tag")}</span>
                                        </th>
                                        <th scope="col" class=format!("{TABLE_HEAD} w-24 text-right")>{t!("organization.ignored")}</th>
                                        <th scope="col" class=format!("{TABLE_HEAD} w-32")>{t!("organization.last_upload")}</th>
                                    </tr>
                                </thead>
                                <tbody>{rows}</tbody>
                            </Table>
                        }
                            .into_any()
                    };
                    let new_project = organization.role.can_manage().then({
                        let slug = slug.clone();
                        move || view! { <NewProject organization=slug /> }
                    });
                    let subtitle = format!("{} · {}", organization.slug, organization.role.label());
                    view! {
                        <PageTitle text=organization.name.clone() />
                        <Heading title=organization.name.clone() subtitle>
                            {check_now}
                            {settings}
                        </Heading>
                        {projects}
                        {new_project}
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

/// The form that creates a project, for those who manage projects. The project page it leads
/// to shows the new project's upload token.
#[component]
fn NewProject(organization: String) -> impl IntoView {
    view! {
        <Card>
            <CardHeader>
                <CardTitle>{t!("organization.new_project_title")}</CardTitle>
                <CardDescription>{t!("organization.new_project_description")}</CardDescription>
            </CardHeader>
            <CardContent>
                <form
                    method="post"
                    action={action::<CreateProject>()}
                    class="grid gap-4 sm:grid-cols-[1fr_1fr_auto] sm:items-start"
                >
                    <input type="hidden" name="organization" value=organization />
                    <Field
                        label=t!("organization.project_slug")
                        input_id="project-slug"
                        hint=t!("organization.project_slug_hint")
                    >
                        <input
                            id="project-slug"
                            name="slug"
                            class=INPUT
                            required
                            pattern="[A-Za-z0-9][A-Za-z0-9._\\-]{0,63}"
                            placeholder="web"
                            autocomplete="off"
                        />
                    </Field>
                    <Field
                        label=t!("organization.project_name")
                        input_id="project-name"
                        hint=t!("organization.project_name_hint")
                    >
                        <input id="project-name" name="name" class=INPUT />
                    </Field>
                    // Level with the inputs, whose labels sit above them.
                    <div class="sm:pt-[1.375rem]">
                        <Button>{t!("organization.create_project")}</Button>
                    </div>
                </form>
            </CardContent>
        </Card>
    }
}

#[cfg(test)]
mod tests {
    use super::bar_share;

    #[test]
    fn a_bar_fills_its_track_as_its_project_compares_to_the_largest() {
        assert_eq!(bar_share(142, 142), 100);
        assert_eq!(bar_share(71, 142), 50);
        // Rounded up: one finding among thousands still shows.
        assert_eq!(bar_share(1, 3), 34);
        assert_eq!(bar_share(1, 5000), 1);
        assert_eq!(bar_share(0, 142), 0);
        // Nothing to compare with, and counts that cannot be: never past the track.
        assert_eq!(bar_share(0, 0), 0);
        assert_eq!(bar_share(5, 0), 100);
        assert_eq!(bar_share(u64::MAX, 1), 100);
    }
}
