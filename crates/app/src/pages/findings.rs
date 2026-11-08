//! A project's findings, a finding's details and the component search.

use leptos::prelude::*;
use leptos_meta::Title;
use leptos_router::hooks::{use_params_map, use_query_map};

use crate::{
    components::{
        Empty, Heading, Loaded, Page, SeverityBadge, StatusBadge, action, format_date, format_time,
        ui::*,
    },
    functions::{
        DeleteProject, IgnoreFinding, RestoreFinding, TriggerRun, load_finding, load_project,
        search_components,
    },
    model::{
        ComponentMatch, FindingData, FindingFilter, FindingRow, ProjectData, Severity, Status,
    },
};

fn finding_rows(findings: Vec<FindingRow>) -> impl IntoView {
    findings
        .into_iter()
        .map(|finding| {
            let href = format!("/findings/{}", finding.id);
            view! {
                <tr class=TABLE_ROW>
                    <td class=TABLE_CELL>
                        <SeverityBadge severity=finding.severity />
                        {finding
                            .cvss_score
                            .map(|score| {
                                view! {
                                    <span class="text-muted-foreground ml-1 text-xs tabular-nums">
                                        {format!("{score:.1}")}
                                    </span>
                                }
                            })}
                    </td>
                    <th scope="row" class=format!("{TABLE_CELL} text-left font-normal")>
                        <a href=href.clone() class="font-medium underline-offset-4 hover:underline">
                            {finding.vulnerability_id.clone()}
                        </a>
                        <span class="text-muted-foreground block max-w-md truncate text-xs">
                            {finding.summary.clone().unwrap_or_default()}
                        </span>
                    </th>
                    <td class=TABLE_CELL>
                        <span class="font-medium">{finding.component_name.clone()}</span>
                        <span class="text-muted-foreground block text-xs">
                            {finding.component_version.clone().unwrap_or_default()} " · "
                            {finding.ecosystem.clone()}
                        </span>
                    </td>
                    <td class=TABLE_CELL>
                        <StatusBadge status=finding.status />
                    </td>
                    <td class=format!("{TABLE_CELL} whitespace-nowrap text-muted-foreground")>
                        {format_date(finding.first_seen_at)}
                    </td>
                </tr>
            }
        })
        .collect_view()
}

#[component]
fn Filters(page: ProjectData, filter: FindingFilter) -> impl IntoView {
    let selected = |current: &Option<String>, value: &str| current.as_deref() == Some(value);
    view! {
        <form method="get" class="flex flex-wrap items-end gap-3" aria-label="Filter findings">
            <div class="grid gap-2">
                <label class=LABEL for="filter-severity">"Severity"</label>
                <select id="filter-severity" name="severity" class=SELECT>
                    <option value="">"Any"</option>
                    {Severity::DESCENDING
                        .into_iter()
                        .map(|severity| {
                            view! {
                                <option
                                    value=severity.as_str()
                                    selected=selected(&filter.severity, severity.as_str())
                                >
                                    {severity.label()}
                                </option>
                            }
                        })
                        .collect_view()}
                </select>
            </div>
            <div class="grid gap-2">
                <label class=LABEL for="filter-status">"Status"</label>
                <select id="filter-status" name="status" class=SELECT>
                    <option value="">"Open and ignored"</option>
                    {Status::ALL
                        .into_iter()
                        .map(|status| {
                            view! {
                                <option
                                    value=status.as_str()
                                    selected=selected(&filter.status, status.as_str())
                                >
                                    {status.label()}
                                </option>
                            }
                        })
                        .collect_view()}
                    <option value="all" selected=selected(&filter.status, "all")>"All"</option>
                </select>
            </div>
            <div class="grid gap-2">
                <label class=LABEL for="filter-ecosystem">"Ecosystem"</label>
                <select id="filter-ecosystem" name="ecosystem" class=SELECT>
                    <option value="">"Any"</option>
                    {page
                        .ecosystems
                        .into_iter()
                        .map(|ecosystem| {
                            let is_selected = selected(&filter.ecosystem, &ecosystem);
                            view! {
                                <option value=ecosystem.clone() selected=is_selected>
                                    {ecosystem.clone()}
                                </option>
                            }
                        })
                        .collect_view()}
                </select>
            </div>
            <Button variant=ButtonVariant::Secondary>"Filter"</Button>
        </form>
    }
}

#[component]
pub fn ProjectPage() -> impl IntoView {
    let params = use_params_map();
    let query = use_query_map();
    let key = move || {
        let params = params.read();
        let query = query.read();
        let nonempty = |name: &str| query.get(name).filter(|value| !value.is_empty());
        (
            params.get("organization").unwrap_or_default(),
            params.get("project").unwrap_or_default(),
            FindingFilter {
                severity: nonempty("severity"),
                status: nonempty("status"),
                ecosystem: nonempty("ecosystem"),
            },
        )
    };
    let page = Resource::new(key, |(organization, project, filter)| {
        load_project(organization, project, filter)
    });
    view! {
        <Page title="Project">
            <Loaded
                resource=page
                render={move |page: ProjectData| {
                    let (_, _, filter) = key();
                    let organization = page.organization.clone();
                    let organization_slug = organization.slug.clone();
                    let project_slug = page.slug.clone();
                    let latest = page.uploads.first().cloned();
                    let subtitle = format!(
                        "{} components{}",
                        page.component_count,
                        latest
                            .as_ref()
                            .map(|upload| format!(" · last upload {}", format_time(upload.uploaded_at)))
                            .unwrap_or_default(),
                    );
                    let check_now = organization.role.can_triage().then({
                        let organization_slug = organization_slug.clone();
                        let project_slug = project_slug.clone();
                        move || {
                            view! {
                                <form method="post" action={action::<TriggerRun>()}>
                                    <input type="hidden" name="organization" value=organization_slug />
                                    <input type="hidden" name="project" value=project_slug />
                                    <Button variant=ButtonVariant::Outline>"Check now"</Button>
                                </form>
                            }
                        }
                    });
                    let without_purl = latest
                        .as_ref()
                        .map(|upload| upload.components_without_purl)
                        .filter(|count| *count > 0)
                        .map(|count| {
                            view! {
                                <Alert title="Some components cannot be checked">
                                    {count}
                                    " components of the last SBOM have no package URL, so OSV cannot match them. Check the generator's settings."
                                </Alert>
                            }
                        });
                    let count = page.findings.len();
                    let rows = finding_rows(page.findings.clone());
                    let table = if page.findings.is_empty() {
                        view! {
                            <Empty title="No finding matches">
                                "Nothing to show for these filters. A project is checked after each upload and every night."
                            </Empty>
                        }
                            .into_any()
                    } else {
                        view! {
                            <Table caption=format!("{count} findings, most severe first")>
                                <thead>
                                    <tr class=TABLE_HEAD_ROW>
                                        <th scope="col" class=TABLE_HEAD>"Severity"</th>
                                        <th scope="col" class=TABLE_HEAD>"Vulnerability"</th>
                                        <th scope="col" class=TABLE_HEAD>"Component"</th>
                                        <th scope="col" class=TABLE_HEAD>"Status"</th>
                                        <th scope="col" class=TABLE_HEAD>"Since"</th>
                                    </tr>
                                </thead>
                                <tbody>{rows}</tbody>
                            </Table>
                        }
                            .into_any()
                    };
                    let uploads = page
                        .uploads
                        .clone()
                        .into_iter()
                        .map(|upload| {
                            view! {
                                <li class="flex flex-wrap gap-x-2">
                                    <span class="font-medium">{format_time(upload.uploaded_at)}</span>
                                    <span class="text-muted-foreground">
                                        {upload.component_count} " components · CycloneDX "
                                        {upload.specification_version}
                                        {upload.source_commit.map(|commit| format!(" · commit {commit}"))}
                                        {upload.image_tag.map(|tag| format!(" · image {tag}"))}
                                    </span>
                                </li>
                            }
                        })
                        .collect_view();
                    let delete = organization.role.can_manage().then({
                        let organization_slug = organization_slug.clone();
                        let project_slug = project_slug.clone();
                        move || {
                            view! {
                                <Card class="border-destructive/40">
                                    <CardHeader>
                                        <CardTitle>"Delete this project"</CardTitle>
                                        <CardDescription>
                                            "Its components, upload history and findings are deleted. A later upload with an organization token creates it again."
                                        </CardDescription>
                                    </CardHeader>
                                    <CardContent>
                                        <form
                                            method="post"
                                            action={action::<DeleteProject>()}
                                            class="flex flex-wrap items-end gap-3"
                                        >
                                            <input type="hidden" name="organization" value=organization_slug />
                                            <input type="hidden" name="project" value=project_slug.clone() />
                                            <Field
                                                label=format!("Type {project_slug} to confirm")
                                                input_id="delete-project-confirmation"
                                            >
                                                <input
                                                    id="delete-project-confirmation"
                                                    name="confirmation"
                                                    class=INPUT
                                                    required
                                                    autocomplete="off"
                                                />
                                            </Field>
                                            <Button variant=ButtonVariant::Destructive>"Delete project"</Button>
                                        </form>
                                    </CardContent>
                                </Card>
                            }
                        }
                    });
                    view! {
                        <Title text=format!("{} · nanobom", page.name) />
                        <nav aria-label="Breadcrumb" class="text-muted-foreground text-sm">
                            <a class="hover:underline" href=format!("/organizations/{organization_slug}")>
                                {organization.name.clone()}
                            </a>
                            " / "
                            <span aria-current="page">{page.name.clone()}</span>
                        </nav>
                        <Heading title=page.name.clone() subtitle>
                            {check_now}
                        </Heading>
                        {without_purl}
                        <Filters page=page.clone() filter />
                        {table}
                        <Card>
                            <CardHeader>
                                <CardTitle>"Upload history"</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <ul class="grid gap-2 text-sm">{uploads}</ul>
                            </CardContent>
                        </Card>
                        {delete}
                    }
                }}
            />
        </Page>
    }
}

fn event_label(kind: &str) -> &'static str {
    match kind {
        "opened" => "Opened",
        "fixed" => "Fixed",
        "reopened" => "Reopened",
        "ignored" => "Ignored",
        "restored" => "Restored",
        "ignore_expired" => "Ignore expired",
        _ => "Changed",
    }
}

#[component]
fn Triage(page: FindingData) -> impl IntoView {
    let finding = page.finding.id.to_string();
    match page.finding.status {
        Status::Open => view! {
            <form method="post" action={action::<IgnoreFinding>()} class="grid gap-4">
                <input type="hidden" name="finding" value=finding />
                <Field
                    label="Reason"
                    input_id="ignore-reason"
                    hint="Why this finding does not apply or is accepted; kept in the history."
                >
                    <textarea id="ignore-reason" name="reason" class=TEXTAREA required></textarea>
                </Field>
                <Field
                    label="Ignore until (optional)"
                    input_id="ignore-expiry"
                    hint="The finding opens again after this date (UTC)."
                >
                    <input id="ignore-expiry" name="expires_on" type="date" class=format!("{INPUT} w-fit") />
                </Field>
                <div>
                    <Button variant=ButtonVariant::Secondary>"Ignore finding"</Button>
                </div>
            </form>
        }
        .into_any(),
        Status::Ignored => view! {
            <form method="post" action={action::<RestoreFinding>()}>
                <input type="hidden" name="finding" value=finding />
                <Button variant=ButtonVariant::Secondary>"Restore finding"</Button>
            </form>
        }
        .into_any(),
        Status::Fixed => view! {
            <p class="text-muted-foreground text-sm">"Fixed findings need no action."</p>
        }
        .into_any(),
    }
}

#[component]
pub fn FindingPage() -> impl IntoView {
    let params = use_params_map();
    let finding = move || {
        params
            .read()
            .get("finding")
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or_default()
    };
    let page = Resource::new(finding, load_finding);
    view! {
        <Page title="Finding">
            <Loaded
                resource=page
                render={|page: FindingData| {
                    let finding = page.finding.clone();
                    let triage = page.can_triage.then({
                        let page = page.clone();
                        move || {
                            view! {
                                <Card>
                                    <CardHeader>
                                        <CardTitle>"Triage"</CardTitle>
                                    </CardHeader>
                                    <CardContent>
                                        <Triage page />
                                    </CardContent>
                                </Card>
                            }
                        }
                    });
                    let cvss_version = page.cvss_version.clone().unwrap_or_default();
                    let cvss_score = finding.cvss_score;
                    let cvss = page.cvss_vector.clone().map(move |vector| {
                        view! {
                            <dt class="text-muted-foreground">"CVSS " {cvss_version}</dt>
                            <dd class="font-mono text-xs break-all">
                                {cvss_score.map(|score| format!("{score:.1} · "))} {vector}
                            </dd>
                        }
                    });
                    let ignored_by = page.ignored_by.clone();
                    let ignore_expires_at = finding.ignore_expires_at;
                    let ignored = finding.ignore_reason.clone().map(move |reason| {
                        view! {
                            <dt class="text-muted-foreground">"Ignored"</dt>
                            <dd>
                                {reason}
                                {ignored_by.map(|actor| format!(" (by {actor})"))}
                                {ignore_expires_at.map(|date| format!(" until {}", format_date(date)))}
                            </dd>
                        }
                    });
                    view! {
                        <Title text=format!("{} · nanobom", finding.vulnerability_id) />
                        <nav aria-label="Breadcrumb" class="text-muted-foreground text-sm">
                            <a class="hover:underline" href=format!("/organizations/{}", page.organization_slug)>
                                {page.organization_slug.clone()}
                            </a>
                            " / "
                            <a
                                class="hover:underline"
                                href=format!("/organizations/{}/projects/{}", page.organization_slug, page.project_slug)
                            >
                                {page.project_slug.clone()}
                            </a>
                            " / "
                            <span aria-current="page">{finding.vulnerability_id.clone()}</span>
                        </nav>
                        <Heading
                            title=finding.vulnerability_id.clone()
                            subtitle=finding.summary.clone().unwrap_or_default()
                        >
                            <SeverityBadge severity=finding.severity />
                            <StatusBadge status=finding.status />
                        </Heading>
                        <div class="grid gap-6 lg:grid-cols-[2fr_1fr]">
                            <div class="grid content-start gap-6">
                                <Card>
                                    <CardHeader>
                                        <CardTitle>"Details"</CardTitle>
                                        <CardDescription>
                                            {page.published.map(|date| format!("Published {} · ", format_date(date)))}
                                            "modified " {format_date(page.modified)}
                                        </CardDescription>
                                    </CardHeader>
                                    <CardContent>
                                        <p class="text-sm whitespace-pre-wrap break-words">
                                            {page.details.clone().unwrap_or_else(|| "No description.".to_owned())}
                                        </p>
                                    </CardContent>
                                </Card>
                                <Card>
                                    <CardHeader>
                                        <CardTitle>"History"</CardTitle>
                                    </CardHeader>
                                    <CardContent>
                                        <ol class="grid gap-2 text-sm">
                                            {page
                                                .events
                                                .clone()
                                                .into_iter()
                                                .map(|event| {
                                                    view! {
                                                        <li>
                                                            <span class="font-medium">{event_label(&event.kind)}</span>
                                                            <span class="text-muted-foreground">
                                                                " · " {format_time(event.created_at)}
                                                                {event.actor.clone().map(|actor| format!(" · by {actor}"))}
                                                            </span>
                                                            {event
                                                                .reason
                                                                .clone()
                                                                .map(|reason| view! { <p class="mt-1 whitespace-pre-wrap">{reason}</p> })}
                                                        </li>
                                                    }
                                                })
                                                .collect_view()}
                                        </ol>
                                    </CardContent>
                                </Card>
                                {triage}
                            </div>
                            <div class="grid content-start gap-6">
                                <Card>
                                    <CardHeader>
                                        <CardTitle>"Component"</CardTitle>
                                    </CardHeader>
                                    <CardContent>
                                        <dl class="grid gap-2 text-sm">
                                            <dt class="text-muted-foreground">"Package"</dt>
                                            <dd class="font-medium break-all">{finding.component_name.clone()}</dd>
                                            <dt class="text-muted-foreground">"Version"</dt>
                                            <dd>{finding.component_version.clone().unwrap_or_default()}</dd>
                                            <dt class="text-muted-foreground">"Fixed in"</dt>
                                            <dd>
                                                {if page.fixed_versions.is_empty() {
                                                    "No fixed version known".to_owned()
                                                } else {
                                                    page.fixed_versions.join(", ")
                                                }}
                                            </dd>
                                            <dt class="text-muted-foreground">"Package URL"</dt>
                                            <dd class="font-mono text-xs break-all">{finding.purl.clone()}</dd>
                                            {cvss}
                                            {ignored}
                                        </dl>
                                    </CardContent>
                                </Card>
                                <Card>
                                    <CardHeader>
                                        <CardTitle>"Aliases"</CardTitle>
                                    </CardHeader>
                                    <CardContent>
                                        <ul class="flex flex-wrap gap-2">
                                            {finding
                                                .aliases
                                                .clone()
                                                .into_iter()
                                                .map(|alias| view! { <li><Badge variant=BadgeVariant::Outline>{alias}</Badge></li> })
                                                .collect_view()}
                                            <li>
                                                <a
                                                    class="text-sm underline-offset-4 hover:underline"
                                                    href=format!("https://osv.dev/vulnerability/{}", finding.vulnerability_id)
                                                    rel="noreferrer"
                                                >
                                                    "View on OSV"
                                                </a>
                                            </li>
                                        </ul>
                                    </CardContent>
                                </Card>
                                <Card>
                                    <CardHeader>
                                        <CardTitle>"Also affected"</CardTitle>
                                        <CardDescription>"In the organizations you can see."</CardDescription>
                                    </CardHeader>
                                    <CardContent>
                                        {if page.affected_components.is_empty() {
                                            view! { <p class="text-muted-foreground text-sm">"No other component."</p> }.into_any()
                                        } else {
                                            view! {
                                                <ul class="grid gap-2 text-sm">
                                                    {page
                                                        .affected_components
                                                        .clone()
                                                        .into_iter()
                                                        .map(|component| {
                                                            view! {
                                                                <li>
                                                                    <a class="underline-offset-4 hover:underline" href=format!("/findings/{}", component.finding_id)>
                                                                        {component.organization_slug.clone()} "/" {component.project_slug.clone()}
                                                                    </a>
                                                                    <span class="text-muted-foreground block font-mono text-xs break-all">
                                                                        {component.purl.clone()}
                                                                    </span>
                                                                    <StatusBadge status=component.status />
                                                                </li>
                                                            }
                                                        })
                                                        .collect_view()}
                                                </ul>
                                            }
                                                .into_any()
                                        }}
                                    </CardContent>
                                </Card>
                                <Card>
                                    <CardHeader>
                                        <CardTitle>"References"</CardTitle>
                                    </CardHeader>
                                    <CardContent>
                                        <ul class="grid gap-1 text-sm">
                                            {page
                                                .references
                                                .clone()
                                                .into_iter()
                                                .map(|reference| {
                                                    view! {
                                                        <li class="break-all">
                                                            <a class="underline-offset-4 hover:underline" href=reference.url.clone() rel="noreferrer">
                                                                {reference.url.clone()}
                                                            </a>
                                                            <span class="text-muted-foreground text-xs">" " {reference.kind.to_lowercase()}</span>
                                                        </li>
                                                    }
                                                })
                                                .collect_view()}
                                        </ul>
                                    </CardContent>
                                </Card>
                            </div>
                        </div>
                    }
                }}
            />
        </Page>
    }
}

#[component]
pub fn SearchPage() -> impl IntoView {
    let query = use_query_map();
    let text = move || query.read().get("query").unwrap_or_default();
    let results = Resource::new(text, search_components);
    view! {
        <Page title="Search">
            <Heading
                title="Search components"
                subtitle="Find which projects use a package: a name, optionally followed by the start of a version (openssl 3.)."
            />
            <form method="get" role="search" class="flex flex-wrap gap-2">
                <label for="search-query" class="sr-only">"Component"</label>
                <input
                    id="search-query"
                    name="query"
                    type="search"
                    class=format!("{INPUT} max-w-md")
                    value=text
                    placeholder="openssl 3."
                />
                <Button>"Search"</Button>
            </form>
            <Loaded
                resource=results
                render={move |results: Vec<ComponentMatch>| {
                    if text().trim().is_empty() {
                        return ().into_any();
                    }
                    if results.is_empty() {
                        return view! { <Empty title="No component found">"Try a shorter name."</Empty> }.into_any();
                    }
                    let count = results.len();
                    view! {
                        <Table caption=format!("{count} components found")>
                            <thead>
                                <tr class=TABLE_HEAD_ROW>
                                    <th scope="col" class=TABLE_HEAD>"Component"</th>
                                    <th scope="col" class=TABLE_HEAD>"Version"</th>
                                    <th scope="col" class=TABLE_HEAD>"Project"</th>
                                </tr>
                            </thead>
                            <tbody>
                                {results
                                    .into_iter()
                                    .map(|component| {
                                        view! {
                                            <tr class=TABLE_ROW>
                                                <th scope="row" class=format!("{TABLE_CELL} text-left font-medium")>
                                                    {component.name}
                                                    <span class="text-muted-foreground block font-mono text-xs font-normal break-all">
                                                        {component.purl}
                                                    </span>
                                                </th>
                                                <td class=TABLE_CELL>{component.version.unwrap_or_default()}</td>
                                                <td class=TABLE_CELL>
                                                    <a
                                                        class="underline-offset-4 hover:underline"
                                                        href=format!(
                                                            "/organizations/{}/projects/{}",
                                                            component.organization_slug,
                                                            component.project_slug,
                                                        )
                                                    >
                                                        {component.organization_slug.clone()} "/" {component.project_slug.clone()}
                                                    </a>
                                                </td>
                                            </tr>
                                        }
                                    })
                                    .collect_view()}
                            </tbody>
                        </Table>
                    }
                        .into_any()
                }}
            />
        </Page>
    }
}
