//! A project's findings, a finding's details and the component search.

use std::collections::{HashMap, HashSet};

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
        ComponentMatch, DependencyComponent, DependencyPaths, FindingData, FindingFilter,
        FindingRow, ProjectData, Severity, Status,
    },
    t, tf, tp,
};

/// A fraction (0 to 1) as a whole percentage, in the request's language.
fn percent(fraction: f64) -> String {
    #[allow(clippy::cast_possible_truncation)]
    let value = (fraction * 100.0).round() as i64;
    tf!("finding.percent", value = value)
}

/// The direct dependencies that lead to a finding's component, for the project's table, by
/// name. A name appears once; its versions are added only when several versions of it lead to
/// the component, to tell them apart.
fn introduced_via_labels(via: &[DependencyComponent]) -> Vec<String> {
    let mut versions_of: HashMap<&str, HashSet<Option<&str>>> = HashMap::new();
    for component in via {
        versions_of
            .entry(component.name.as_str())
            .or_default()
            .insert(component.version.as_deref());
    }
    let mut labels: Vec<String> = Vec::new();
    for component in via {
        let label = match &component.version {
            Some(version) if versions_of[component.name.as_str()].len() > 1 => {
                format!("{} {version}", component.name)
            }
            _ => component.name.clone(),
        };
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    labels
}

/// The direct dependencies that lead to a finding's component, for the project's table: the
/// first two, then how many more; all of them in the tooltip.
fn introduced_via(finding: &FindingRow) -> impl IntoView + use<> {
    let via = &finding.introduced_via;
    if via.len() == 1 && via[0].purl == finding.purl {
        return view! { <span class="text-muted-foreground">{t!("project.direct")}</span> }
            .into_any();
    }
    let labels = introduced_via_labels(via);
    let mut shown = labels
        .iter()
        .take(2)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if labels.len() > 2 {
        shown = format!(
            "{shown} {}",
            tf!("project.via_more", count = labels.len() - 2)
        );
    }
    let title = (!labels.is_empty()).then(|| tf!("project.via_title", names = labels.join(", ")));
    view! { <span title=title>{shown}</span> }.into_any()
}

fn finding_rows(findings: Vec<FindingRow>) -> impl IntoView {
    findings
        .into_iter()
        .map(|finding| {
            let href = format!("/findings/{}", finding.id);
            let exploited = finding.exploitation.known_exploited.then(|| {
                let title = finding
                    .exploitation
                    .kev_due_date
                    .map(|date| tf!("project.known_exploited_due", date = date.to_string()));
                view! {
                    <span title=title class="mt-1 block">
                        <Badge variant=BadgeVariant::Destructive>{t!("project.known_exploited")}</Badge>
                    </span>
                }
            });
            let epss = finding
                .exploitation
                .epss_percentile
                .map(percent)
                .unwrap_or_default();
            let via = introduced_via(&finding);
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
                        {exploited}
                    </th>
                    <td class=TABLE_CELL>
                        <span class="font-medium">{finding.component_name.clone()}</span>
                        <span class="text-muted-foreground block text-xs">
                            {finding.component_version.clone().unwrap_or_default()} " · "
                            {finding.ecosystem.clone()}
                        </span>
                    </td>
                    <td class=format!("{TABLE_CELL} text-sm")>{via}</td>
                    <td class=format!("{TABLE_CELL} text-right tabular-nums")>{epss}</td>
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
        <form method="get" class="flex flex-wrap items-end gap-3" aria-label=t!("project.filter_label")>
            <div class="grid gap-2">
                <label class=LABEL for="filter-severity">{t!("project.severity")}</label>
                <select id="filter-severity" name="severity" class=SELECT>
                    <option value="">{t!("project.filter_any_severity")}</option>
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
                <label class=LABEL for="filter-status">{t!("project.status")}</label>
                <select id="filter-status" name="status" class=SELECT>
                    <option value="">{t!("project.filter_open_and_ignored")}</option>
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
                    <option value="all" selected=selected(&filter.status, "all")>{t!("project.filter_all")}</option>
                </select>
            </div>
            <div class="grid gap-2">
                <label class=LABEL for="filter-ecosystem">{t!("project.filter_ecosystem")}</label>
                <select id="filter-ecosystem" name="ecosystem" class=SELECT>
                    <option value="">{t!("project.filter_any_ecosystem")}</option>
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
            <label class=format!("{LABEL} h-9")>
                <input type="checkbox" name="exploited" value="1" class=CHECKBOX checked=filter.exploited />
                {t!("project.filter_exploited")}
            </label>
            <Button variant=ButtonVariant::Secondary>{t!("project.filter")}</Button>
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
                exploited: nonempty("exploited").is_some_and(|value| value == "1"),
            },
        )
    };
    let page = Resource::new(key, |(organization, project, filter)| {
        load_project(organization, project, filter)
    });
    view! {
        <Page title=t!("project.title")>
            <Loaded
                resource=page
                render={move |page: ProjectData| {
                    let (_, _, filter) = key();
                    let organization = page.organization.clone();
                    let organization_slug = organization.slug.clone();
                    let project_slug = page.slug.clone();
                    let latest = page.uploads.first().cloned();
                    let subtitle = format!(
                        "{}{}",
                        tp!("project.components", page.component_count),
                        latest
                            .as_ref()
                            .map(|upload| {
                                format!(
                                    " · {}",
                                    tf!("project.last_upload", time = format_time(upload.uploaded_at)),
                                )
                            })
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
                                    <Button variant=ButtonVariant::Outline>{t!("organization.check_now")}</Button>
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
                                <Alert title=t!("project.without_purl_title")>
                                    {tp!("project.without_purl_text", count)}
                                </Alert>
                            }
                        });
                    let stale = page.stale.then(|| {
                        let message = match page.last_upload_at {
                            Some(time) => tf!("project.stale_alert", date = format_time(time)),
                            None => {
                                tf!("project.stale_never_alert", date = format_date(page.created_at))
                            }
                        };
                        view! { <Alert variant=AlertVariant::Warning>{message}</Alert> }
                    });
                    let count = page.findings.len();
                    let rows = finding_rows(page.findings.clone());
                    let table = if page.findings.is_empty() {
                        view! {
                            <Empty title=t!("project.no_match_title")>
                                {t!("project.no_match_text")}
                            </Empty>
                        }
                            .into_any()
                    } else {
                        view! {
                            <Table caption=tp!("project.findings_caption", count)>
                                <thead>
                                    <tr class=TABLE_HEAD_ROW>
                                        <th scope="col" class=TABLE_HEAD>{t!("project.severity")}</th>
                                        <th scope="col" class=TABLE_HEAD>{t!("project.vulnerability")}</th>
                                        <th scope="col" class=TABLE_HEAD>{t!("project.component")}</th>
                                        <th scope="col" class=TABLE_HEAD>{t!("project.via")}</th>
                                        <th scope="col" class=format!("{TABLE_HEAD} text-right")>{t!("project.epss")}</th>
                                        <th scope="col" class=TABLE_HEAD>{t!("project.status")}</th>
                                        <th scope="col" class=TABLE_HEAD>{t!("project.since")}</th>
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
                                        {tp!("project.components", upload.component_count)} " · "
                                        {sbom_format(&upload.specification_version)}
                                        {upload.source_commit.map(|commit| format!(" · {}", tf!("project.commit", commit = commit)))}
                                        {upload.image_tag.map(|tag| format!(" · {}", tf!("project.image", tag = tag)))}
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
                                        <CardTitle>{t!("project.delete_title")}</CardTitle>
                                        <CardDescription>{t!("project.delete_description")}</CardDescription>
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
                                                label=tf!("common.type_to_confirm", slug = project_slug.clone())
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
                                            <Button variant=ButtonVariant::Destructive>{t!("project.delete")}</Button>
                                        </form>
                                    </CardContent>
                                </Card>
                            }
                        }
                    });
                    view! {
                        <Title text=format!("{} · nanobom", page.name) />
                        <nav aria-label=t!("common.breadcrumb") class="text-muted-foreground text-sm">
                            <a class="hover:underline" href=format!("/organizations/{organization_slug}")>
                                {organization.name.clone()}
                            </a>
                            " / "
                            <span aria-current="page">{page.name.clone()}</span>
                        </nav>
                        <Heading title=page.name.clone() subtitle>
                            <LinkButton
                                href=format!("/api/organizations/{organization_slug}/projects/{project_slug}/vex")
                                variant=ButtonVariant::Outline
                            >
                                {t!("project.export_vex")}
                            </LinkButton>
                            {check_now}
                        </Heading>
                        {stale}
                        {without_purl}
                        <Filters page=page.clone() filter />
                        {table}
                        <Card>
                            <CardHeader>
                                <CardTitle>{t!("project.uploads_title")}</CardTitle>
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

/// The justifications offered when ignoring a finding: the CycloneDX impact analysis
/// justifications, then the false positive state (see `nanobom_domain::findings::Justification`).
const JUSTIFICATIONS: [&str; 10] = [
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
    "false_positive",
];

fn justification_label(value: &str) -> &'static str {
    match value {
        "code_not_present" => t!("finding.justification_code_not_present"),
        "code_not_reachable" => t!("finding.justification_code_not_reachable"),
        "requires_configuration" => t!("finding.justification_requires_configuration"),
        "requires_dependency" => t!("finding.justification_requires_dependency"),
        "requires_environment" => t!("finding.justification_requires_environment"),
        "protected_by_compiler" => t!("finding.justification_protected_by_compiler"),
        "protected_at_runtime" => t!("finding.justification_protected_at_runtime"),
        "protected_at_perimeter" => t!("finding.justification_protected_at_perimeter"),
        "protected_by_mitigating_control" => {
            t!("finding.justification_protected_by_mitigating_control")
        }
        "false_positive" => t!("finding.justification_false_positive"),
        _ => t!("finding.justification_none"),
    }
}

/// Who made a change: a member, or an upload token importing a VEX document.
fn changed_by(actor: Option<String>, token: Option<String>) -> Option<String> {
    match (actor, token) {
        (Some(actor), _) => Some(tf!("finding.by", actor = actor)),
        (None, Some(token)) => Some(tf!("finding.by_token", token = token)),
        (None, None) => None,
    }
}

fn event_label(kind: &str) -> &'static str {
    match kind {
        "opened" => t!("finding.event_opened"),
        "fixed" => t!("finding.event_fixed"),
        "reopened" => t!("finding.event_reopened"),
        "ignored" => t!("finding.event_ignored"),
        "restored" => t!("finding.event_restored"),
        "ignore_expired" => t!("finding.event_ignore_expired"),
        _ => t!("finding.event_changed"),
    }
}

/// A component of a dependency path, with its version.
fn path_component(component: &DependencyComponent) -> String {
    match &component.version {
        Some(version) => format!("{} {version}", component.name),
        None => component.name.clone(),
    }
}

/// The paths from the project's direct dependencies to a finding's component, or why there is
/// none.
fn dependency_paths(paths: Option<DependencyPaths>) -> impl IntoView {
    let Some(paths) = paths else {
        return view! { <p class="text-muted-foreground text-sm">{t!("finding.no_dependency_graph")}</p> }
            .into_any();
    };
    let partial = paths.partial.then(|| {
        view! { <p class="text-muted-foreground mt-2 text-sm">{t!("finding.partial_graph")}</p> }
    });
    if paths.paths.is_empty() {
        return view! {
            <p class="text-muted-foreground text-sm">{t!("finding.not_linked")}</p>
            {partial}
        }
        .into_any();
    }
    let more = (paths.more > 0).then(|| {
        view! { <p class="text-muted-foreground mt-2 text-sm">{tp!("finding.more_paths", paths.more)}</p> }
    });
    let items = paths
        .paths
        .into_iter()
        .map(|path| {
            let direct = (path.len() == 1).then(|| {
                view! {
                    <span class="text-muted-foreground">" (" {t!("finding.direct_dependency")} ")"</span>
                }
            });
            let text = path.iter().map(path_component).collect::<Vec<_>>().join(" → ");
            view! {
                <li class="break-words">
                    {text}
                    {direct}
                </li>
            }
        })
        .collect_view();
    view! {
        <ul class="grid gap-2 text-sm">{items}</ul>
        {more}
        {partial}
    }
    .into_any()
}

#[component]
fn Triage(page: FindingData) -> impl IntoView {
    let finding = page.finding.id.to_string();
    match page.finding.status {
        Status::Open => view! {
            <form method="post" action={action::<IgnoreFinding>()} class="grid gap-4">
                <input type="hidden" name="finding" value=finding />
                <Field
                    label=t!("finding.reason")
                    input_id="ignore-reason"
                    hint=t!("finding.reason_hint")
                >
                    <textarea id="ignore-reason" name="reason" class=TEXTAREA required></textarea>
                </Field>
                <Field
                    label=t!("finding.justification")
                    input_id="ignore-justification"
                    hint=t!("finding.justification_hint")
                >
                    <select id="ignore-justification" name="justification" class=format!("{SELECT} w-fit")>
                        <option value="">{t!("finding.justification_none")}</option>
                        {JUSTIFICATIONS
                            .iter()
                            .map(|value| view! { <option value=*value>{justification_label(value)}</option> })
                            .collect_view()}
                    </select>
                </Field>
                <Field
                    label=t!("finding.ignore_until")
                    input_id="ignore-expiry"
                    hint=t!("finding.ignore_until_hint")
                >
                    <input id="ignore-expiry" name="expires_on" type="date" class=format!("{INPUT} w-fit") />
                </Field>
                <div>
                    <Button variant=ButtonVariant::Secondary>{t!("finding.ignore")}</Button>
                </div>
            </form>
        }
        .into_any(),
        Status::Ignored => view! {
            <form method="post" action={action::<RestoreFinding>()}>
                <input type="hidden" name="finding" value=finding />
                <Button variant=ButtonVariant::Secondary>{t!("finding.restore")}</Button>
            </form>
        }
        .into_any(),
        Status::Fixed => view! {
            <p class="text-muted-foreground text-sm">{t!("finding.fixed_no_action")}</p>
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
        <Page title=t!("finding.title")>
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
                                        <CardTitle>{t!("finding.triage")}</CardTitle>
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
                    let ignored_by = changed_by(page.ignored_by.clone(), page.ignored_by_token.clone());
                    let ignore_expires_at = finding.ignore_expires_at;
                    let ignore_justification = finding.ignore_justification.clone();
                    // The reason outlives the ignore (see `FindingRow`): shown while ignored only.
                    let ignored = finding
                        .ignore_reason
                        .clone()
                        .filter(|_| finding.status == Status::Ignored)
                        .map(move |reason| {
                        view! {
                            <dt class="text-muted-foreground">{t!("finding.ignored")}</dt>
                            <dd>
                                {reason}
                                {ignored_by.map(|by| format!(" ({by})"))}
                                {ignore_expires_at
                                    .map(|date| format!(" {}", tf!("finding.until", date = format_date(date))))}
                            </dd>
                            {ignore_justification.map(|value| view! {
                                <dt class="text-muted-foreground">{t!("finding.justification")}</dt>
                                <dd>{justification_label(&value)}</dd>
                            })}
                        }
                    });
                    let exploitation = finding.exploitation.clone();
                    let known_exploited = exploitation.known_exploited;
                    let exploitation_body = if known_exploited || exploitation.epss_score.is_some() {
                        let yes_no = |value: bool| if value { t!("finding.yes") } else { t!("finding.no") };
                        let kev = known_exploited.then(|| {
                            view! {
                                <dt class="text-muted-foreground">{t!("finding.kev_added")}</dt>
                                <dd>{exploitation.kev_date_added.map(|date| date.to_string())}</dd>
                                <dt class="text-muted-foreground">{t!("finding.kev_due")}</dt>
                                <dd>{exploitation.kev_due_date.map(|date| date.to_string())}</dd>
                                <dt class="text-muted-foreground">{t!("finding.ransomware")}</dt>
                                <dd>{yes_no(exploitation.kev_ransomware)}</dd>
                            }
                        });
                        let epss = exploitation.epss_score.map(|score| {
                            let percentile = exploitation.epss_percentile.map(percent).unwrap_or_default();
                            let date = exploitation.epss_date.map(|date| date.to_string()).unwrap_or_default();
                            view! {
                                <dt class="text-muted-foreground">{t!("finding.epss_score")}</dt>
                                <dd>
                                    {tf!(
                                        "finding.epss_value", score = format!("{score:.3}"), percentile = percentile, date = date
                                    )}
                                </dd>
                            }
                        });
                        view! { <dl class="grid gap-2 text-sm">{kev}{epss}</dl> }.into_any()
                    } else {
                        view! { <p class="text-muted-foreground text-sm">{t!("finding.exploitation_none")}</p> }
                            .into_any()
                    };
                    let known_exploited_badge = known_exploited
                        .then(|| view! { <Badge variant=BadgeVariant::Destructive>{t!("project.known_exploited")}</Badge> });
                    view! {
                        <Title text=format!("{} · nanobom", finding.vulnerability_id) />
                        <nav aria-label=t!("common.breadcrumb") class="text-muted-foreground text-sm">
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
                            {known_exploited_badge}
                            <StatusBadge status=finding.status />
                        </Heading>
                        <div class="grid gap-6 lg:grid-cols-[2fr_1fr]">
                            <div class="grid content-start gap-6">
                                <Card>
                                    <CardHeader>
                                        <CardTitle>{t!("finding.details")}</CardTitle>
                                        <CardDescription>
                                            {page
                                                .published
                                                .map(|date| format!("{} · ", tf!("finding.published", date = format_date(date))))}
                                            {tf!("finding.modified", date = format_date(page.modified))}
                                        </CardDescription>
                                    </CardHeader>
                                    <CardContent>
                                        <p class="text-sm whitespace-pre-wrap break-words">
                                            {page.details.clone().unwrap_or_else(|| t!("finding.no_description").to_owned())}
                                        </p>
                                    </CardContent>
                                </Card>
                                <Card>
                                    <CardHeader>
                                        <CardTitle>{t!("finding.exploitation")}</CardTitle>
                                    </CardHeader>
                                    <CardContent>
                                        <div class="grid gap-3">
                                        {exploitation_body}
                                        <p class="flex flex-wrap gap-x-4 text-sm">
                                            <a
                                                class="underline-offset-4 hover:underline"
                                                href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                                                rel="noreferrer"
                                            >
                                                {t!("finding.kev_link")}
                                            </a>
                                            <a
                                                class="underline-offset-4 hover:underline"
                                                href="https://www.first.org/epss/"
                                                rel="noreferrer"
                                            >
                                                {t!("finding.epss_link")}
                                            </a>
                                        </p>
                                        </div>
                                    </CardContent>
                                </Card>
                                <Card>
                                    <CardHeader>
                                        <CardTitle>{t!("finding.history")}</CardTitle>
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
                                                                {changed_by(event.actor.clone(), event.token.clone()).map(|by| format!(" · {by}"))}
                                                                {event
                                                                    .justification
                                                                    .as_deref()
                                                                    .map(|value| format!(" · {}", justification_label(value)))}
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
                                        <CardTitle>{t!("finding.component")}</CardTitle>
                                    </CardHeader>
                                    <CardContent>
                                        <dl class="grid gap-2 text-sm">
                                            <dt class="text-muted-foreground">{t!("finding.package")}</dt>
                                            <dd class="font-medium break-all">{finding.component_name.clone()}</dd>
                                            <dt class="text-muted-foreground">{t!("finding.version")}</dt>
                                            <dd>{finding.component_version.clone().unwrap_or_default()}</dd>
                                            <dt class="text-muted-foreground">{t!("finding.fixed_in")}</dt>
                                            <dd>
                                                {if page.fixed_versions.is_empty() {
                                                    t!("finding.no_fixed_version").to_owned()
                                                } else {
                                                    page.fixed_versions.join(", ")
                                                }}
                                            </dd>
                                            <dt class="text-muted-foreground">{t!("finding.package_url")}</dt>
                                            <dd class="font-mono text-xs break-all">{finding.purl.clone()}</dd>
                                            {cvss}
                                            {ignored}
                                        </dl>
                                    </CardContent>
                                </Card>
                                {(finding.status != Status::Fixed).then(|| view! {
                                    <Card>
                                        <CardHeader>
                                            <CardTitle>{t!("finding.introduced_via")}</CardTitle>
                                            <CardDescription>{t!("finding.introduced_via_description")}</CardDescription>
                                        </CardHeader>
                                        <CardContent>{dependency_paths(page.dependency_paths.clone())}</CardContent>
                                    </Card>
                                })}
                                <Card>
                                    <CardHeader>
                                        <CardTitle>{t!("finding.aliases")}</CardTitle>
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
                                                    {t!("finding.view_on_osv")}
                                                </a>
                                            </li>
                                        </ul>
                                    </CardContent>
                                </Card>
                                <Card>
                                    <CardHeader>
                                        <CardTitle>{t!("finding.also_affected")}</CardTitle>
                                        <CardDescription>{t!("finding.also_affected_description")}</CardDescription>
                                    </CardHeader>
                                    <CardContent>
                                        {if page.affected_components.is_empty() {
                                            view! { <p class="text-muted-foreground text-sm">{t!("finding.no_other_component")}</p> }.into_any()
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
                                        <CardTitle>{t!("finding.references")}</CardTitle>
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
        <Page title=t!("search.title")>
            <Heading title=t!("search.heading") subtitle=t!("search.subtitle") />
            <form method="get" role="search" class="flex flex-wrap gap-2">
                <label for="search-query" class="sr-only">{t!("search.label")}</label>
                <input
                    id="search-query"
                    name="query"
                    type="search"
                    class=format!("{INPUT} max-w-md")
                    value=text
                    placeholder="openssl 3."
                />
                <Button>{t!("search.submit")}</Button>
            </form>
            <Loaded
                resource=results
                render={move |results: Vec<ComponentMatch>| {
                    if text().trim().is_empty() {
                        return ().into_any();
                    }
                    if results.is_empty() {
                        return view! { <Empty title=t!("search.empty_title")>{t!("search.empty_text")}</Empty> }.into_any();
                    }
                    let count = results.len();
                    view! {
                        <Table caption=tp!("search.caption", count)>
                            <thead>
                                <tr class=TABLE_HEAD_ROW>
                                    <th scope="col" class=TABLE_HEAD>{t!("search.component")}</th>
                                    <th scope="col" class=TABLE_HEAD>{t!("search.version")}</th>
                                    <th scope="col" class=TABLE_HEAD>{t!("search.project")}</th>
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

/// An upload's format and version: SPDX versions are stored as SPDX documents spell them
/// (`SPDX-2.3`), CycloneDX versions bare (`1.6`).
fn sbom_format(specification_version: &str) -> String {
    match specification_version.strip_prefix("SPDX-") {
        Some(version) => format!("SPDX {version}"),
        None => format!("CycloneDX {specification_version}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component(name: &str, version: &str) -> DependencyComponent {
        DependencyComponent {
            purl: format!("pkg:npm/{name}@{version}"),
            name: name.to_owned(),
            version: Some(version.to_owned()),
        }
    }

    #[test]
    fn labels_are_names_unless_versions_tell_them_apart() {
        assert_eq!(
            introduced_via_labels(&[component("bar", "1.0.0"), component("foo", "2.0.0")]),
            ["bar", "foo"]
        );
        assert_eq!(
            introduced_via_labels(&[
                component("bar", "1.0.0"),
                component("foo", "1.0.0"),
                component("foo", "2.0.0"),
            ]),
            ["bar", "foo 1.0.0", "foo 2.0.0"]
        );
    }

    #[test]
    fn a_name_is_listed_once() {
        // The same package with different qualifiers has the same name and version.
        let mut qualified = component("foo", "1.0.0");
        qualified.purl.push_str("?arch=x86_64");
        assert_eq!(
            introduced_via_labels(&[component("foo", "1.0.0"), qualified]),
            ["foo"]
        );
    }
}
