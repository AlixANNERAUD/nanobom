//! The vulnerability report of a project version, for customers, auditors and regulators: a
//! page made to be printed or saved as PDF, and the same content as a standalone document for
//! tokens ([`document`]).
//!
//! [`ReportBody`] renders both, so they cannot drift apart. It uses only plain components (no
//! resource, no island): the server renders it outside the router for the document. Names and
//! advisory texts are rendered as text, which Leptos escapes; the document's title goes through
//! the same escaping as page titles.

use leptos::prelude::*;
use leptos_router::hooks::{use_params_map, use_query_map};

use crate::{
    components::{Loaded, Page, PageTitle, SeverityBadge, format_date, format_time, ui::*},
    functions::load_report,
    model::{AssessedFinding, LicenseAction, ReportData, ReportFinding, ReportLicenses},
    pages::findings::{
        changed_by, introduced_via_labels, justification_label, percent, sbom_format,
        version_label, version_query,
    },
    t, tf, tp,
};

/// A cell of the report's tables: long identifiers break anywhere rather than widen the table
/// past the page, on screen and on paper.
const CELL: &str = "px-3 py-2 align-top wrap-anywhere";

/// `?version=…` for a link to the report's version, empty for the latest one.
fn version_suffix(report: &ReportData) -> String {
    if report.latest {
        String::new()
    } else {
        format!("?{}", version_query(&report.version))
    }
}

/// The report page of the interface: the report, with a way back to the project and a hint on
/// how to print it, both left out of the printout.
#[component]
pub fn ReportPage() -> impl IntoView {
    let params = use_params_map();
    let query = use_query_map();
    let key = move || {
        let params = params.read();
        (
            params.get("organization").unwrap_or_default(),
            params.get("project").unwrap_or_default(),
            // Empty names the unnamed version.
            query.read().get("version"),
        )
    };
    let report = Resource::new(key, |(organization, project, version)| {
        load_report(organization, project, version)
    });
    view! {
        <Page title=t!("report.title")>
            <Loaded
                resource=report
                render=move |report: ReportData| {
                    let organization_href = format!("/organizations/{}", report.organization_slug);
                    let project_href = format!(
                        "/organizations/{}/projects/{}{}",
                        report.organization_slug,
                        report.project_slug,
                        version_suffix(&report),
                    );
                    view! {
                        <PageTitle text=format!("{} · {}", t!("report.title"), report.project_name) />
                        <nav
                            aria-label=t!("common.breadcrumb")
                            class="text-muted-foreground text-sm wrap-anywhere print:hidden"
                        >
                            <a class="hover:underline" href=organization_href>
                                {report.organization_name.clone()}
                            </a>
                            " / "
                            <a class="hover:underline" href=project_href>
                                {report.project_name.clone()}
                            </a>
                            " / "
                            <span aria-current="page">{t!("report.title")}</span>
                        </nav>
                        <p class="text-muted-foreground text-sm print:hidden">{t!("report.print_hint")}</p>
                        <ReportBody report />
                    }
                }
            />
        </Page>
    }
}

/// The report itself, in the request's language.
#[component]
pub fn ReportBody(report: ReportData) -> impl IntoView {
    // The unnamed version's label already says "version".
    let version = if report.version.is_empty() {
        version_label(&report.version)
    } else {
        tf!("report.version", version = report.version.clone()).to_string()
    };
    let subtitle = format!(
        "{} / {} · {}",
        report.organization_name, report.project_name, version,
    );
    let generated = format!(
        "{} {}",
        tf!("report.generated", time = format_time(report.generated_at)),
        tf!(
            "report.generated_by",
            version = report.nanobom_version.clone(),
            host = report.host.clone()
        ),
    );
    let stale = report.stale.then(|| {
        let message = match report.project_last_upload_at {
            Some(time) => tf!("report.stale", date = format_time(time)),
            None => tf!("report.stale_never", date = format_date(report.project_created_at)),
        };
        view! { <Alert variant=AlertVariant::Warning title=t!("report.stale_title")>{message}</Alert> }
    });
    let inactive = (!report.active).then(|| {
        view! {
            <Alert variant=AlertVariant::Warning title=t!("project.inactive_title")>
                {t!("report.inactive")}
            </Alert>
        }
    });
    view! {
        <article class="grid gap-6">
            <header class="grid gap-1">
                <h1 class="text-2xl font-semibold tracking-tight wrap-anywhere">{t!("report.title")}</h1>
                <p class="text-lg wrap-anywhere">{subtitle}</p>
                <p class="text-muted-foreground text-sm wrap-anywhere">{generated}</p>
            </header>
            {stale}
            {inactive}
            {provenance(report.clone())}
            {summary(report.clone())}
            {open_findings(report.clone())}
            {assessed_findings(report.clone())}
            {licenses(report.licenses.clone())}
            <Card>
                <CardHeader>
                    <CardTitle>{t!("report.method_title")}</CardTitle>
                </CardHeader>
                <CardContent>
                    <div class="grid gap-2 text-sm">
                        <p>{t!("report.method_checks")}</p>
                        <p>{t!("report.method_limits")}</p>
                        <p>{t!("report.method_time")}</p>
                    </div>
                </CardContent>
            </Card>
        </article>
    }
}

/// A term and its description in a list of facts.
fn fact(term: String, description: String) -> impl IntoView {
    view! {
        <div class="grid gap-x-4 sm:grid-cols-[16rem_minmax(0,1fr)]">
            <dt class="text-muted-foreground">{term}</dt>
            <dd class="wrap-anywhere">{description}</dd>
        </div>
    }
}

fn time_or_never(time: Option<chrono::DateTime<chrono::FixedOffset>>) -> String {
    time.map(format_time)
        .unwrap_or_else(|| t!("common.never").to_owned())
}

/// Where the report's data comes from and how fresh it is.
fn provenance(report: ReportData) -> impl IntoView + use<> {
    let upload = match &report.upload {
        Some(upload) => {
            let mut text = format!(
                "{} · {}",
                tf!("report.uploaded", time = format_time(upload.uploaded_at)),
                sbom_format(&upload.specification_version),
            );
            if let Some(commit) = &upload.source_commit {
                text = format!(
                    "{text} · {}",
                    tf!("project.commit", commit = commit.clone())
                );
            }
            if let Some(tag) = &upload.image_tag {
                text = format!("{text} · {}", tf!("project.image", tag = tag.clone()));
            }
            text
        }
        None => t!("report.no_upload").to_owned(),
    };
    let without_purl = report
        .upload
        .as_ref()
        .map_or(0, |upload| upload.components_without_purl);
    view! {
        <Card>
            <CardHeader>
                <CardTitle>{t!("report.scope_title")}</CardTitle>
            </CardHeader>
            <CardContent>
                <dl class="grid gap-2 text-sm">
                    {fact(t!("report.sbom").to_owned(), upload)}
                    {fact(t!("report.components_checked").to_owned(), report.component_count.to_string())}
                    {fact(
                        t!("report.components_not_checked").to_owned(),
                        tp!("report.without_purl", without_purl),
                    )}
                    {fact(
                        t!("report.last_evaluation").to_owned(),
                        // Runs skip inactive versions: the last run's date would overstate them.
                        if report.active {
                            time_or_never(report.last_evaluation)
                        } else {
                            t!("report.not_checked_while_inactive").to_owned()
                        },
                    )}
                    {fact(t!("report.kev_checked").to_owned(), time_or_never(report.kev_checked_at))}
                    {fact(t!("report.epss_checked").to_owned(), time_or_never(report.epss_checked_at))}
                </dl>
            </CardContent>
        </Card>
    }
}

/// The summary sentence: whether anything of high or critical severity is open.
fn summary_sentence(report: &ReportData) -> String {
    let severe = report.counts.critical + report.counts.high;
    let total = report.counts.total();
    if total == 0 {
        t!("report.sentence_none").to_owned()
    } else if severe == 0 {
        tp!("report.sentence_lower", total)
    } else {
        tp!("report.sentence_severe", severe)
    }
}

fn summary(report: ReportData) -> impl IntoView + use<> {
    let known_exploited = i64::try_from(report.known_exploited).unwrap_or(i64::MAX);
    view! {
        <Card>
            <CardHeader>
                <CardTitle>{t!("report.summary_title")}</CardTitle>
            </CardHeader>
            <CardContent>
                <div class="grid gap-3">
                    <p class="font-medium">{summary_sentence(&report)}</p>
                    <SeverityBar counts=report.counts />
                    <div class="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
                        <p class="font-medium">{tp!("project.open_findings", report.counts.total())}</p>
                        <SeverityLegend counts=report.counts known_exploited=known_exploited />
                    </div>
                    <dl class="grid gap-2 text-sm">
                        {fact(t!("report.ignored").to_owned(), report.ignored.to_string())}
                        {fact(t!("report.fixed_recently").to_owned(), report.fixed_recently.to_string())}
                    </dl>
                </div>
            </CardContent>
        </Card>
    }
}

/// The identifier of a finding's vulnerability and its other names.
fn identifiers(finding: &crate::model::FindingRow) -> impl IntoView + use<> {
    let aliases = (!finding.aliases.is_empty()).then(|| {
        view! {
            <span class="text-muted-foreground block font-mono text-xs">
                {finding.aliases.join(", ")}
            </span>
        }
    });
    view! {
        <span class=format!("{MONO} block font-medium")>{finding.vulnerability_id.clone()}</span>
        {aliases}
    }
}

fn component(finding: &crate::model::FindingRow) -> impl IntoView + use<> {
    view! {
        <span class="block font-medium">{finding.component_name.clone()}</span>
        <span class="text-muted-foreground block font-mono text-xs">
            {finding.component_version.clone().unwrap_or_default()} " · " {finding.ecosystem.clone()}
        </span>
    }
}

/// How the project depends on a finding's component.
fn dependency(finding: &crate::model::FindingRow) -> String {
    let via = &finding.introduced_via;
    if via.len() == 1 && via[0].purl == finding.purl {
        t!("report.direct").to_owned()
    } else if via.is_empty() {
        t!("report.unknown").to_owned()
    } else {
        tf!(
            "report.transitive",
            names = introduced_via_labels(via).join(", ")
        )
    }
}

fn open_row(row: ReportFinding) -> impl IntoView {
    let finding = row.finding;
    let exploited = if finding.exploitation.known_exploited {
        view! { <Badge variant=BadgeVariant::Destructive>{t!("report.yes")}</Badge> }.into_any()
    } else {
        view! { <span class="text-muted-foreground">{t!("report.no")}</span> }.into_any()
    };
    let fixed = if row.fixed_versions.is_empty() {
        view! { <span class="text-muted-foreground">{t!("report.unknown")}</span> }.into_any()
    } else {
        view! { <span class=MONO>{row.fixed_versions.join(", ")}</span> }.into_any()
    };
    view! {
        <tr class="border-b last:border-0">
            <th scope="row" class=format!("{CELL} text-left font-normal")>{identifiers(&finding)}</th>
            <td class=CELL>{component(&finding)}</td>
            <td class=CELL>
                <SeverityBadge severity=finding.severity />
                {finding
                    .cvss_score
                    .map(|score| {
                        view! {
                            <span class=format!("{MONO} text-muted-foreground block tabular-nums")>
                                {format!("CVSS {score:.1}")}
                            </span>
                        }
                    })}
            </td>
            <td class=CELL>{exploited}</td>
            <td class=format!("{CELL} tabular-nums")>
                {finding.exploitation.epss_percentile.map(percent).unwrap_or_default()}
            </td>
            <td class=CELL>{dependency(&finding)}</td>
            <td class=CELL>{fixed}</td>
            <td class=format!("{CELL} whitespace-nowrap")>{format_date(finding.first_seen_at)}</td>
        </tr>
    }
}

/// How many items of a list cut at its bound are not shown.
fn hidden(total: u64, listed: usize) -> Option<u64> {
    let hidden = total.saturating_sub(u64::try_from(listed).unwrap_or(u64::MAX));
    (hidden > 0).then_some(hidden)
}

fn note(text: Option<String>) -> Option<impl IntoView + use<>> {
    text.map(|text| view! { <p class="text-muted-foreground text-sm">{text}</p> })
}

fn open_findings(report: ReportData) -> impl IntoView + use<> {
    let content = if report.open.is_empty() {
        view! { <p class="text-muted-foreground text-sm">{t!("report.open_none")}</p> }.into_any()
    } else {
        let rows = report.open.clone().into_iter().map(open_row).collect_view();
        view! {
            <Table caption=t!("report.open_caption")>
                <thead>
                    <tr class=TABLE_HEAD_ROW>
                        <th scope="col" class=TABLE_HEAD>{t!("project.vulnerability")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("project.component")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("project.severity")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("project.known_exploited")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("project.epss")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("report.dependency")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("finding.fixed_in")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("report.first_seen")}</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </Table>
        }
        .into_any()
    };
    view! {
        <Card>
            <CardHeader>
                <CardTitle>{t!("report.open_title")}</CardTitle>
                <CardDescription>{t!("report.open_description")}</CardDescription>
            </CardHeader>
            <CardContent>
                <div class="grid gap-2">
                    {content}
                    {note(hidden(report.counts.total(), report.open.len()).map(|count| tp!("report.open_more", count)))}
                </div>
            </CardContent>
        </Card>
    }
}

fn assessed_row(row: AssessedFinding) -> impl IntoView {
    let finding = row.finding;
    let justification = finding
        .ignore_justification
        .as_deref()
        .map_or_else(|| t!("report.accepted_risk"), justification_label);
    let decided = [
        row.ignored_at.map(format_date),
        changed_by(row.ignored_by, row.ignored_by_token),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ");
    let until = finding.ignore_expires_at.map(|date| {
        view! {
            <span class="text-muted-foreground block">
                {tf!("finding.until", date = format_date(date))}
            </span>
        }
    });
    view! {
        <tr class="border-b last:border-0">
            <th scope="row" class=format!("{CELL} text-left font-normal")>{identifiers(&finding)}</th>
            <td class=CELL>{component(&finding)}</td>
            <td class=CELL>{justification}</td>
            <td class=format!("{CELL} whitespace-pre-line")>{finding.ignore_reason.clone().unwrap_or_default()}</td>
            <td class=CELL>{decided} {until}</td>
        </tr>
    }
}

fn assessed_findings(report: ReportData) -> impl IntoView + use<> {
    let content = if report.assessed.is_empty() {
        view! { <p class="text-muted-foreground text-sm">{t!("report.assessed_none")}</p> }
            .into_any()
    } else {
        let rows = report
            .assessed
            .clone()
            .into_iter()
            .map(assessed_row)
            .collect_view();
        view! {
            <Table caption=t!("report.assessed_title")>
                <thead>
                    <tr class=TABLE_HEAD_ROW>
                        <th scope="col" class=TABLE_HEAD>{t!("project.vulnerability")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("project.component")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("finding.justification")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("finding.reason")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("report.decided")}</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </Table>
        }
        .into_any()
    };
    view! {
        <Card>
            <CardHeader>
                <CardTitle>{t!("report.assessed_title")}</CardTitle>
                <CardDescription>{t!("report.assessed_description")}</CardDescription>
            </CardHeader>
            <CardContent>
                <div class="grid gap-2">
                    <p class="text-sm wrap-anywhere">
                        {t!("report.vex_export")} " "
                        <a class="text-primary underline underline-offset-4" href=report.vex_url.clone()>
                            {report.vex_url.clone()}
                        </a>
                    </p>
                    {content}
                    {note(hidden(report.ignored, report.assessed.len()).map(|count| tp!("report.assessed_more", count)))}
                </div>
            </CardContent>
        </Card>
    }
}

fn licenses(licenses: ReportLicenses) -> impl IntoView {
    let (description, content) = match licenses {
        ReportLicenses::Policy(violations) => {
            let counts = violations.counts;
            let description = format!(
                "{} · {}",
                tp!("project.licenses_forbidden", counts.forbidden),
                tp!("project.licenses_warned", counts.warned),
            );
            let more = note(
                hidden(counts.forbidden + counts.warned, violations.items.len())
                    .map(|count| tp!("report.licenses_more", count)),
            );
            let content = if violations.items.is_empty() {
                view! { <p class="text-muted-foreground text-sm">{t!("project.licenses_none")}</p> }
                    .into_any()
            } else {
                let rows = violations
                    .items
                    .into_iter()
                    .map(|violation| {
                        let variant = match violation.verdict {
                            LicenseAction::Forbid => BadgeVariant::Destructive,
                            LicenseAction::Warn | LicenseAction::Allow => BadgeVariant::Outline,
                        };
                        view! {
                            <tr class="border-b last:border-0">
                                <th scope="row" class=format!("{CELL} text-left font-medium")>
                                    {violation.name}
                                    <span class="text-muted-foreground block font-mono text-xs font-normal">
                                        {violation.purl}
                                    </span>
                                </th>
                                <td class=CELL>{violation.version.unwrap_or_default()}</td>
                                <td class=CELL>
                                    {violation
                                        .license
                                        .unwrap_or_else(|| t!("project.license_unknown").to_owned())}
                                </td>
                                <td class=CELL>
                                    <Badge variant=variant>{violation.verdict.verdict()}</Badge>
                                </td>
                            </tr>
                        }
                    })
                    .collect_view();
                view! {
                    <Table caption=t!("project.licenses_caption")>
                        <thead>
                            <tr class=TABLE_HEAD_ROW>
                                <th scope="col" class=TABLE_HEAD>{t!("project.component")}</th>
                                <th scope="col" class=TABLE_HEAD>{t!("project.version")}</th>
                                <th scope="col" class=TABLE_HEAD>{t!("project.license")}</th>
                                <th scope="col" class=TABLE_HEAD>{t!("project.verdict")}</th>
                            </tr>
                        </thead>
                        <tbody>{rows}</tbody>
                    </Table>
                }
                .into_any()
            };
            (
                description,
                view! {
                    {content}
                    {more}
                }
                .into_any(),
            )
        }
        ReportLicenses::Counts {
            groups,
            other,
            without,
        } => {
            let mut rows: Vec<(String, u64)> = groups;
            if other > 0 {
                rows.push((t!("report.licenses_other").to_owned(), other));
            }
            if without > 0 {
                rows.push((t!("report.licenses_without").to_owned(), without));
            }
            let content = if rows.is_empty() {
                view! { <p class="text-muted-foreground text-sm">{t!("report.licenses_empty")}</p> }
                    .into_any()
            } else {
                let rows = rows
                    .into_iter()
                    .map(|(license, count)| {
                        view! {
                            <tr class="border-b last:border-0">
                                <th scope="row" class=format!("{CELL} text-left font-normal")>{license}</th>
                                <td class=format!("{CELL} text-right tabular-nums")>{count}</td>
                            </tr>
                        }
                    })
                    .collect_view();
                view! {
                    <Table caption=t!("report.licenses_counts_caption")>
                        <thead>
                            <tr class=TABLE_HEAD_ROW>
                                <th scope="col" class=TABLE_HEAD>{t!("project.license")}</th>
                                <th scope="col" class=format!("{TABLE_HEAD} text-right")>{t!("report.license_components")}</th>
                            </tr>
                        </thead>
                        <tbody>{rows}</tbody>
                    </Table>
                }
                .into_any()
            };
            (t!("report.licenses_no_policy").to_owned(), content)
        }
    };
    view! {
        <Card>
            <CardHeader>
                <CardTitle>{t!("project.licenses_title")}</CardTitle>
                <CardDescription>{description}</CardDescription>
            </CardHeader>
            <CardContent>
                <div class="grid gap-2">{content}</div>
            </CardContent>
        </Card>
    }
}

/// The report as a complete HTML document, for the read API, in the language an
/// `Accept-Language` header prefers (English without one): light colors, and the interface's
/// stylesheet inlined when given, so an archived copy needs nothing else to show.
#[cfg(feature = "ssr")]
pub fn document(
    report: ReportData,
    accept_language: Option<&str>,
    stylesheet: Option<&str>,
) -> String {
    use leptos::tachys::view::RenderHtml;
    let locale = accept_language
        .and_then(crate::i18n::negotiate)
        .unwrap_or_else(crate::i18n::default_locale);
    let owner = Owner::new();
    owner.with(|| {
        provide_context(locale);
        let title = crate::components::title_text(&format!(
            "{} · {} {}",
            t!("report.title"),
            report.project_name,
            version_label(&report.version),
        ));
        let body = view! {
            <main class="mx-auto grid max-w-6xl grid-cols-1 gap-6 px-4 py-6">
                <ReportBody report />
            </main>
        }
        .to_html();
        // The stylesheet is the build's own: it holds no `</style>`.
        let style = stylesheet
            .map(|css| format!("<style>{css}</style>"))
            .unwrap_or_default();
        format!(
            "<!DOCTYPE html><html lang=\"{}\" class=\"light\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             <title>{title}</title>{style}</head>\
             <body class=\"bg-background text-foreground antialiased\">{body}</body></html>",
            crate::i18n::tag(locale),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FindingRow, SeverityCounts, Status};

    fn report() -> ReportData {
        let now = chrono::Utc::now().fixed_offset();
        ReportData {
            generated_at: now,
            nanobom_version: "0.1.2".to_owned(),
            host: "nanobom.example".to_owned(),
            vex_url: "https://nanobom.example/api/organizations/acme/projects/web/vex".to_owned(),
            organization_slug: "acme".to_owned(),
            organization_name: "R&D <Acme>".to_owned(),
            project_slug: "web".to_owned(),
            project_name: "</title><script>alert(1)</script>".to_owned(),
            version: "1.0".to_owned(),
            latest: true,
            active: true,
            upload: None,
            component_count: 3,
            stale: false,
            project_last_upload_at: Some(now),
            project_created_at: now,
            last_evaluation: None,
            kev_checked_at: None,
            epss_checked_at: None,
            counts: SeverityCounts {
                high: 1,
                ..SeverityCounts::default()
            },
            known_exploited: 0,
            ignored: 1,
            fixed_recently: 0,
            open: Vec::new(),
            assessed: vec![AssessedFinding {
                finding: FindingRow {
                    id: 1,
                    version: "1.0".to_owned(),
                    component_name: "minimist".to_owned(),
                    component_version: Some("1.2.5".to_owned()),
                    license: None,
                    ecosystem: "npm".to_owned(),
                    purl: "pkg:npm/minimist@1.2.5".to_owned(),
                    vulnerability_id: "GHSA-xvch-5gv4-984h".to_owned(),
                    aliases: vec!["CVE-2021-44906".to_owned()],
                    summary: None,
                    severity: crate::model::Severity::Critical,
                    cvss_score: None,
                    status: Status::Ignored,
                    first_seen_at: now,
                    fixed_at: None,
                    ignore_reason: Some("<b>build only</b>".to_owned()),
                    ignore_expires_at: None,
                    ignore_justification: None,
                    exploitation: crate::model::Exploitation::default(),
                    introduced_via: Vec::new(),
                },
                ignored_at: Some(now),
                ignored_by: Some("owner".to_owned()),
                ignored_by_token: None,
            }],
            licenses: ReportLicenses::Counts {
                groups: vec![("MIT".to_owned(), 2)],
                other: 0,
                without: 1,
            },
        }
    }

    #[test]
    fn the_document_escapes_names_and_follows_the_language() {
        let html = document(report(), None, Some("body{}"));
        assert!(html.starts_with("<!DOCTYPE html><html lang=\"en\" class=\"light\">"));
        assert!(html.contains("<style>body{}</style>"));
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;/title&gt;&lt;script&gt;"), "{html}");
        assert!(html.contains("R&amp;D &lt;Acme&gt;"));
        assert!(html.contains("&lt;b&gt;build only&lt;/b&gt;"));
        assert!(html.contains("Vulnerability report"));
        assert!(html.contains("None (accepted risk)"));
        assert!(html.contains("by owner"));

        let html = document(report(), Some("fr-FR,fr;q=0.9"), None);
        assert!(html.contains("<html lang=\"fr\""));
        assert!(html.contains("Rapport de vulnérabilités"));
        assert!(!html.contains("<style>"));
    }

    #[test]
    fn a_full_report_lists_its_open_findings_provenance_and_policy_violations() {
        use crate::model::{
            DependencyComponent, LicenseAction, LicenseCounts, LicenseViolation, LicenseViolations,
            Severity, Upload,
        };
        let now = chrono::Utc::now().fixed_offset();
        let mut data = report();
        data.stale = true;
        data.last_evaluation = Some(now);
        data.upload = Some(Upload {
            version: "1.0".to_owned(),
            uploaded_at: now,
            specification_version: "1.6".to_owned(),
            source_commit: Some("0123abcd".to_owned()),
            image_tag: Some("ghcr.io/acme/web:1.0".to_owned()),
            component_count: 3,
            components_without_purl: 1,
        });
        data.counts = SeverityCounts {
            critical: 1,
            medium: 2,
            ..SeverityCounts::default()
        };
        data.known_exploited = 1;
        let mut direct = data.assessed[0].finding.clone();
        direct.status = Status::Open;
        direct.severity = Severity::Critical;
        direct.vulnerability_id = "CVE-2021-44228".to_owned();
        direct.aliases = Vec::new();
        direct.component_name = "log4j-core".to_owned();
        direct.exploitation.known_exploited = true;
        direct.exploitation.epss_percentile = Some(0.97);
        // A component the project depends on directly is introduced through itself.
        direct.introduced_via = vec![DependencyComponent {
            purl: direct.purl.clone(),
            name: direct.component_name.clone(),
            version: direct.component_version.clone(),
        }];
        let mut transitive = direct.clone();
        transitive.severity = Severity::Medium;
        transitive.vulnerability_id = "GHSA-transitive".to_owned();
        transitive.component_name = "deep-dependency".to_owned();
        transitive.exploitation = crate::model::Exploitation::default();
        transitive.introduced_via = vec![DependencyComponent {
            purl: "pkg:npm/express@4.0.0".to_owned(),
            name: "express".to_owned(),
            version: Some("4.0.0".to_owned()),
        }];
        data.open = vec![
            ReportFinding {
                finding: direct,
                fixed_versions: vec!["2.17.1".to_owned()],
            },
            ReportFinding {
                finding: transitive,
                fixed_versions: Vec::new(),
            },
        ];
        data.ignored = 3;
        data.assessed[0].finding.ignore_justification = Some("code_not_reachable".to_owned());
        data.assessed[0].ignored_by = None;
        data.assessed[0].ignored_by_token = Some("CI".to_owned());
        data.assessed[0].ignored_at = None;
        data.licenses = ReportLicenses::Policy(LicenseViolations {
            counts: LicenseCounts {
                forbidden: 2,
                warned: 1,
            },
            items: vec![LicenseViolation {
                purl: "pkg:npm/copyleft@1.0.0".to_owned(),
                name: "copyleft".to_owned(),
                version: Some("1.0.0".to_owned()),
                license: Some("GPL-3.0-only".to_owned()),
                verdict: LicenseAction::Forbid,
                licenses: vec!["GPL-3.0-only".to_owned()],
            }],
        });

        let html = document(data, None, None);
        for expected in [
            "1 open vulnerability of high or critical severity.",
            "this report may not describe what is deployed",
            "0123abcd",
            "ghcr.io/acme/web:1.0",
            "CVE-2021-44228",
            "log4j-core",
            "2.17.1",
            "97%",
            ">Direct<",
            "Transitive, through express",
            // Three open findings counted, two listed.
            "And 1 more, listed on the project page.",
            // Three ignored, one listed.
            "And 2 more, listed on the project page.",
            "copyleft",
            "GPL-3.0-only",
            // Three violations counted, one listed.
            "And 2 more components, listed on the project page.",
        ] {
            assert!(html.contains(expected), "{expected} missing from {html}");
        }
        // Only the token is known: the decision column has no leading space.
        assert!(!html.contains("> by"), "{html}");
    }

    #[test]
    fn the_summary_sentence_follows_the_worst_severity() {
        let mut data = report();
        data.counts = SeverityCounts::default();
        assert_eq!(summary_sentence(&data), "No open vulnerabilities.");
        data.counts.low = 2;
        assert_eq!(
            summary_sentence(&data),
            "No open vulnerabilities of high or critical severity; 2 of lower or unknown severity."
        );
    }

    #[test]
    fn the_unnamed_version_is_named_once_and_inactive_versions_have_no_check_date() {
        let mut data = report();
        data.version = String::new();
        data.active = false;
        data.last_evaluation = Some(chrono::Utc::now().fixed_offset());
        let html = document(data, None, None);
        assert!(html.contains("· Unnamed version<"), "{html}");
        assert!(!html.contains("version Unnamed version"), "{html}");
        assert!(
            html.contains("Not since the version became inactive"),
            "{html}"
        );

        let html = document(report(), None, None);
        assert!(html.contains("· version 1.0<"), "{html}");
    }
}
