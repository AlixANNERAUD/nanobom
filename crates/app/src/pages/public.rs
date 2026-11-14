//! The public page of a project version: its findings and how they were triaged, for visitors
//! who are not members, such as readers of an open-source project's README.
//!
//! The server renders it outside the router, as a standalone document ([`document`]), with no
//! script: it uses only plain components, like the report ([`super::report`]), whose layout it
//! follows. It shows the fields of [`PublicPageData`] and nothing else: no organization, no
//! link into the interface, no reasons and nobody's name. Advisory links leave for osv.dev
//! without a referrer, so the page's key never reaches it.

use leptos::prelude::*;

use crate::{
    components::{SeverityBadge, format_date, format_time, ui::*},
    model::{PublicAssessedFinding, PublicComponent, PublicOpenFinding, PublicPageData},
    pages::{
        findings::{justification_label, percent, version_label},
        report::{CELL, fact, hidden, note, summary_sentence, time_or_never},
    },
    t, tf, tp,
};

/// The page itself, in the request's language.
#[component]
pub fn PublicPageBody(page: PublicPageData) -> impl IntoView {
    let version = if page.version.is_empty() {
        version_label(&page.version)
    } else {
        tf!("report.version", version = page.version.clone()).to_string()
    };
    let served = tf!(
        "public.served_by",
        version = page.nanobom_version.clone(),
        host = page.host.clone()
    );
    let stale = page.stale.then(|| {
        view! {
            <Alert variant=AlertVariant::Warning title=t!("report.stale_title")>
                {t!("public.stale")}
            </Alert>
        }
    });
    let inactive = (!page.active).then(|| {
        view! {
            <Alert variant=AlertVariant::Warning title=t!("project.inactive_title")>
                {t!("report.inactive")}
            </Alert>
        }
    });
    view! {
        <article class="grid gap-6">
            <header class="grid gap-1">
                <h1 class="text-2xl font-semibold tracking-tight wrap-anywhere">{page.project_name.clone()}</h1>
                <p class="text-lg wrap-anywhere">{format!("{} · {}", t!("public.title"), version)}</p>
                <p class="text-muted-foreground text-sm wrap-anywhere">{served}</p>
            </header>
            {stale}
            {inactive}
            {provenance(page.clone())}
            {summary(page.clone())}
            {open_findings(page.clone())}
            {assessed_findings(page)}
            <Card>
                <CardHeader>
                    <CardTitle>{t!("report.method_title")}</CardTitle>
                </CardHeader>
                <CardContent>
                    <div class="grid gap-2 text-sm">
                        <p>{t!("report.method_checks")}</p>
                        <p>{t!("report.method_limits")}</p>
                        <p>{t!("public.method_time")}</p>
                    </div>
                </CardContent>
            </Card>
        </article>
    }
}

/// Where the page's data comes from and how fresh it is.
fn provenance(page: PublicPageData) -> impl IntoView + use<> {
    let upload = page.uploaded_at.map_or_else(
        || t!("report.no_upload").to_owned(),
        |time| tf!("report.uploaded", time = format_time(time)),
    );
    let last_evaluation = if page.active {
        time_or_never(page.last_evaluation)
    } else {
        // Runs skip inactive versions: the last run's date would overstate them.
        t!("report.not_checked_while_inactive").to_owned()
    };
    view! {
        <Card>
            <CardHeader>
                <CardTitle>{t!("report.scope_title")}</CardTitle>
            </CardHeader>
            <CardContent>
                <dl class="grid gap-2 text-sm">
                    {fact(t!("report.sbom").to_owned(), upload)}
                    {fact(t!("report.components_checked").to_owned(), page.component_count.to_string())}
                    {fact(
                        t!("report.components_not_checked").to_owned(),
                        tp!("report.without_purl", page.components_without_purl),
                    )}
                    {fact(t!("report.last_evaluation").to_owned(), last_evaluation)}
                    {fact(t!("report.kev_checked").to_owned(), time_or_never(page.kev_checked_at))}
                    {fact(t!("report.epss_checked").to_owned(), time_or_never(page.epss_checked_at))}
                </dl>
            </CardContent>
        </Card>
    }
}

fn summary(page: PublicPageData) -> impl IntoView + use<> {
    let known_exploited = i64::try_from(page.known_exploited).unwrap_or(i64::MAX);
    view! {
        <Card>
            <CardHeader>
                <CardTitle>{t!("report.summary_title")}</CardTitle>
            </CardHeader>
            <CardContent>
                <div class="grid gap-3">
                    <p class="font-medium">{summary_sentence(&page.counts)}</p>
                    <SeverityBar counts=page.counts />
                    <div class="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
                        <p class="font-medium">{tp!("project.open_findings", page.counts.total())}</p>
                        <SeverityLegend counts=page.counts known_exploited=known_exploited />
                    </div>
                    <dl class="grid gap-2 text-sm">
                        {fact(t!("report.ignored").to_owned(), page.ignored.to_string())}
                        {fact(t!("report.fixed_recently").to_owned(), page.fixed_recently.to_string())}
                    </dl>
                </div>
            </CardContent>
        </Card>
    }
}

/// The address of an advisory on osv.dev, which knows every identifier nanobom learned from it,
/// aliases included.
fn advisory_url(id: &str) -> String {
    format!("https://osv.dev/vulnerability/{id}")
}

/// The identifier of a finding's vulnerability, linked to its advisory, and its other names.
fn identifiers(id: &str, aliases: &[String]) -> impl IntoView + use<> {
    let aliases = (!aliases.is_empty()).then(|| {
        view! { <span class="text-muted-foreground block font-mono text-xs">{aliases.join(", ")}</span> }
    });
    view! {
        <a
            class=format!("{MONO} text-primary block font-medium underline underline-offset-4")
            href=advisory_url(id)
            rel="noreferrer"
        >
            {id.to_owned()}
        </a>
        {aliases}
    }
}

fn component(component: &PublicComponent) -> impl IntoView + use<> {
    view! {
        <span class="block font-medium">{component.name.clone()}</span>
        <span class="text-muted-foreground block font-mono text-xs">
            {component.version.clone().unwrap_or_default()}
        </span>
        <span class="text-muted-foreground block font-mono text-xs">{component.purl.clone()}</span>
    }
}

fn open_row(finding: PublicOpenFinding) -> impl IntoView {
    let exploited = if finding.exploitation.known_exploited {
        view! { <Badge variant=BadgeVariant::Destructive>{t!("report.yes")}</Badge> }.into_any()
    } else {
        view! { <span class="text-muted-foreground">{t!("report.no")}</span> }.into_any()
    };
    let fixed = if finding.fixed_versions.is_empty() {
        view! { <span class="text-muted-foreground">{t!("report.unknown")}</span> }.into_any()
    } else {
        view! { <span class=MONO>{finding.fixed_versions.join(", ")}</span> }.into_any()
    };
    let summary = finding
        .summary
        .clone()
        .map(|summary| view! { <span class="block pt-1">{summary}</span> });
    view! {
        <tr class="border-b last:border-0">
            <th scope="row" class=format!("{CELL} text-left font-normal")>
                {identifiers(&finding.vulnerability_id, &finding.aliases)}
                {summary}
            </th>
            <td class=CELL>{component(&finding.component)}</td>
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
            <td class=CELL>{fixed}</td>
            <td class=format!("{CELL} whitespace-nowrap")>{format_date(finding.first_seen_at)}</td>
        </tr>
    }
}

fn open_findings(page: PublicPageData) -> impl IntoView + use<> {
    let content = if page.open.is_empty() {
        view! { <p class="text-muted-foreground text-sm">{t!("report.open_none")}</p> }.into_any()
    } else {
        let rows = page.open.clone().into_iter().map(open_row).collect_view();
        view! {
            <Table caption=t!("report.open_caption")>
                <thead>
                    <tr class=TABLE_HEAD_ROW>
                        <th scope="col" class=TABLE_HEAD>{t!("project.vulnerability")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("project.component")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("project.severity")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("project.known_exploited")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("project.epss")}</th>
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
                <CardDescription>{t!("public.open_description")}</CardDescription>
            </CardHeader>
            <CardContent>
                <div class="grid gap-2">
                    {content}
                    {note(hidden(page.counts.total(), page.open.len()).map(|count| tp!("public.more", count)))}
                </div>
            </CardContent>
        </Card>
    }
}

fn assessed_row(finding: PublicAssessedFinding) -> impl IntoView {
    let justification = finding
        .justification
        .as_deref()
        .map_or_else(|| t!("report.accepted_risk"), justification_label);
    view! {
        <tr class="border-b last:border-0">
            <th scope="row" class=format!("{CELL} text-left font-normal")>
                {identifiers(&finding.vulnerability_id, &finding.aliases)}
            </th>
            <td class=CELL>{component(&finding.component)}</td>
            <td class=CELL><SeverityBadge severity=finding.severity /></td>
            <td class=CELL>{justification}</td>
            <td class=format!("{CELL} whitespace-nowrap")>
                {finding.ignored_at.map(format_date).unwrap_or_default()}
            </td>
        </tr>
    }
}

fn assessed_findings(page: PublicPageData) -> impl IntoView + use<> {
    let content = if page.assessed.is_empty() {
        view! { <p class="text-muted-foreground text-sm">{t!("report.assessed_none")}</p> }
            .into_any()
    } else {
        let rows = page
            .assessed
            .clone()
            .into_iter()
            .map(assessed_row)
            .collect_view();
        view! {
            <Table caption=t!("public.assessed_title")>
                <thead>
                    <tr class=TABLE_HEAD_ROW>
                        <th scope="col" class=TABLE_HEAD>{t!("project.vulnerability")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("project.component")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("project.severity")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("finding.justification")}</th>
                        <th scope="col" class=TABLE_HEAD>{t!("public.ignored_on")}</th>
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
                <CardTitle>{t!("public.assessed_title")}</CardTitle>
                <CardDescription>{t!("public.assessed_description")}</CardDescription>
            </CardHeader>
            <CardContent>
                <div class="grid gap-2">
                    <p class="text-sm wrap-anywhere">
                        {t!("public.vex")} " "
                        <a
                            class="text-primary underline underline-offset-4"
                            href=page.vex_url.clone()
                            rel="noreferrer"
                        >
                            {page.vex_url.clone()}
                        </a>
                    </p>
                    {content}
                    {note(hidden(page.ignored, page.assessed.len()).map(|count| tp!("public.more", count)))}
                </div>
            </CardContent>
        </Card>
    }
}

/// The public page as a complete HTML document, in the language an `Accept-Language` header
/// prefers (English without one): light colors, the interface's stylesheet inlined when given,
/// and no script. The head asks search engines not to index it and browsers to send no
/// referrer, as the server's headers also do.
#[cfg(feature = "ssr")]
pub fn document(
    page: PublicPageData,
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
            page.project_name,
            t!("public.title"),
            version_label(&page.version),
        ));
        let body = view! {
            <main class="mx-auto grid max-w-6xl grid-cols-1 gap-6 px-4 py-6">
                <PublicPageBody page />
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
             <meta name=\"robots\" content=\"noindex\">\
             <meta name=\"referrer\" content=\"no-referrer\">\
             <title>{title}</title>{style}</head>\
             <body class=\"bg-background text-foreground antialiased\">{body}</body></html>",
            crate::i18n::tag(locale),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Exploitation, Severity, SeverityCounts};

    fn page() -> PublicPageData {
        let now = chrono::Utc::now().fixed_offset();
        PublicPageData {
            nanobom_version: "0.1.3".to_owned(),
            host: "nanobom.example".to_owned(),
            vex_url: "https://nanobom.example/public/0123456789abcdef0123456789abcdef/vex.json"
                .to_owned(),
            project_name: "</title><script>alert(1)</script>".to_owned(),
            version: "1.0".to_owned(),
            latest: true,
            active: true,
            uploaded_at: Some(now),
            component_count: 3,
            components_without_purl: 1,
            last_evaluation: Some(now),
            kev_checked_at: None,
            epss_checked_at: None,
            stale: false,
            counts: SeverityCounts {
                critical: 2,
                ..SeverityCounts::default()
            },
            known_exploited: 1,
            ignored: 3,
            fixed_recently: 4,
            open: vec![PublicOpenFinding {
                vulnerability_id: "CVE-2021-44228".to_owned(),
                aliases: vec!["GHSA-jfh8-c2jp-5v3q".to_owned()],
                summary: Some("Remote code execution in <log4j>".to_owned()),
                severity: Severity::Critical,
                cvss_score: Some(10.0),
                component: PublicComponent {
                    name: "log4j-core".to_owned(),
                    version: Some("2.14.1".to_owned()),
                    purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1".to_owned(),
                },
                fixed_versions: vec!["2.17.1".to_owned()],
                exploitation: Exploitation {
                    known_exploited: true,
                    epss_percentile: Some(0.97),
                    ..Exploitation::default()
                },
                first_seen_at: now,
            }],
            assessed: vec![
                PublicAssessedFinding {
                    vulnerability_id: "GHSA-xvch-5gv4-984h".to_owned(),
                    aliases: vec!["CVE-2021-44906".to_owned()],
                    severity: Severity::Critical,
                    component: PublicComponent {
                        name: "minimist".to_owned(),
                        version: Some("1.2.5".to_owned()),
                        purl: "pkg:npm/minimist@1.2.5".to_owned(),
                    },
                    justification: Some("code_not_reachable".to_owned()),
                    ignored_at: Some(now),
                },
                PublicAssessedFinding {
                    vulnerability_id: "GHSA-accepted".to_owned(),
                    aliases: Vec::new(),
                    severity: Severity::Low,
                    component: PublicComponent {
                        name: "left-pad".to_owned(),
                        version: None,
                        purl: "pkg:npm/left-pad".to_owned(),
                    },
                    justification: None,
                    ignored_at: None,
                },
            ],
        }
    }

    #[test]
    fn the_document_escapes_names_and_follows_the_language() {
        let html = document(page(), None, Some("body{}"));
        assert!(html.starts_with("<!DOCTYPE html><html lang=\"en\" class=\"light\">"));
        assert!(html.contains("<meta name=\"robots\" content=\"noindex\">"));
        assert!(html.contains("<meta name=\"referrer\" content=\"no-referrer\">"));
        assert!(html.contains("<style>body{}</style>"));
        assert!(!html.contains("<script"), "{html}");
        assert!(html.contains("&lt;/title&gt;&lt;script&gt;"), "{html}");
        assert!(
            html.contains("Remote code execution in &lt;log4j&gt;"),
            "{html}"
        );
        for expected in [
            "Vulnerabilities · version 1.0",
            "nanobom 0.1.3 on nanobom.example",
            "2 open vulnerabilities of high or critical severity.",
            "href=\"https://osv.dev/vulnerability/CVE-2021-44228\"",
            "GHSA-jfh8-c2jp-5v3q",
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            "2.17.1",
            "97%",
            "Vulnerable code not reachable",
            "None (accepted risk)",
            "/public/0123456789abcdef0123456789abcdef/vex.json",
            // Two open counted, one listed; three ignored, two listed.
            "And 1 more, not listed here.",
        ] {
            assert!(html.contains(expected), "{expected} missing from {html}");
        }
        assert_eq!(html.matches("rel=\"noreferrer\"").count(), 4, "{html}");
        // Nothing links into the interface.
        assert!(!html.contains("/organizations"), "{html}");

        let html = document(page(), Some("fr-FR,fr;q=0.9"), None);
        assert!(html.contains("<html lang=\"fr\""));
        assert!(html.contains("Vulnérabilités"), "{html}");
        assert!(!html.contains("<style>"));
    }

    #[test]
    fn stale_and_inactive_versions_are_flagged() {
        let mut data = page();
        data.stale = true;
        data.active = false;
        data.version = String::new();
        let html = document(data, None, None);
        assert!(html.contains("The SBOM may be out of date"), "{html}");
        assert!(
            html.contains("Not since the version became inactive"),
            "{html}"
        );
        assert!(html.contains("· Unnamed version<"), "{html}");
    }
}
