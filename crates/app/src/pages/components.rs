//! The components of a project version: what its SBOM holds, vulnerable or not, with their
//! licenses and how the project depends on them.
//!
//! A version may hold thousands of components, so the page lists one page of them at a time,
//! filtered and sorted by the database. Filters and pages are plain links and a GET form, which
//! keep the version shown.

use leptos::prelude::*;
use leptos_router::hooks::{use_params_map, use_query_map};

use crate::{
    components::{Empty, Heading, Loaded, Page, PageTitle, SeverityBadge, ui::*},
    functions::load_components,
    model::{ComponentRow, ComponentsData, ComponentsQuery, ComponentsShown, DependencyKind},
    pages::findings::{
        encode_query_value, names_versions, split_namespace, version_options, version_query,
    },
    t, tf, tp,
};

/// The views of a project, as tabs above their content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectView {
    Findings,
    Components,
}

const TAB: &str =
    "text-muted-foreground hover:text-foreground -mb-px border-b-2 border-transparent px-1 pb-2";
const TAB_CURRENT: &str =
    "text-foreground -mb-px border-b-2 border-foreground px-1 pb-2 font-medium";

/// The tabs between a project version's findings and its components. `version_suffix` is the
/// query string naming the version, empty for the latest one.
pub(crate) fn project_views(
    organization: &str,
    project: &str,
    version_suffix: &str,
    components: u64,
    current: ProjectView,
) -> impl IntoView + use<> {
    let base = format!("/organizations/{organization}/projects/{project}");
    let tab = move |view: ProjectView, href: String, label: String| {
        let selected = view == current;
        view! {
            <a href=href class=if selected { TAB_CURRENT } else { TAB } aria-current=selected.then_some("page")>
                {label}
            </a>
        }
    };
    view! {
        <nav aria-label=t!("project.views") class="flex gap-4 border-b text-sm">
            {tab(
                ProjectView::Findings,
                format!("{base}{version_suffix}"),
                t!("project.tab_findings").to_owned(),
            )}
            {tab(
                ProjectView::Components,
                format!("{base}/components{version_suffix}"),
                tf!("project.tab_components", count = components).to_string(),
            )}
        </nav>
    }
}

/// Encodes a query string value: names are free text and may hold `&`, `#` or `+`.
/// The address of a page of components with the same version and filters.
fn page_href(
    base: &str,
    version: Option<&str>,
    name: &str,
    shown: ComponentsShown,
    page: u64,
) -> String {
    let mut pairs = Vec::new();
    if let Some(version) = version {
        pairs.push(format!("version={}", encode_query_value(version)));
    }
    if !name.is_empty() {
        pairs.push(format!("name={}", encode_query_value(name)));
    }
    if shown != ComponentsShown::All {
        pairs.push(format!("show={}", shown.as_str()));
    }
    if page > 1 {
        pairs.push(format!("page={page}"));
    }
    if pairs.is_empty() {
        base.to_owned()
    } else {
        format!("{base}?{}", pairs.join("&"))
    }
}

fn shown_label(shown: ComponentsShown) -> &'static str {
    match shown {
        ComponentsShown::All => t!("components.show_all"),
        ComponentsShown::WithOpenFindings => t!("components.show_open"),
        ComponentsShown::WithoutLicense => t!("components.show_unlicensed"),
    }
}

fn dependency_label(dependency: DependencyKind) -> &'static str {
    match dependency {
        DependencyKind::Direct => t!("components.direct"),
        DependencyKind::Transitive => t!("components.transitive"),
        DependencyKind::Unknown => t!("components.dependency_unknown"),
    }
}

/// The filters, a GET form with one button: the version, for projects that name versions, the
/// name and what to show. Filtering goes back to the first page.
fn filters(data: &ComponentsData, query: &ComponentsQuery) -> impl IntoView + use<> {
    let shown = ComponentsShown::parse(query.show.as_deref());
    let version = if names_versions(&data.versions) {
        Some(
            view! {
                <div class="grid min-w-0 gap-1">
                    <label class=FILTER_LABEL for="version">{t!("project.version")}</label>
                    <select id="version" name="version" class=format!("{SELECT_COMPACT} max-w-56")>
                        {version_options(&data.versions, &data.version.name)}
                    </select>
                </div>
            }
            .into_any(),
        )
    } else {
        query.version.clone().map(|version| {
            view! { <input type="hidden" name="version" value=version /> }.into_any()
        })
    };
    let options = std::iter::once(ComponentsShown::All)
        .chain(ComponentsShown::FILTERS)
        .map(|option| {
            view! {
                <option value=option.as_str() selected=option == shown>
                    {shown_label(option)}
                </option>
            }
        })
        .collect_view();
    view! {
        <form method="get" class="flex flex-wrap items-end gap-x-3 gap-y-2" aria-label=t!("components.filter_label")>
            {version}
            <div class="grid min-w-0 gap-1">
                <label class=FILTER_LABEL for="components-name">{t!("components.name")}</label>
                <input
                    id="components-name"
                    name="name"
                    type="search"
                    class=format!("{INPUT} h-8 max-w-56")
                    value=query.name.clone().unwrap_or_default()
                />
            </div>
            <div class="grid min-w-0 gap-1">
                <label class=FILTER_LABEL for="components-show">{t!("components.show")}</label>
                <select id="components-show" name="show" class=SELECT_COMPACT>
                    {options}
                </select>
            </div>
            <Button variant=ButtonVariant::Secondary size=ButtonSize::Small>{t!("project.filter")}</Button>
        </form>
    }
}

/// The open findings of a component: the worst severity and a link to them, the finding itself
/// when there is one. The project page has no filter by component, so several findings link
/// to the version's findings.
fn findings_cell(component: &ComponentRow, project_href: &str) -> impl IntoView + use<> {
    match component.worst_severity {
        Some(severity) => {
            let href = match component.only_open_finding {
                Some(id) => format!("/findings/{id}"),
                None => project_href.to_owned(),
            };
            view! {
                <span class="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity />
                    <a class="underline-offset-4 hover:underline whitespace-nowrap" href=href>
                        {tp!("project.open_findings", component.open_findings)}
                    </a>
                </span>
            }
            .into_any()
        }
        None => view! { <span class="text-muted-foreground">{t!("components.no_findings")}</span> }
            .into_any(),
    }
}

fn component_rows(components: Vec<ComponentRow>, project_href: &str) -> impl IntoView + use<> {
    components
        .into_iter()
        .map(|component| {
            let findings = findings_cell(&component, project_href);
            let (namespace, name) = split_namespace(&component.name);
            let namespace = (!namespace.is_empty()).then(|| {
                view! { <span class="text-muted-foreground font-normal">{namespace.to_owned()}</span> }
            });
            let name = name.to_owned();
            view! {
                <tr class=TABLE_ROW>
                    <th scope="row" class=format!("{TABLE_CELL} text-left font-medium wrap-anywhere")>
                        {namespace}
                        {name}
                        <span class=format!("{MONO} text-muted-foreground block text-xs font-normal break-all")>
                            {component.purl.clone()}
                        </span>
                    </th>
                    <td class=format!("{TABLE_CELL} {MONO} wrap-anywhere")>{component.version.clone().unwrap_or_default()}</td>
                    <td class=TABLE_CELL>{component.ecosystem.clone()}</td>
                    <td class=format!("{TABLE_CELL} wrap-anywhere")>
                        {match component.license.clone() {
                            Some(license) => license.into_any(),
                            None => view! {
                                <span class="text-muted-foreground">{t!("components.no_license")}</span>
                            }
                                .into_any(),
                        }}
                    </td>
                    <td class=TABLE_CELL>{findings}</td>
                    <td class=format!("{TABLE_CELL} whitespace-nowrap")>{dependency_label(component.dependency)}</td>
                </tr>
            }
        })
        .collect_view()
}

#[component]
pub fn ComponentsPage() -> impl IntoView {
    let params = use_params_map();
    let query = use_query_map();
    let key = move || {
        let params = params.read();
        let query = query.read();
        let nonempty = |name: &str| query.get(name).filter(|value| !value.trim().is_empty());
        (
            params.get("organization").unwrap_or_default(),
            params.get("project").unwrap_or_default(),
            ComponentsQuery {
                // Empty names the unnamed version.
                version: query.get("version"),
                name: nonempty("name"),
                show: nonempty("show"),
                page: query
                    .get("page")
                    .and_then(|page| page.parse().ok())
                    .unwrap_or(1),
            },
        )
    };
    let data = Resource::new(key, |(organization, project, query)| {
        load_components(organization, project, query)
    });
    view! {
        <Page title=t!("components.title")>
            <Loaded
                resource=data
                render=move |data: ComponentsData| {
                    let (_, _, query) = key();
                    let organization_slug = data.organization.slug.clone();
                    let project_href = format!("/organizations/{organization_slug}/projects/{}", data.slug);
                    // Links name the version shown, unless it is the latest, which they show anyway.
                    let version = (!data.version.latest).then(|| data.version.name.clone());
                    let version_suffix = version
                        .as_deref()
                        .map(|name| format!("?{}", version_query(name)))
                        .unwrap_or_default();
                    let shown = ComponentsShown::parse(query.show.as_deref());
                    let name = query.name.clone().unwrap_or_default().trim().to_owned();
                    let base = format!("{project_href}/components");
                    let mut facts = vec![tp!("components.total", data.total)];
                    if data.without_purl > 0 {
                        facts.push(tp!("components.without_purl", data.without_purl));
                    }
                    if !name.is_empty() || shown != ComponentsShown::All {
                        facts.push(tp!("components.matching", data.matching));
                    }
                    let pages = data.matching.div_ceil(data.per_page).max(1);
                    let pagination = (data.page > 1 || data.has_next).then(|| {
                        let previous = (data.page > 1).then(|| {
                            let href = page_href(&base, version.as_deref(), &name, shown, data.page - 1);
                            view! {
                                <LinkButton href=href variant=ButtonVariant::Outline size=ButtonSize::Small>
                                    {t!("components.previous")}
                                </LinkButton>
                            }
                        });
                        let next = data.has_next.then(|| {
                            let href = page_href(&base, version.as_deref(), &name, shown, data.page + 1);
                            view! {
                                <LinkButton href=href variant=ButtonVariant::Outline size=ButtonSize::Small>
                                    {t!("components.next")}
                                </LinkButton>
                            }
                        });
                        view! {
                            <nav aria-label=t!("components.pagination") class="flex flex-wrap items-center gap-3 text-sm">
                                {previous}
                                <span class="text-muted-foreground">
                                    {tf!("components.page_of", page = data.page, pages = pages)}
                                </span>
                                {next}
                            </nav>
                        }
                    });
                    let table = if data.components.is_empty() {
                        let (title, text) = if data.total == 0 {
                            (t!("components.empty_title"), t!("components.empty_text"))
                        } else {
                            (t!("components.no_match_title"), t!("components.no_match_text"))
                        };
                        view! { <Empty title=title>{text}</Empty> }.into_any()
                    } else {
                        let rows = component_rows(
                            data.components.clone(),
                            &format!("{project_href}{version_suffix}"),
                        );
                        let partial = data.dependencies_partial.then(|| view! {
                            <p class="text-muted-foreground text-sm">{t!("finding.partial_graph")}</p>
                        });
                        view! {
                            {partial}
                            <Table caption=tp!("components.caption", data.matching) class="min-w-[56rem]">
                                <thead>
                                    <tr class=TABLE_HEAD_ROW>
                                        <th scope="col" class=TABLE_HEAD>{t!("components.component")}</th>
                                        <th scope="col" class=TABLE_HEAD>{t!("project.version")}</th>
                                        <th scope="col" class=TABLE_HEAD>{t!("components.ecosystem")}</th>
                                        <th scope="col" class=TABLE_HEAD>{t!("components.license")}</th>
                                        <th scope="col" class=TABLE_HEAD>{t!("components.findings")}</th>
                                        <th scope="col" class=TABLE_HEAD>{t!("components.dependency")}</th>
                                    </tr>
                                </thead>
                                <tbody>{rows}</tbody>
                            </Table>
                        }
                            .into_any()
                    };
                    let views = project_views(
                        &organization_slug,
                        &data.slug,
                        &version_suffix,
                        data.total,
                        ProjectView::Components,
                    );
                    let filters = filters(&data, &query);
                    view! {
                        <PageTitle text=format!("{} · {}", t!("components.title"), data.name) />
                        <nav aria-label=t!("common.breadcrumb") class="text-muted-foreground text-sm wrap-anywhere">
                            <a class="hover:underline" href=format!("/organizations/{organization_slug}")>
                                {data.organization.name.clone()}
                            </a>
                            " / "
                            <a class="hover:underline" href=format!("{project_href}{version_suffix}")>
                                {data.name.clone()}
                            </a>
                            " / "
                            <span aria-current="page">{t!("components.title")}</span>
                        </nav>
                        <Heading title=data.name.clone() subtitle=facts.join(" · ") />
                        {views}
                        {filters}
                        {table}
                        {pagination}
                    }
                }
            />
        </Page>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_addresses_keep_the_version_and_filters() {
        let base = "/organizations/acme/projects/web/components";
        assert_eq!(page_href(base, None, "", ComponentsShown::All, 1), base);
        assert_eq!(
            page_href(
                base,
                Some("1.0+build"),
                "a&b c",
                ComponentsShown::WithoutLicense,
                3
            ),
            format!("{base}?version=1.0%2Bbuild&name=a%26b%20c&show=unlicensed&page=3")
        );
        assert_eq!(
            page_href(base, Some(""), "", ComponentsShown::WithOpenFindings, 2),
            format!("{base}?version=&show=open&page=2")
        );
    }

    #[test]
    fn non_ascii_names_are_encoded_by_byte() {
        assert_eq!(encode_query_value("é/x"), "%C3%A9%2Fx");
    }
}
