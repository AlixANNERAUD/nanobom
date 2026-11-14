//! The About page: which release runs, who wrote it, where to read more, and the data sources
//! nanobom relies on with how fresh they are on this instance.
//!
//! It is for signed-in users only, like every page of the interface: it names the release, and
//! an anonymous page naming it would tell anyone which instances run one with a known flaw.
//! The release, the author and the links come from the workspace's Cargo metadata, so a fork
//! shows its own.

use leptos::prelude::*;

use crate::{
    components::{Heading, Loaded, Page, ui::*},
    functions::load_about,
    model::AboutData,
    pages::report::{fact, time_or_never},
    t, tf,
};

/// The running release.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The source repository, which also hosts the release notes and the issue tracker.
const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

/// The guide.
const GUIDE: &str = env!("CARGO_PKG_HOMEPAGE");

/// The SPDX expression of nanobom's license.
const LICENSE: &str = env!("CARGO_PKG_LICENSE");

/// Where the author's name links to: the source link already leads to GitHub.
const AUTHOR_URL: &str = "https://alix.anneraud.fr";

/// The page listing OSV's sources and the license of each.
const OSV_SOURCES: &str = "https://google.github.io/osv.dev/data/";

/// Links leaving for another site. Each also sends no referrer: the instance's addresses are
/// nobody else's business.
const LINK: &str = "text-primary underline underline-offset-4";

/// The first author of the workspace without the `<email>` part, which is never shown.
pub fn author() -> &'static str {
    let authors = env!("CARGO_PKG_AUTHORS");
    let first = authors.split(':').next().unwrap_or(authors);
    first.split('<').next().unwrap_or(first).trim()
}

#[component]
pub fn AboutPage() -> impl IntoView {
    let data = Resource::new(|| (), |()| load_about());
    view! {
        <Page title=t!("about.title")>
            <Heading title=t!("about.heading") />
            <Loaded resource=data render=|data: AboutData| view! { <AboutBody data /> } />
        </Page>
    }
}

fn external(href: String, text: String) -> impl IntoView {
    view! {
        <a class=LINK href=href rel="noreferrer">
            {text}
        </a>
    }
}

/// The cards of the page. Plain components only, so a test can render them outside the router.
#[component]
pub fn AboutBody(data: AboutData) -> impl IntoView {
    view! {
        <Card>
            <CardHeader>
                <CardTitle>{t!("about.name")}</CardTitle>
                <CardDescription>{t!("about.description")}</CardDescription>
            </CardHeader>
            <CardContent>
                <dl class="grid gap-2 text-sm">
                    {fact(t!("about.version").to_owned(), VERSION.to_owned())}
                    <div class="grid gap-x-4 sm:grid-cols-[16rem_minmax(0,1fr)]">
                        <dt class="text-muted-foreground">{t!("about.author")}</dt>
                        <dd>{external(AUTHOR_URL.to_owned(), author().to_owned())}</dd>
                    </div>
                </dl>
            </CardContent>
        </Card>
        <Card>
            <CardHeader>
                <CardTitle>{t!("about.links")}</CardTitle>
            </CardHeader>
            <CardContent>
                <ul class="grid gap-2 text-sm">
                    <li>{external(GUIDE.to_owned(), t!("about.guide").to_owned())}</li>
                    <li>{external(REPOSITORY.to_owned(), t!("about.source").to_owned())}</li>
                    <li>
                        {external(format!("{REPOSITORY}/releases"), t!("about.releases").to_owned())}
                    </li>
                    <li>{external(format!("{REPOSITORY}/issues"), t!("about.issues").to_owned())}</li>
                </ul>
            </CardContent>
        </Card>
        <Card>
            <CardHeader>
                <CardTitle>{t!("about.license")}</CardTitle>
            </CardHeader>
            <CardContent>
                <p class="text-sm">
                    {tf!("about.license_text", license = LICENSE)}" "
                    {external(
                        format!("{REPOSITORY}/blob/main/LICENSE"),
                        t!("about.license_link").to_owned(),
                    )}
                </p>
            </CardContent>
        </Card>
        <Card>
            <CardHeader>
                <CardTitle>{t!("about.sources")}</CardTitle>
                <CardDescription>{t!("about.sources_description")}</CardDescription>
            </CardHeader>
            <CardContent>
                <div class="grid gap-6">
                    <Source
                        name=t!("about.osv_name").to_owned()
                        href="https://osv.dev"
                        purpose=t!("about.osv_use").to_owned()
                        terms=view! {
                            {t!("about.osv_terms")}
                            " "
                            {external(OSV_SOURCES.to_owned(), t!("about.osv_terms_link").to_owned())}
                        }
                            .into_any()
                        read=time_or_never(data.osv_read_at)
                    />
                    <Source
                        name=t!("about.kev_name").to_owned()
                        href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                        purpose=t!("about.kev_use").to_owned()
                        terms=t!("about.kev_terms").into_any()
                        read=time_or_never(data.kev_checked_at)
                    />
                    <Source
                        name=t!("about.epss_name").to_owned()
                        href="https://www.first.org/epss/"
                        purpose=t!("about.epss_use").to_owned()
                        terms=t!("about.epss_terms").into_any()
                        read=time_or_never(data.epss_checked_at)
                    />
                </div>
            </CardContent>
        </Card>
        <Card>
            <CardHeader>
                <CardTitle>{t!("about.built_with")}</CardTitle>
            </CardHeader>
            <CardContent>
                <dl class="grid gap-2 text-sm">
                    <Credit
                        names=vec![("Rust", "https://www.rust-lang.org")]
                        role=t!("about.rust_role").to_owned()
                    />
                    <Credit
                        names=vec![("Leptos", "https://leptos.dev")]
                        role=t!("about.leptos_role").to_owned()
                    />
                    <Credit
                        names=vec![
                            ("shadcn/ui", "https://github.com/shadcn-ui/ui"),
                            ("Rust/UI", "https://github.com/rust-ui/ui"),
                        ]
                        role=t!("about.primitives_role").to_owned()
                    />
                </dl>
            </CardContent>
        </Card>
    }
}

/// A data source: what nanobom uses it for, its terms and when this instance last read it.
#[component]
fn Source(
    name: String,
    href: &'static str,
    purpose: String,
    terms: AnyView,
    read: String,
) -> impl IntoView {
    view! {
        <section class="grid gap-1 text-sm">
            <h3 class="font-medium">{external(href.to_owned(), name)}</h3>
            <p>{purpose}</p>
            <p class="text-muted-foreground">{terms}</p>
            <p class="text-muted-foreground">{tf!("about.last_read", time = read)}</p>
        </section>
    }
}

/// A row of the "built with" card: the projects, linked, then what they do for nanobom.
#[component]
fn Credit(names: Vec<(&'static str, &'static str)>, role: String) -> impl IntoView {
    let count = names.len();
    view! {
        <div class="grid gap-x-4 sm:grid-cols-[16rem_minmax(0,1fr)]">
            <dt>
                {names
                    .into_iter()
                    .enumerate()
                    .map(|(index, (name, href))| {
                        view! {
                            {(index > 0).then_some(if index + 1 == count { " & " } else { ", " })}
                            {external(href.to_owned(), name.to_owned())}
                        }
                    })
                    .collect_view()}
            </dt>
            <dd class="text-muted-foreground">{role}</dd>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use leptos::tachys::view::RenderHtml;

    use super::*;

    fn render(locale: &str) -> String {
        let owner = Owner::new();
        owner.with(|| {
            provide_context(crate::i18n::find(locale).expect("an embedded locale"));
            let now = chrono::DateTime::parse_from_rfc3339("2026-11-07T18:04:00Z").unwrap();
            view! {
                <AboutBody data=AboutData {
                    osv_read_at: Some(now),
                    kev_checked_at: None,
                    epss_checked_at: Some(now),
                } />
            }
            .to_html()
        })
    }

    #[test]
    fn the_author_is_named_without_an_email_address() {
        assert_eq!(author(), "Alix ANNERAUD");
    }

    #[test]
    fn the_page_names_the_release_the_author_the_links_and_the_sources() {
        let html = render("en");
        for expected in [
            VERSION,
            ">Alix ANNERAUD</a>",
            "href=\"https://alix.anneraud.fr\"",
            "href=\"https://alixanneraud.github.io/nanobom/\"",
            "href=\"https://github.com/AlixANNERAUD/nanobom\"",
            "href=\"https://github.com/AlixANNERAUD/nanobom/releases\"",
            "href=\"https://github.com/AlixANNERAUD/nanobom/issues\"",
            "href=\"https://github.com/AlixANNERAUD/nanobom/blob/main/LICENSE\"",
            "Apache-2.0",
            "href=\"https://osv.dev\"",
            "href=\"https://google.github.io/osv.dev/data/\"",
            "href=\"https://www.cisa.gov/known-exploited-vulnerabilities-catalog\"",
            "href=\"https://www.first.org/epss/\"",
            "EPSS scores by FIRST.org",
            "Last read: 2026-11-07 18:04 UTC",
            "Last read: Never",
            "href=\"https://leptos.dev\"",
            "href=\"https://github.com/shadcn-ui/ui\"",
            "href=\"https://github.com/rust-ui/ui\"",
        ] {
            assert!(html.contains(expected), "{expected} missing from {html}");
        }
        assert!(!html.contains('@'), "an email address in {html}");
        // Every link leaves for another site.
        assert_eq!(
            html.matches("<a ").count(),
            html.matches("rel=\"noreferrer\"").count(),
            "{html}"
        );
    }

    #[test]
    fn the_page_follows_the_language() {
        let html = render("fr");
        for expected in [
            "Sources de données",
            "Dernière lecture : 2026-11-07 18:04 UTC",
            "Scores EPSS par FIRST.org",
            "Alix ANNERAUD",
        ] {
            assert!(html.contains(expected), "{expected} missing from {html}");
        }
        assert!(!html.contains("Data sources"), "{html}");
    }
}
