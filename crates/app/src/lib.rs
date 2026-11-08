//! Web interface of nanobom, rendered on the server. Pages are complete HTML and every action is
//! a plain form posting to a server function, so the interface works without JavaScript;
//! islands add small enhancements such as the theme switch.
//!
//! # Features
//!
//! The crate is compiled twice. With `ssr`, for the server: pages render to HTML and server
//! functions run, calling `nanobom-domain`. With `hydrate`, for the browser bundle built by the
//! `frontend` crate: only islands run, and server functions become HTTP calls. The two features
//! are never enabled in the same build, so code that needs the database or the request lives
//! behind `#[cfg(feature = "ssr")]` (the [`server`](mod@server) module, the bodies of server
//! functions).
//!
//! # How a page works
//!
//! Each route renders with [`SsrMode::Async`]: the server waits for the page's data before
//! sending complete HTML. A page loads its data through a `load_*` server function of
//! [`functions`], which returns a [`model`] type. Forms post to the other
//! server functions, which act on behalf of the signed-in user and redirect back with a message
//! shown by [`components::Flash`]. Every string goes through [`t!`], [`tf!`] or [`tp!`]
//! ([`i18n`]), with keys in `locales/en.json` and `locales/fr.json`.
//!
//! The interface never decides what a user may do: it hides controls the user's role cannot
//! use, and the domain crate refuses the action anyway.
//!
//! # Where to start reading
//!
//! [`App`] lists the routes; [`functions`] holds everything that runs on the server;
//! [`server`](mod@server) has the helpers those functions share.

pub mod components;
pub mod functions;
pub mod i18n;
pub mod model;
pub mod pages;
#[cfg(feature = "ssr")]
pub mod server;

use leptos::prelude::*;
use leptos_meta::{MetaTags, provide_meta_context};
use leptos_router::{
    SsrMode,
    components::{Redirect, Route, Router, Routes},
    path,
};

use crate::{
    components::{Page, ui::Alert},
    pages::{
        findings::{FindingPage, ProjectPage, SearchPage},
        organizations::{OrganizationPage, OrganizationsPage, SignInPage},
        settings::{AdministrationPage, SettingsPage},
    },
};

/// Applies the theme stored by the theme switch before the page is painted.
const THEME_SCRIPT: &str = "try{var t=localStorage.getItem('theme');if(t==='dark'||t==='light'){document.documentElement.classList.add(t)}}catch(e){}";

/// The HTML document around every page. Its `lang` attribute is the request's language, which
/// islands read back in the browser.
pub fn shell(options: LeptosOptions) -> impl IntoView {
    let language = i18n::tag(i18n::locale());
    view! {
        <!DOCTYPE html>
        <html lang=language>
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <meta name="color-scheme" content="light dark" />
                <script inner_html=THEME_SCRIPT></script>
                <link rel="stylesheet" id="leptos" href="/pkg/nanobom.css" />
                <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
                <AutoReload options=options.clone() />
                <HydrationScripts options islands=true />
                <MetaTags />
            </head>
            <body class="bg-background text-foreground min-h-screen antialiased">
                <App />
            </body>
        </html>
    }
}

/// The router: every page of the interface. The server also uses it to list the routes it
/// serves.
#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    i18n::provide_locale();
    view! {
        <Router>
            <Routes fallback=NotFound>
                <Route path=path!("/") view=|| view! { <Redirect path="/organizations" /> } ssr=SsrMode::Async />
                <Route path=path!("/login") view=SignInPage ssr=SsrMode::Async />
                <Route path=path!("/organizations") view=OrganizationsPage ssr=SsrMode::Async />
                <Route path=path!("/organizations/:organization") view=OrganizationPage ssr=SsrMode::Async />
                <Route path=path!("/organizations/:organization/settings") view=SettingsPage ssr=SsrMode::Async />
                <Route
                    path=path!("/organizations/:organization/projects/:project")
                    view=ProjectPage
                    ssr=SsrMode::Async
                />
                <Route path=path!("/findings/:finding") view=FindingPage ssr=SsrMode::Async />
                <Route path=path!("/search") view=SearchPage ssr=SsrMode::Async />
                <Route path=path!("/administration") view=AdministrationPage ssr=SsrMode::Async />
            </Routes>
        </Router>
    }
}

#[component]
fn NotFound() -> impl IntoView {
    #[cfg(feature = "ssr")]
    if let Some(response) = use_context::<leptos_axum::ResponseOptions>() {
        response.set_status(axum::http::StatusCode::NOT_FOUND);
    }
    view! {
        <Page title=t!("not_found.title")>
            <Alert title=t!("not_found.heading")>
                <a class="underline" href="/organizations">{t!("not_found.back")}</a>
            </Alert>
        </Page>
    }
}
