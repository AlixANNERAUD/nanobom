//! Web interface of nanobom, rendered on the server. Pages are complete HTML and every action is
//! a plain form posting to a server function, so the interface works without JavaScript;
//! islands add small enhancements such as the theme switch.

pub mod components;
pub mod functions;
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

/// The HTML document around every page.
pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
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

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
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
        <Page title="Not found">
            <Alert title="Page not found">
                <a class="underline" href="/organizations">"Back to your organizations"</a>
            </Alert>
        </Page>
    }
}
