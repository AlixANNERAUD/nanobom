//! Web interface of nanobom, rendered on the server with interactive islands.

use leptos::prelude::*;
use leptos_meta::{MetaTags, Title, provide_meta_context};
use leptos_router::{
    StaticSegment,
    components::{Route, Router, Routes},
};

/// The HTML document around every page.
pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <AutoReload options=options.clone() />
                <HydrationScripts options islands=true />
                <link rel="stylesheet" id="leptos" href="/pkg/nanobom.css" />
                <MetaTags />
            </head>
            <body class="min-h-screen bg-white text-slate-900 dark:bg-slate-950 dark:text-slate-100">
                <App />
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    view! {
        <Title text="nanobom" />
        <Router>
            <main class="mx-auto max-w-6xl p-4">
                <Routes fallback=|| view! { <p>"Page not found."</p> }>
                    <Route path=StaticSegment("") view=HomePage />
                </Routes>
            </main>
        </Router>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    view! { <h1 class="text-2xl font-semibold">"nanobom"</h1> }
}
