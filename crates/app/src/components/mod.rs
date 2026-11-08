//! Building blocks of the pages.

pub mod ui;

use chrono::{DateTime, FixedOffset, Utc};
use leptos::{prelude::*, server_fn::ServerFn};
use leptos_meta::Title;
use leptos_router::hooks::use_query_map;
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    functions::load_current_user,
    model::{CurrentUser, Severity, Status},
};
use ui::*;

/// The address a form posts to for a server function.
pub fn action<F: ServerFn>() -> &'static str {
    F::PATH
}

/// A date and time in UTC, as `2026-11-07 18:04 UTC`.
pub fn format_time(time: DateTime<FixedOffset>) -> String {
    time.with_timezone(&Utc)
        .format("%Y-%m-%d %H:%M UTC")
        .to_string()
}

/// A date in UTC, as `2026-11-07`.
pub fn format_date(time: DateTime<FixedOffset>) -> String {
    time.with_timezone(&Utc).format("%Y-%m-%d").to_string()
}

#[component]
pub fn SeverityBadge(severity: Severity) -> impl IntoView {
    let colors = match severity {
        Severity::Critical => "bg-severity-critical text-white",
        Severity::High => "bg-severity-high text-white",
        Severity::Medium => "bg-severity-medium text-white",
        Severity::Low => "bg-severity-low text-white",
        Severity::Unknown => "bg-muted text-muted-foreground",
    };
    view! {
        <span class=format!(
            "inline-flex w-fit items-center rounded-md px-2 py-0.5 text-xs font-semibold whitespace-nowrap {colors}",
        )>{severity.label()}</span>
    }
}

#[component]
pub fn StatusBadge(status: Status) -> impl IntoView {
    let variant = match status {
        Status::Open => BadgeVariant::Outline,
        Status::Ignored => BadgeVariant::Muted,
        Status::Fixed => BadgeVariant::Secondary,
    };
    view! { <Badge variant>{status.label()}</Badge> }
}

/// The `notice` or `error` message an action redirected with.
#[component]
pub fn Flash() -> impl IntoView {
    let query = use_query_map();
    move || {
        let query = query.read();
        if let Some(error) = query.get("error") {
            Some(
                view! {
                    <Alert variant=AlertVariant::Destructive>{error}</Alert>
                }
                .into_any(),
            )
        } else {
            query.get("notice").map(|notice| {
                view! { <Alert variant=AlertVariant::Success>{notice}</Alert> }.into_any()
            })
        }
    }
}

/// Renders a server function's result once loaded, or its error.
#[component]
pub fn Loaded<T, V, F>(resource: Resource<Result<T, ServerFnError>>, render: F) -> impl IntoView
where
    T: Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
    F: Fn(T) -> V + Clone + Send + Sync + 'static,
    V: IntoView + 'static,
{
    view! {
        <Suspense fallback=|| view! { <p class="text-muted-foreground">"Loading…"</p> }>
            {move || {
                let render = render.clone();
                Suspend::new(async move {
                    match resource.await {
                        Ok(value) => render(value).into_any(),
                        Err(error) => view! { <ErrorMessage error /> }.into_any(),
                    }
                })
            }}
        </Suspense>
    }
}

#[component]
pub fn ErrorMessage(error: ServerFnError) -> impl IntoView {
    let message = match &error {
        ServerFnError::ServerError(message) => message.clone(),
        other => other.to_string(),
    };
    // A redirection to the sign-in page is on its way.
    (message != "sign in required").then(|| {
        view! {
            <Alert variant=AlertVariant::Destructive title="Unable to show this page">
                {message}
            </Alert>
        }
    })
}

#[component]
pub fn Empty(#[prop(into)] title: String, children: Children) -> impl IntoView {
    view! {
        <div class="rounded-lg border border-dashed p-8 text-center">
            <p class="font-medium">{title}</p>
            <div class="text-muted-foreground mt-1 text-sm">{children()}</div>
        </div>
    }
}

/// Switches between the light and dark themes, remembering the choice in the browser. Without
/// JavaScript, the theme follows the system preference.
#[island]
pub fn ThemeToggle() -> impl IntoView {
    let toggle = move |_| {
        #[cfg(feature = "hydrate")]
        {
            let Some(root) = document().document_element() else {
                return;
            };
            let classes = root.class_list();
            let system_dark = window()
                .match_media("(prefers-color-scheme: dark)")
                .ok()
                .flatten()
                .is_some_and(|query| query.matches());
            let dark = classes.contains("dark") || (!classes.contains("light") && system_dark);
            let next = if dark { "light" } else { "dark" };
            let _ = classes.remove_2("light", "dark");
            let _ = classes.add_1(next);
            if let Ok(Some(storage)) = window().local_storage() {
                let _ = storage.set_item("theme", next);
            }
        }
    };
    view! {
        <button
            type="button"
            on:click=toggle
            class=button_class(ButtonVariant::Ghost, ButtonSize::Small)
            aria-label="Switch between the light and dark themes"
            title="Switch theme"
        >
            <span aria-hidden="true">"◐"</span>
        </button>
    }
}

/// The header: home link, organization switcher, search, administration and the account.
#[component]
fn Header(user: CurrentUser) -> impl IntoView {
    let organizations = user.organizations.clone();
    view! {
        <header class="border-b bg-background">
            <div class="mx-auto flex max-w-6xl flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
                <a href="/organizations" class="font-semibold tracking-tight">
                    "nanobom"
                </a>
                <details class="relative">
                    <summary class=format!(
                        "{} list-none",
                        button_class(ButtonVariant::Outline, ButtonSize::Small),
                    )>"Organizations ▾"</summary>
                    <ul class="bg-popover text-popover-foreground absolute z-20 mt-1 min-w-56 rounded-md border p-1 shadow-md">
                        {organizations
                            .into_iter()
                            .map(|organization| {
                                view! {
                                    <li>
                                        <a
                                            href=format!("/organizations/{}", organization.slug)
                                            class="hover:bg-accent block rounded-sm px-2 py-1.5 text-sm"
                                        >
                                            {organization.name}
                                            <span class="text-muted-foreground ml-2 text-xs">
                                                {organization.role.label()}
                                            </span>
                                        </a>
                                    </li>
                                }
                            })
                            .collect_view()}
                        <li class="mt-1 border-t pt-1">
                            <a
                                href="/organizations"
                                class="hover:bg-accent block rounded-sm px-2 py-1.5 text-sm"
                            >
                                "All organizations"
                            </a>
                        </li>
                    </ul>
                </details>
                <form action="/search" method="get" role="search" class="flex min-w-48 flex-1 gap-2">
                    <label for="header-search" class="sr-only">
                        "Search components"
                    </label>
                    <input
                        id="header-search"
                        name="query"
                        type="search"
                        placeholder="Search components, e.g. openssl 3."
                        class=INPUT
                    />
                </form>
                <nav aria-label="Account" class="flex items-center gap-2">
                    {user
                        .is_instance_administrator
                        .then(|| {
                            view! {
                                <LinkButton
                                    href="/administration"
                                    variant=ButtonVariant::Ghost
                                    size=ButtonSize::Small
                                >
                                    "Administration"
                                </LinkButton>
                            }
                        })}
                    <span class="text-muted-foreground text-sm" title=user.username.clone()>
                        {user.display_name}
                    </span>
                    <ThemeToggle />
                    <form method="post" action="/auth/logout">
                        <Button variant=ButtonVariant::Outline size=ButtonSize::Small>
                            "Sign out"
                        </Button>
                    </form>
                </nav>
            </div>
        </header>
    }
}

/// A page of the signed-in interface: header, title, flash message and content.
#[component]
pub fn Page(#[prop(into)] title: String, children: ChildrenFn) -> impl IntoView {
    let user = Resource::new(|| (), |()| load_current_user());
    view! {
        <Title text=format!("{title} · nanobom") />
        <a
            href="#content"
            class="focus:bg-background sr-only focus:not-sr-only focus:absolute focus:p-2"
        >
            "Skip to content"
        </a>
        <Loaded
            resource=user
            render={move |user: Option<CurrentUser>| {
                let children = children.clone();
                match user {
                    Some(user) => {
                        view! {
                            <Header user />
                            <main id="content" class="mx-auto grid max-w-6xl gap-6 px-4 py-6">
                                <Flash />
                                {children()}
                            </main>
                        }
                            .into_any()
                    }
                    None => {
                        view! {
                            <main id="content" class="mx-auto max-w-md px-4 py-16">
                                <Alert title="Signed out">
                                    <a class="underline" href="/login">
                                        "Sign in"
                                    </a>
                                    " to continue."
                                </Alert>
                            </main>
                        }
                            .into_any()
                    }
                }
            }}
        />
    }
}

/// A page heading with optional actions on the right.
#[component]
pub fn Heading(
    #[prop(into)] title: String,
    #[prop(optional, into)] subtitle: Option<String>,
    #[prop(optional)] children: Option<Children>,
) -> impl IntoView {
    view! {
        <div class="flex flex-wrap items-end justify-between gap-4">
            <div class="grid gap-1">
                <h1 class="text-2xl font-semibold tracking-tight">{title}</h1>
                {subtitle.map(|subtitle| view! { <p class="text-muted-foreground">{subtitle}</p> })}
            </div>
            <div class="flex flex-wrap items-center gap-2">{children.map(|children| children())}</div>
        </div>
    }
}
