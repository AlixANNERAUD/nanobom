//! Building blocks of the pages.

pub mod ui;

use chrono::{DateTime, FixedOffset, Utc};
use leptos::{prelude::*, server_fn::ServerFn};
use leptos_meta::Title;
use leptos_router::hooks::use_query_map;
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    functions::{SetLanguage, load_current_user},
    i18n,
    model::{CurrentUser, Organization, Severity, Status},
    t,
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
        <Suspense fallback=|| view! { <p class="text-muted-foreground">{t!("common.loading")}</p> }>
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
    (message != crate::model::SIGN_IN_REQUIRED).then(|| {
        view! {
            <Alert variant=AlertVariant::Destructive title=t!("common.page_error")>
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

/// A row of a header menu: a link or a button as wide as the menu. Its focus ring is drawn
/// inside the row, where the menu's border cannot hide it.
const MENU_ITEM: &str = "hover:bg-accent hover:text-accent-foreground flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-sm hover:cursor-pointer focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring/70";

/// The panel of a header menu, opening under its `<details>` button and above the page. Each menu
/// adds its own position and width.
const MENU_PANEL: &str =
    "bg-popover text-popover-foreground absolute z-20 mt-1 rounded-md border p-1 shadow-md";

/// A language of the account menu. The focus ring keeps a gap from the button: on the current
/// language, both are the accent color and would merge.
const LANGUAGE_BUTTON: &str = "h-8 flex-1 rounded-md px-3 text-sm font-medium hover:cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring/70";

/// The `name` shared by the header's menus: browsers that support it close one when the other
/// opens, the others let both stay open.
const HEADER_MENUS: &str = "header-menu";

/// Switches between the light and dark themes, remembering the choice in the browser. Without
/// JavaScript, the theme follows the system preference. Shown as a row of the account menu.
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
        <button type="button" on:click=toggle class=MENU_ITEM title=t!("theme.label")>
            <span aria-hidden="true">"◐"</span>
            {t!("theme.title")}
        </button>
    }
}

/// Chooses the interface's language, remembered in a cookie: one submit button per language in
/// a plain form, so it works without JavaScript.
#[component]
pub fn LanguageSwitch() -> impl IntoView {
    let current = i18n::locale();
    let target = action::<SetLanguage>();
    view! {
        <form method="post" action=target class="grid gap-1.5 px-2 py-1.5">
            <span id="language-label" class="text-muted-foreground text-xs">
                {t!("language.label")}
            </span>
            <div role="group" aria-labelledby="language-label" class="flex gap-1">
                {i18n::languages()
                    .map(|(locale, tag, name)| {
                        let selected = locale == current;
                        let state = if selected {
                            "bg-primary text-primary-foreground"
                        } else {
                            "border-input hover:bg-accent hover:text-accent-foreground border"
                        };
                        view! {
                            <button
                                type="submit"
                                name="locale"
                                value=tag
                                lang=tag
                                aria-current=selected.then_some("true")
                                class=format!("{LANGUAGE_BUTTON} {state}")
                            >
                                {name}
                            </button>
                        }
                    })
                    .collect_view()}
            </div>
        </form>
    }
}

/// The character shown in the account button: the first visible character of the display name,
/// else of the username, in upper case; `?` when neither has one. Only the first character of
/// the upper case form is kept (`S` for `ß`), so the button never holds more than one.
fn initial(display_name: &str, username: &str) -> String {
    [display_name, username]
        .into_iter()
        .find_map(|name| name.chars().find(|&character| is_visible(character)))
        .and_then(|character| character.to_uppercase().next())
        .map_or_else(|| "?".to_owned(), String::from)
}

/// Whether a character draws something. Besides spaces and control characters, this leaves out
/// the format characters that names pick up when pasted (soft hyphen, zero-width spaces and
/// joiners, direction marks, byte order mark): `char` has no test for them.
fn is_visible(character: char) -> bool {
    !(character.is_whitespace()
        || character.is_control()
        || matches!(
            character,
            '\u{ad}'
                | '\u{34f}'
                | '\u{61c}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
        ))
}

/// The organization switcher of the header: the user's organizations, then the list of all.
#[component]
fn OrganizationSwitcher(organizations: Vec<Organization>) -> impl IntoView {
    view! {
        <details name=HEADER_MENUS class="md:relative">
            <summary class=format!(
                "{} list-none",
                button_class(ButtonVariant::Outline, ButtonSize::Small),
            )>{t!("header.organizations")}" ▾"</summary>
            // Below `md` the details is not positioned, so the list is placed against the header
            // and spans the page: next to the wordmark, a list starting at its button would run
            // off a phone's screen.
            <ul class=format!("{MENU_PANEL} inset-x-4 max-h-[70vh] overflow-y-auto md:inset-x-auto md:min-w-56")>
                {organizations
                    .into_iter()
                    .map(|organization| {
                        view! {
                            <li>
                                <a
                                    href=format!("/organizations/{}", organization.slug)
                                    class=format!("{MENU_ITEM} break-words")
                                >
                                    <span class="min-w-0">{organization.name}</span>
                                    <span class="text-muted-foreground text-xs">
                                        {organization.role.label()}
                                    </span>
                                </a>
                            </li>
                        }
                    })
                    .collect_view()}
                <li class="mt-1 border-t pt-1">
                    <a href="/organizations" class=MENU_ITEM>
                        {t!("header.all_organizations")}
                    </a>
                </li>
            </ul>
        </details>
    }
}

/// The account menu of the header, opened from a round button showing the user's initial: who
/// is signed in, the administration for instance administrators, the language, the theme and
/// signing out.
#[component]
fn UserMenu(user: CurrentUser) -> impl IntoView {
    let initial = initial(&user.display_name, &user.username);
    let name = if !user.display_name.chars().any(is_visible) {
        user.username.clone()
    } else {
        user.display_name
    };
    // Accounts created without a display name are named after their username: once is enough.
    let username = (name != user.username).then_some(user.username);
    view! {
        // On phones the button sits at the end of the first line, the search below it.
        <details name=HEADER_MENUS class="relative ml-auto md:ml-0">
            <summary
                class="bg-primary text-primary-foreground flex size-8 list-none items-center justify-center rounded-full text-sm font-semibold select-none hover:cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring/70"
                aria-label=t!("header.account")
                title=t!("header.account")
            >
                <span aria-hidden="true">{initial}</span>
            </summary>
            // The button is pushed to the right end of its line at every width, so a panel
            // aligned on its right edge and no wider than the page stays on screen.
            <div class=format!("{MENU_PANEL} right-0 w-64 max-w-[calc(100vw-2rem)]")>
                <div class="px-2 py-1.5">
                    <p class="truncate text-sm font-medium" title=name.clone()>{name.clone()}</p>
                    {username
                        .map(|username| {
                            view! {
                                <p class="text-muted-foreground truncate text-xs" title=username.clone()>
                                    {username.clone()}
                                </p>
                            }
                        })}
                </div>
                <div class="mt-1 border-t pt-1">
                    {user
                        .is_instance_administrator
                        .then(|| {
                            view! {
                                <a href="/administration" class=MENU_ITEM>
                                    {t!("header.administration")}
                                </a>
                            }
                        })}
                    <LanguageSwitch />
                    <ThemeToggle />
                </div>
                <form method="post" action="/auth/logout" class="mt-1 border-t pt-1">
                    <button type="submit" class=MENU_ITEM>
                        {t!("header.sign_out")}
                    </button>
                </form>
            </div>
        </details>
    }
    // Erased: nested in the header and the page, the menu's full type is deeper than the
    // compiler accepts when it lays out the page's future.
    .into_any()
}

/// The header: home link, organization switcher, search and the account menu. One line from the
/// `md` breakpoint; below it, the search takes a second line.
#[component]
fn Header(user: CurrentUser) -> impl IntoView {
    let organizations = user.organizations.clone();
    view! {
        <header class="border-b bg-background">
            // `relative`: on phones the organization menu is placed against the header. The
            // narrower gap below `md` keeps the account button on the first line at 320 px.
            <div class="relative mx-auto flex max-w-6xl flex-wrap items-center gap-x-3 gap-y-2 px-4 py-3 md:flex-nowrap md:gap-x-4">
                <a
                    href="/organizations"
                    class="flex shrink-0 items-center gap-2 font-semibold tracking-tight"
                >
                    <Mark />
                    "nanobom"
                </a>
                <OrganizationSwitcher organizations />
                <form
                    action="/search"
                    method="get"
                    role="search"
                    class="order-last min-w-0 basis-full md:order-none md:flex-1"
                >
                    <label for="header-search" class="sr-only">
                        {t!("header.search_label")}
                    </label>
                    <input
                        id="header-search"
                        name="query"
                        type="search"
                        placeholder=t!("header.search_placeholder")
                        class=INPUT
                    />
                </form>
                <UserMenu user />
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
            {t!("common.skip_to_content")}
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
                                <Alert title=t!("signed_out.title")>
                                    <a class="underline" href="/login">
                                        {t!("signed_out.sign_in")}
                                    </a>
                                    {t!("signed_out.to_continue")}
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

#[cfg(test)]
mod tests {
    use super::initial;

    #[test]
    fn the_initial_is_the_first_letter_of_the_display_name() {
        assert_eq!(initial("Alice", "alice"), "A");
        assert_eq!(initial("alice", "x"), "A");
        assert_eq!(initial("éric", "x"), "É");
    }

    #[test]
    fn the_initial_falls_back_to_the_username() {
        assert_eq!(initial("", "bob"), "B");
        assert_eq!(initial("  ", "bob"), "B");
        assert_eq!(initial("", ""), "?");
        assert_eq!(initial(" ", "\t"), "?");
    }

    /// One character is shown even when the upper case form has several.
    #[test]
    fn the_initial_is_a_single_character() {
        assert_eq!(initial("ß", "x"), "S");
        assert_eq!(initial("ǆ", "x"), "Ǆ");
    }

    #[test]
    fn the_initial_keeps_characters_without_case() {
        assert_eq!(initial("李雷", "x"), "李");
        assert_eq!(initial("🦀 Ferris", "x"), "🦀");
        assert_eq!(initial("42", "x"), "4");
    }

    /// A name pasted with a byte order mark or a zero-width space would otherwise give an empty
    /// button.
    #[test]
    fn the_initial_skips_invisible_characters() {
        assert_eq!(initial("\u{feff}Alice", "x"), "A");
        assert_eq!(initial("\u{200b}\u{200d} zoé", "x"), "Z");
        assert_eq!(initial("\u{200b}", "bob"), "B");
        assert_eq!(initial("\u{0007}", "\u{00ad}"), "?");
    }
}
