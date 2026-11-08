//! Interface primitives in the style of shadcn/ui: buttons, inputs, cards, tables, badges and
//! alerts. Their classes come from Rust/UI's Leptos components and shadcn/ui (MIT, see
//! `LICENSE-rust-ui`), kept as plain class strings so they render without client code.

use leptos::prelude::*;

const BUTTON_BASE: &str = "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-all disabled:pointer-events-none disabled:opacity-50 shrink-0 outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] hover:cursor-pointer";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ButtonVariant {
    #[default]
    Default,
    Destructive,
    Outline,
    Secondary,
    Ghost,
    Link,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ButtonSize {
    #[default]
    Default,
    Small,
}

pub fn button_class(variant: ButtonVariant, size: ButtonSize) -> String {
    let variant = match variant {
        ButtonVariant::Default => {
            "bg-primary text-primary-foreground shadow-xs hover:bg-primary/90"
        }
        ButtonVariant::Destructive => {
            "bg-destructive text-white shadow-xs hover:bg-destructive/90 focus-visible:ring-destructive/20"
        }
        ButtonVariant::Outline => {
            "border border-input bg-background shadow-xs hover:bg-accent hover:text-accent-foreground"
        }
        ButtonVariant::Secondary => {
            "bg-secondary text-secondary-foreground shadow-xs hover:bg-secondary/80"
        }
        ButtonVariant::Ghost => "hover:bg-accent hover:text-accent-foreground",
        ButtonVariant::Link => "text-primary underline-offset-4 hover:underline",
    };
    let size = match size {
        ButtonSize::Default => "h-9 px-4 py-2",
        ButtonSize::Small => "h-8 gap-1.5 px-3",
    };
    format!("{BUTTON_BASE} {variant} {size}")
}

/// A submit button.
#[component]
pub fn Button(
    #[prop(optional)] variant: ButtonVariant,
    #[prop(optional)] size: ButtonSize,
    children: Children,
) -> impl IntoView {
    view! {
        <button type="submit" class=button_class(variant, size)>
            {children()}
        </button>
    }
}

/// A link that looks like a button.
#[component]
pub fn LinkButton(
    #[prop(into)] href: String,
    #[prop(optional)] variant: ButtonVariant,
    #[prop(optional)] size: ButtonSize,
    children: Children,
) -> impl IntoView {
    view! {
        <a href=href class=button_class(variant, size)>
            {children()}
        </a>
    }
}

pub const INPUT: &str = "text-foreground placeholder:text-muted-foreground selection:bg-primary selection:text-primary-foreground border-input flex h-9 w-full min-w-0 rounded-md border bg-transparent px-3 py-1 text-base shadow-xs transition-[color,box-shadow] outline-none disabled:cursor-not-allowed disabled:opacity-50 md:text-sm focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:border-destructive";

pub const SELECT: &str = "text-foreground border-input flex h-9 w-full min-w-0 rounded-md border bg-background px-3 py-1 text-base shadow-xs outline-none md:text-sm focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px]";

pub const TEXTAREA: &str = "text-foreground placeholder:text-muted-foreground border-input flex min-h-20 w-full rounded-md border bg-transparent px-3 py-2 text-base shadow-xs outline-none md:text-sm focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px]";

pub const LABEL: &str = "flex items-center gap-2 text-sm leading-none font-medium select-none";

pub const CHECKBOX: &str = "size-4 rounded border-input accent-primary";

/// A label above its field, with an optional hint below.
#[component]
pub fn Field(
    #[prop(into)] label: String,
    #[prop(into)] input_id: String,
    #[prop(optional, into)] hint: Option<String>,
    children: Children,
) -> impl IntoView {
    view! {
        <div class="grid gap-2">
            <label class=LABEL for=input_id>
                {label}
            </label>
            {children()}
            {hint.map(|hint| view! { <p class="text-muted-foreground text-sm">{hint}</p> })}
        </div>
    }
}

#[component]
pub fn Card(#[prop(optional, into)] class: String, children: Children) -> impl IntoView {
    view! {
        <section class=format!(
            "bg-card text-card-foreground flex flex-col gap-4 rounded-xl border py-6 shadow-sm {class}",
        )>{children()}</section>
    }
}

#[component]
pub fn CardHeader(children: Children) -> impl IntoView {
    view! { <div class="flex flex-col items-start gap-1.5 px-6">{children()}</div> }
}

#[component]
pub fn CardTitle(children: Children) -> impl IntoView {
    view! { <h2 class="leading-none font-semibold">{children()}</h2> }
}

#[component]
pub fn CardDescription(children: Children) -> impl IntoView {
    view! { <p class="text-muted-foreground text-sm">{children()}</p> }
}

#[component]
pub fn CardContent(children: Children) -> impl IntoView {
    view! { <div class="px-6">{children()}</div> }
}

/// A scrollable table with a caption for screen readers.
#[component]
pub fn Table(#[prop(into)] caption: String, children: Children) -> impl IntoView {
    view! {
        <div class="w-full overflow-x-auto rounded-md border">
            <table class="w-full text-sm caption-bottom">
                <caption class="sr-only">{caption}</caption>
                {children()}
            </table>
        </div>
    }
}

pub const TABLE_HEAD_ROW: &str = "border-b bg-muted/50";
pub const TABLE_HEAD: &str =
    "h-10 px-3 text-left align-middle font-medium text-muted-foreground whitespace-nowrap";
pub const TABLE_ROW: &str = "border-b last:border-0 transition-colors hover:bg-muted/50";
pub const TABLE_CELL: &str = "p-3 align-middle";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BadgeVariant {
    #[default]
    Secondary,
    Outline,
    Destructive,
    Muted,
}

#[component]
pub fn Badge(
    #[prop(optional)] variant: BadgeVariant,
    #[prop(optional, into)] title: Option<String>,
    children: Children,
) -> impl IntoView {
    let variant = match variant {
        BadgeVariant::Secondary => "border-transparent bg-secondary text-secondary-foreground",
        BadgeVariant::Outline => "text-foreground",
        BadgeVariant::Destructive => "border-transparent bg-destructive text-white",
        BadgeVariant::Muted => "border-transparent bg-muted text-muted-foreground",
    };
    view! {
        <span
            title=title
            class=format!(
                "inline-flex w-fit items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-semibold whitespace-nowrap {variant}",
            )
        >{children()}</span>
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AlertVariant {
    #[default]
    Default,
    Destructive,
    Success,
    Warning,
}

#[component]
pub fn Alert(
    #[prop(optional)] variant: AlertVariant,
    #[prop(optional, into)] title: Option<String>,
    children: Children,
) -> impl IntoView {
    let (variant, role) = match variant {
        AlertVariant::Default => ("bg-card text-card-foreground", "status"),
        AlertVariant::Destructive => ("border-destructive/50 bg-card text-destructive", "alert"),
        AlertVariant::Success => ("border-success/50 bg-card text-success", "status"),
        AlertVariant::Warning => ("border-warning/50 bg-card text-warning", "status"),
    };
    view! {
        <div role=role class=format!("relative w-full rounded-lg border px-4 py-3 text-sm {variant}")>
            {title.map(|title| view! { <p class="mb-1 font-medium leading-none">{title}</p> })}
            <div class="text-sm">{children()}</div>
        </div>
    }
}

pub const SEPARATOR: &str = "shrink-0 bg-border h-px w-full";
