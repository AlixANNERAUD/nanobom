//! Interface primitives in the style of shadcn/ui: buttons, inputs, cards, tables, badges and
//! alerts. Their classes come from Rust/UI's Leptos components and shadcn/ui (MIT, see
//! `LICENSE-rust-ui`), kept as plain class strings so they render without client code.

use leptos::prelude::*;

use crate::{
    model::{Severity, SeverityCounts},
    t, tp,
};

const BUTTON_BASE: &str = "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-all disabled:pointer-events-none disabled:opacity-50 shrink-0 outline-none focus-visible:border-ring focus-visible:ring-ring/70 focus-visible:ring-[3px] hover:cursor-pointer";

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
            "bg-destructive text-destructive-foreground shadow-xs hover:bg-destructive/90 focus-visible:ring-destructive/20"
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

/// The nanobom mark, a small box in a box. It is decorative: the wordmark next to it carries the
/// name. `class` replaces the default size, since two size classes on one element would be
/// settled by their order in the stylesheet.
#[component]
pub fn Mark(#[prop(optional, into)] class: String) -> impl IntoView {
    let size = if class.is_empty() {
        "size-[18px]"
    } else {
        class.as_str()
    };
    view! {
        <svg viewBox="0 0 18 18" aria-hidden="true" class=format!("shrink-0 {size}")>
            <rect width="18" height="18" rx="5" class="fill-primary" />
            <rect x="8" y="8" width="6" height="6" rx="1.5" class="fill-primary-foreground" />
        </svg>
    }
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

pub const INPUT: &str = "text-foreground placeholder:text-muted-foreground selection:bg-primary selection:text-primary-foreground border-input flex h-9 w-full min-w-0 rounded-md border bg-transparent px-3 py-1 text-base shadow-xs transition-[color,box-shadow] outline-none disabled:cursor-not-allowed disabled:opacity-50 md:text-sm focus-visible:border-ring focus-visible:ring-ring/70 focus-visible:ring-[3px] aria-invalid:border-destructive";

pub const SELECT: &str = "text-foreground border-input flex h-9 w-full min-w-0 rounded-md border bg-background px-3 py-1 text-base shadow-xs outline-none md:text-sm focus-visible:border-ring focus-visible:ring-ring/70 focus-visible:ring-[3px]";

pub const TEXTAREA: &str = "text-foreground placeholder:text-muted-foreground border-input flex min-h-20 w-full rounded-md border bg-transparent px-3 py-2 text-base shadow-xs outline-none md:text-sm focus-visible:border-ring focus-visible:ring-ring/70 focus-visible:ring-[3px]";

/// A select of a row of filters: as high as a small button and as wide as its options, where
/// [`SELECT`] fills its column.
pub const SELECT_COMPACT: &str = "text-foreground border-input h-8 min-w-0 rounded-md border bg-background px-2 text-base shadow-xs outline-none md:text-sm focus-visible:border-ring focus-visible:ring-ring/70 focus-visible:ring-[3px]";

/// The label above a control of a row of filters.
pub const FILTER_LABEL: &str = "text-muted-foreground text-xs select-none";

/// Identifiers read character by character: vulnerability ids, versions, package URLs, CVSS
/// vectors, token prefixes and scores. Slightly smaller than the text around it, since the
/// monospace face runs wider.
pub const MONO: &str = "font-mono text-[0.8125rem]";

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

/// A table with a caption for screen readers, scrolling sideways inside its frame when it is
/// wider than the page. `class` adds to the table itself, such as a fixed layout.
#[component]
pub fn Table(
    #[prop(into)] caption: String,
    #[prop(optional, into)] class: String,
    children: Children,
) -> impl IntoView {
    view! {
        <div class="w-full overflow-x-auto rounded-md border">
            <table class=format!("w-full text-sm caption-bottom {class}")>
                <caption class="sr-only">{caption}</caption>
                {children()}
            </table>
        </div>
    }
}

pub const TABLE_HEAD_ROW: &str = "border-b bg-muted/50";
pub const TABLE_HEAD: &str =
    "h-9 px-3 text-left align-middle font-medium text-muted-foreground whitespace-nowrap";
pub const TABLE_ROW: &str = "border-b last:border-0 transition-colors hover:bg-muted/50";
pub const TABLE_CELL: &str = "px-3 py-2 align-middle";

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
        BadgeVariant::Destructive => {
            "border-transparent bg-destructive text-destructive-foreground"
        }
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

/// The color of a severity in a [`SeverityBar`] and its legend. Unknown is a neutral grey: it
/// says nothing about how bad a finding is, so it must not read as the least severe.
fn severity_fill(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "bg-severity-critical",
        Severity::High => "bg-severity-high",
        Severity::Medium => "bg-severity-medium",
        Severity::Low => "bg-severity-low",
        Severity::Unknown => "bg-muted-foreground/40",
    }
}

/// The segments of a [`SeverityBar`]: the severities that have findings, most severe first.
fn segments(counts: SeverityCounts) -> Vec<(Severity, u64)> {
    Severity::DESCENDING
        .into_iter()
        .map(|severity| (severity, counts.get(severity)))
        .filter(|(_, count)| *count > 0)
        .collect()
}

/// Open findings by severity as a stacked bar. It is decorative: the numbers next to it, such
/// as a [`SeverityLegend`], say the same to everyone.
///
/// Each severity that has findings gets a segment growing with its count (`flex-grow`), so no
/// share is ever computed and an empty total divides nothing: it leaves the track empty.
/// Segments keep a minimum width, so one finding among hundreds stays visible.
#[component]
pub fn SeverityBar(counts: SeverityCounts, #[prop(optional, into)] class: String) -> impl IntoView {
    let segments = segments(counts);
    let segments = if segments.is_empty() {
        view! { <div class="bg-muted-foreground/20 flex-1"></div> }.into_any()
    } else {
        segments
            .into_iter()
            .map(|(severity, count)| {
                view! {
                    <div
                        class=format!("min-w-1.5 {}", severity_fill(severity))
                        style=format!("flex-grow:{count}")
                    ></div>
                }
            })
            .collect_view()
            .into_any()
    };
    view! {
        <div aria-hidden="true" class=format!("flex h-2 gap-0.5 overflow-hidden rounded-full {class}")>
            {segments}
        </div>
    }
}

/// The numbers behind a [`SeverityBar`]: the count of every severity, those without findings
/// included so the list always reads the same, then how many open findings are known exploited
/// when `known_exploited` is given.
#[component]
pub fn SeverityLegend(
    counts: SeverityCounts,
    #[prop(optional)] known_exploited: Option<i64>,
) -> impl IntoView {
    let severities = Severity::DESCENDING
        .into_iter()
        .map(|severity| {
            view! {
                <li class="flex items-center gap-1.5">
                    <span aria-hidden="true" class=format!("size-2.5 rounded-xs {}", severity_fill(severity))></span>
                    <span class="font-medium tabular-nums">{counts.get(severity)}</span>
                    <span class="text-muted-foreground">{severity.label()}</span>
                </li>
            }
        })
        .collect_view();
    let known_exploited = known_exploited.map(|count| {
        let class = if count > 0 {
            "text-destructive font-medium"
        } else {
            "text-muted-foreground"
        };
        view! { <li class=class>{tp!("severity.known_exploited", count)}</li> }
    });
    view! {
        <ul aria-label=t!("severity.legend") class="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
            {severities}
            {known_exploited}
        </ul>
    }
}

pub const SEPARATOR: &str = "shrink-0 bg-border h-px w-full";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bar_draws_the_severities_that_have_findings_most_severe_first() {
        let counts = SeverityCounts {
            critical: 0,
            high: 12,
            medium: 0,
            low: 1,
            unknown: 3,
        };
        assert_eq!(
            segments(counts),
            [
                (Severity::High, 12),
                (Severity::Low, 1),
                (Severity::Unknown, 3)
            ]
        );
    }

    #[test]
    fn the_bar_has_no_segment_without_findings() {
        assert!(segments(SeverityCounts::default()).is_empty());
    }

    #[test]
    fn findings_of_unknown_severity_alone_still_draw_a_segment() {
        let counts = SeverityCounts {
            unknown: 4,
            ..SeverityCounts::default()
        };
        assert_eq!(segments(counts), [(Severity::Unknown, 4)]);
        // Neutral, not one of the severity colors.
        assert!(!severity_fill(Severity::Unknown).contains("severity"));
    }
}
