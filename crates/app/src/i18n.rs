//! The language of the interface. Every message is compiled in for each embedded locale (the
//! `available_locales` of the crate's `i18n!`); each request picks one: the language the user
//! chose with the language switch (a cookie), else the browser's preferences
//! (`Accept-Language`), else English.
//!
//! [`t!`](crate::t) translates a message into the request's language, [`tf!`](crate::tf)
//! formats one with arguments into a `String`, and [`tp!`](crate::tp) picks the plural form for
//! a count. Keys live in `crates/app/locales/*.json`; a key missing from any locale fails the
//! build.
//!
//! ```ignore
//! let label = t!("settings.save");
//! let notice = tf!("notices.user_created", username = user.username);
//! let components = tp!("project.components", upload.component_count);
//! ```

use embedded_i18n::Locale;
use leptos::prelude::*;

/// Name of the cookie remembering the chosen language.
pub const COOKIE: &str = "nanobom_locale";

/// The locales offered by the language switch: locale, tag and name in its own language.
pub fn languages() -> impl Iterator<Item = (Locale, &'static str, &'static str)> {
    embedded_i18n::available_locales!().iter().map(|&tag| {
        let locale = Locale::new(tag);
        (
            locale,
            tag,
            embedded_i18n::t!("language.name", locale = locale),
        )
    })
}

/// The request's locale, decided once by [`provide_locale`] for pages and on demand elsewhere
/// (server functions, islands in the browser). It is always one of the embedded locales.
pub fn locale() -> Locale {
    use_context::<Locale>().unwrap_or_else(detect)
}

/// Decides the request's locale and makes it available to every component below.
pub fn provide_locale() -> Locale {
    let locale = detect();
    provide_context(locale);
    locale
}

/// The language tag of an embedded locale, for `<html lang>` and the cookie.
pub fn tag(locale: Locale) -> &'static str {
    embedded_i18n::available_locales!()
        .iter()
        .copied()
        .find(|&tag| Locale::new(tag) == locale)
        .unwrap_or_else(default_tag)
}

/// The `default_locale` of the crate: the global locale of embedded-i18n is never set, so
/// `locale!()` always names it.
fn default_tag() -> &'static str {
    embedded_i18n::locale!()
}

fn default_locale() -> Locale {
    Locale::new(default_tag())
}

/// The embedded locale serving a requested language tag: the same tag, else the first one of the
/// same language (`fr` for `fr-CA`).
pub fn find(requested: &str) -> Option<Locale> {
    let requested = requested.trim();
    let wanted = Locale::new(requested);
    let language = primary_language(requested);
    let locales = embedded_i18n::available_locales!();
    locales
        .iter()
        .copied()
        .find(|&tag| Locale::new(tag) == wanted)
        .or_else(|| {
            locales
                .iter()
                .copied()
                .find(|&tag| primary_language(tag).eq_ignore_ascii_case(language))
        })
        .map(Locale::new)
}

fn primary_language(tag: &str) -> &str {
    tag.split(['-', '_']).next().unwrap_or_default()
}

#[cfg(feature = "ssr")]
fn detect() -> Locale {
    use axum::http::{header, request::Parts};
    let Some(parts) = use_context::<Parts>() else {
        return default_locale();
    };
    let chosen = parts
        .headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE)
        .and_then(|(_, value)| find(value));
    chosen
        .or_else(|| {
            parts
                .headers
                .get(header::ACCEPT_LANGUAGE)
                .and_then(|value| value.to_str().ok())
                .and_then(negotiate)
        })
        .unwrap_or_else(default_locale)
}

/// In the browser, islands follow the language the server rendered the page in.
#[cfg(not(feature = "ssr"))]
fn detect() -> Locale {
    document()
        .document_element()
        .and_then(|root| root.get_attribute("lang"))
        .and_then(|tag| find(&tag))
        .unwrap_or_else(default_locale)
}

/// The embedded locale best matching an `Accept-Language` header: languages are tried by
/// decreasing quality, in header order for equal qualities; `q=0` and `*` are skipped.
pub fn negotiate(accept_language: &str) -> Option<Locale> {
    let mut ranges: Vec<(&str, u16)> = accept_language
        .split(',')
        .filter_map(|range| {
            let mut parts = range.split(';');
            let tag = parts.next()?.trim();
            let quality = parts
                .filter_map(|parameter| parameter.trim().strip_prefix("q="))
                .find_map(|value| value.trim().parse::<f32>().ok())
                .unwrap_or(1.0);
            // Thousandths, so qualities sort without floating-point comparisons.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let quality = (quality.clamp(0.0, 1.0) * 1000.0).round() as u16;
            (!tag.is_empty() && tag != "*" && quality > 0).then_some((tag, quality))
        })
        .collect();
    ranges.sort_by_key(|range| std::cmp::Reverse(range.1));
    ranges.into_iter().find_map(|(tag, _)| find(tag))
}

/// Translates a message into the request's language: `t!("key")`.
#[macro_export]
macro_rules! t {
    ($($arguments:tt)*) => {
        ::embedded_i18n::t!(locale = $crate::i18n::locale(), $($arguments)*)
    };
}

/// Formats a message with arguments into a `String`, in the request's language:
/// `tf!("key", name = value)`.
#[macro_export]
macro_rules! tf {
    ($($arguments:tt)*) => {
        ::std::format!(
            "{}",
            ::embedded_i18n::t!(locale = $crate::i18n::locale(), $($arguments)*)
        )
    };
}

/// Formats the plural form of a message matching a count into a `String`, in the request's
/// language: `tp!("key", count)`. Forms use `{count}`.
#[macro_export]
macro_rules! tp {
    ($key:literal, $count:expr) => {
        ::std::format!(
            "{}",
            ::embedded_i18n::t!($key, count = $count, locale = $crate::i18n::locale())
        )
    };
}

#[cfg(test)]
mod tests {
    use embedded_i18n::Locale;

    use super::{find, negotiate};

    #[test]
    fn negotiates_the_preferred_embedded_language() {
        let french = Some(Locale::new("fr"));
        let english = Some(Locale::new("en"));
        assert_eq!(negotiate("fr-CA,fr;q=0.9,en;q=0.8"), french);
        assert_eq!(negotiate("de-DE, en;q=0.5, fr;q=0.7"), french);
        assert_eq!(negotiate("en-GB"), english);
        assert_eq!(negotiate("fr;q=0, en;q=0.1"), english);
        assert_eq!(negotiate("de, *"), None);
        assert_eq!(negotiate(""), None);
    }

    #[test]
    fn finds_the_embedded_locale_of_a_tag() {
        assert_eq!(find("fr"), Some(Locale::new("fr")));
        assert_eq!(find("FR_ca"), Some(Locale::new("fr")));
        assert_eq!(find(" en-GB "), Some(Locale::new("en")));
        assert_eq!(find("de"), None);
        assert_eq!(find(""), None);
        assert_eq!(find("-fr"), None);
    }
}
