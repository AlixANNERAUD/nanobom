//! The language of the interface. Every message is compiled in for each embedded locale
//! (`EMBEDDED_I18N_LOCALES`, see `.cargo/config.toml`); each request picks one: the language the
//! user chose with the language switch (a cookie), else the browser's preferences
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
//! let new_findings = tp!("organization.run_new", run.new_findings);
//! ```

use leptos::prelude::*;

embedded_i18n::track_locales!();

/// Name of the cookie remembering the chosen language.
pub const COOKIE: &str = "nanobom_locale";

/// The locale of the current request, as an index in [`embedded_i18n::LOCALES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Locale(pub usize);

/// The locales offered by the language switch: tag and name in its own language.
pub fn languages() -> impl Iterator<Item = (usize, &'static str, &'static str)> {
    embedded_i18n::LOCALES
        .iter()
        .enumerate()
        .map(|(index, &tag)| (index, tag, translate_name(index)))
}

fn translate_name(index: usize) -> &'static str {
    embedded_i18n::translate!(locale = index, "language.name")
}

/// The request's locale, decided once by [`provide_locale`] for pages and on demand elsewhere
/// (server functions, islands in the browser).
pub fn locale() -> usize {
    use_context::<Locale>().map_or_else(detect, |locale| locale.0)
}

/// Decides the request's locale and makes it available to every component below.
pub fn provide_locale() -> usize {
    let locale = detect();
    provide_context(Locale(locale));
    locale
}

/// The language tag of a locale, for `<html lang>`.
pub fn tag(locale: usize) -> &'static str {
    embedded_i18n::LOCALES
        .get(locale)
        .copied()
        .unwrap_or(embedded_i18n::LOCALES[embedded_i18n::DEFAULT_LOCALE_INDEX])
}

#[cfg(feature = "ssr")]
fn detect() -> usize {
    use axum::http::{header, request::Parts};
    let Some(parts) = use_context::<Parts>() else {
        return embedded_i18n::DEFAULT_LOCALE_INDEX;
    };
    let chosen = parts
        .headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE)
        .and_then(|(_, value)| embedded_i18n::match_locale(value));
    chosen
        .or_else(|| {
            parts
                .headers
                .get(header::ACCEPT_LANGUAGE)
                .and_then(|value| value.to_str().ok())
                .and_then(negotiate)
        })
        .unwrap_or(embedded_i18n::DEFAULT_LOCALE_INDEX)
}

/// In the browser, islands follow the language the server rendered the page in.
#[cfg(not(feature = "ssr"))]
fn detect() -> usize {
    document()
        .document_element()
        .and_then(|root| root.get_attribute("lang"))
        .and_then(|tag| embedded_i18n::match_locale(&tag))
        .unwrap_or(embedded_i18n::DEFAULT_LOCALE_INDEX)
}

/// The embedded locale best matching an `Accept-Language` header: languages are tried by
/// decreasing quality, in header order for equal qualities; `q=0` and `*` are skipped.
pub fn negotiate(accept_language: &str) -> Option<usize> {
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
    ranges
        .into_iter()
        .find_map(|(tag, _)| embedded_i18n::match_locale(tag))
}

/// Translates a message into the request's language: `t!("key")`, or with a context,
/// `t!(context = "menu", "key")`.
#[macro_export]
macro_rules! t {
    ($($arguments:tt)*) => {
        ::embedded_i18n::translate!(locale = $crate::i18n::locale(), $($arguments)*)
    };
}

/// Formats a message with arguments into a `String`, in the request's language:
/// `tf!("key", name = value)`.
#[macro_export]
macro_rules! tf {
    ($($arguments:tt)*) => {
        ::std::format!(
            "{}",
            ::embedded_i18n::translate_args!(locale = $crate::i18n::locale(), $($arguments)*)
        )
    };
}

/// Formats the plural form of a message matching a count into a `String`, in the request's
/// language: `tp!("key", count)`. Forms use `{count}`.
#[macro_export]
macro_rules! tp {
    ($key:literal, $count:expr) => {{
        let count = $count;
        ::embedded_i18n::translate_plural!(locale = $crate::i18n::locale(), $key, count)
            .replace("{count}", &count.to_string())
    }};
}

#[cfg(test)]
mod tests {
    use super::negotiate;

    #[test]
    fn negotiates_the_preferred_embedded_language() {
        let french = embedded_i18n::find_locale("fr");
        let english = embedded_i18n::find_locale("en");
        assert_eq!(negotiate("fr-CA,fr;q=0.9,en;q=0.8"), french);
        assert_eq!(negotiate("de-DE, en;q=0.5, fr;q=0.7"), french);
        assert_eq!(negotiate("en-GB"), english);
        assert_eq!(negotiate("fr;q=0, en;q=0.1"), english);
        assert_eq!(negotiate("de, *"), None);
        assert_eq!(negotiate(""), None);
    }
}
