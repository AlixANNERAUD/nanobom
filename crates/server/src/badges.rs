//! Public project badges ([`nanobom_domain::badges`]): `GET /badges/{key}.svg` and
//! `GET /badges/{key}.json`, with an optional `?version=`.
//!
//! The key in the path is the only authorization: no session, token or cross-site check is
//! involved, so README renderers and image proxies fetch the badge anonymously. Anything that
//! does not resolve (an unknown or replaced key, a badge turned off, an unknown version, another
//! extension, a malformed query) is the same empty `404`, so a caller cannot tell which part was
//! wrong.
//!
//! The SVG imitates the flat style of shields.io, and the JSON is the shields.io endpoint schema,
//! so a badge can be restyled through `https://img.shields.io/endpoint?url=…`. Badges are in
//! English whatever the interface language: they are embedded in READMEs of any language.
//!
//! Responses are `Cache-Control: public, max-age=300`: image proxies such as GitHub's camo cache
//! them, and five minutes bounds how long a badge lags behind triage. They carry a strong
//! `ETag` of the body; [`crate::http::layers`] leaves such responses uncompressed so the tag
//! keeps naming the bytes sent.

use std::fmt::Write as _;

use axum::{
    Router,
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use nanobom_domain::{Error, badges::Summary, findings::OpenSummary};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::state::AppState;

/// The text on the left of every badge.
pub const LABEL: &str = "vulnerabilities";

/// The grey behind the label.
const LABEL_COLOR: &str = "555555";
/// Text drawn on light colours, where white would not be legible.
const DARK_TEXT: &str = "1f2328";
const LIGHT_TEXT: &str = "ffffff";

/// The colours of a badge's message. Each keeps a contrast of at least 4.5:1 with its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    /// No open finding.
    Green,
    /// A critical or known exploited finding.
    Red,
    /// A high finding.
    Orange,
    /// A medium finding, with dark text.
    Yellow,
    /// A low finding, with dark text.
    YellowGreen,
    /// Findings of unknown severity only, or no SBOM yet.
    Grey,
}

impl Color {
    /// The colour in hexadecimal, without `#`, as the shields.io endpoint schema takes it.
    pub fn hex(self) -> &'static str {
        match self {
            Color::Green => "1f883d",
            Color::Red => "cf222e",
            Color::Orange => "bc4c00",
            Color::Yellow => "d4a72c",
            Color::YellowGreen => "a2b82c",
            Color::Grey => "6e7781",
        }
    }

    fn text(self) -> &'static str {
        match self {
            Color::Yellow | Color::YellowGreen => DARK_TEXT,
            _ => LIGHT_TEXT,
        }
    }
}

/// What a badge says: its message and colour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Badge {
    pub message: String,
    pub color: Color,
}

impl Badge {
    /// The message and colour for a summary: the known exploited count first, then the non-zero
    /// counts from the worst severity; the colour is that of the worst open finding.
    pub fn new(summary: &Summary) -> Self {
        let OpenSummary {
            counts,
            known_exploited,
        } = match summary {
            Summary::NoSbom => {
                return Self {
                    message: "no SBOM".to_owned(),
                    color: Color::Grey,
                };
            }
            Summary::Findings(open) => *open,
        };
        let mut parts = Vec::new();
        if known_exploited > 0 {
            parts.push(format!("{known_exploited} exploited"));
        }
        let severities = [
            (counts.critical, "critical", Color::Red),
            (counts.high, "high", Color::Orange),
            (counts.medium, "medium", Color::Yellow),
            (counts.low, "low", Color::YellowGreen),
            (counts.unknown, "unknown", Color::Grey),
        ];
        let mut color = None;
        for (count, name, severity_color) in severities {
            if count > 0 {
                parts.push(format!("{count} {name}"));
                color.get_or_insert(severity_color);
            }
        }
        if parts.is_empty() {
            return Self {
                message: "none".to_owned(),
                color: Color::Green,
            };
        }
        if known_exploited > 0 {
            color = Some(Color::Red);
        }
        Self {
            message: parts.join(", "),
            // Known exploited findings are open findings, so some severity was counted.
            color: color.unwrap_or(Color::Red),
        }
    }

    /// The shields.io endpoint document.
    pub fn json(&self) -> String {
        serde_json::json!({
            "schemaVersion": 1,
            "label": LABEL,
            "message": self.message,
            "color": self.color.hex(),
        })
        .to_string()
    }

    /// A flat SVG badge in the style of shields.io: the label on grey, the message on its colour.
    pub fn svg(&self) -> String {
        let label_width = segment_width(LABEL);
        let message_width = segment_width(&self.message);
        let width = label_width + message_width;
        let title = escape(&format!("{LABEL}: {}", self.message));
        let label = escape(LABEL);
        let message = escape(&self.message);
        let color = self.color.hex();
        // Text is laid out at ten times its size and scaled down, so positions keep a decimal.
        let label_x = label_width * 5;
        let message_x = label_width * 10 + message_width * 5;
        let label_length = (text_width(LABEL) * 10.0).round();
        let message_length = (text_width(&self.message) * 10.0).round();
        let mut svg = String::new();
        let _ = write!(
            svg,
            r##"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20" role="img" aria-label="{title}"><title>{title}</title><linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="r"><rect width="{width}" height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#r)"><rect width="{label_width}" height="20" fill="#{LABEL_COLOR}"/><rect x="{label_width}" width="{message_width}" height="20" fill="#{color}"/><rect width="{width}" height="20" fill="url(#s)"/></g><g fill="#{LIGHT_TEXT}" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">"##
        );
        text(&mut svg, label_x, label_length, &label, LIGHT_TEXT);
        text(
            &mut svg,
            message_x,
            message_length,
            &message,
            self.color.text(),
        );
        svg.push_str("</g></svg>");
        svg
    }
}

/// One line of text, with a shadow under light text as shields.io draws it.
fn text(svg: &mut String, x: u32, length: f64, content: &str, color: &str) {
    if color == LIGHT_TEXT {
        let _ = write!(
            svg,
            r##"<text aria-hidden="true" x="{x}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{length}">{content}</text>"##
        );
    }
    let _ = write!(
        svg,
        r##"<text x="{x}" y="140" fill="#{color}" transform="scale(.1)" textLength="{length}">{content}</text>"##
    );
}

/// Widths of the printable ASCII characters, from space to `~`, in Verdana at 11 pixels. Other
/// characters count as wide as `m`, so text is never clipped; badges only print ASCII.
const WIDTHS: [f64; 95] = [
    3.87, 4.33, 5.05, 9.0, 6.99, 11.84, 7.99, 2.95, 4.99, 4.99, 6.99, 9.0, 4.0, 4.99, 4.0, 4.99,
    6.99, 6.99, 6.99, 6.99, 6.99, 6.99, 6.99, 6.99, 6.99, 6.99, 4.99, 4.99, 9.0, 9.0, 9.0, 6.0,
    11.0, 7.52, 7.54, 7.68, 8.48, 6.96, 6.32, 8.53, 8.27, 4.63, 5.0, 7.62, 6.12, 9.27, 8.23, 8.66,
    6.63, 8.66, 7.65, 7.52, 6.78, 8.05, 7.52, 10.88, 7.54, 6.77, 7.54, 4.99, 4.99, 4.99, 9.0, 6.99,
    6.99, 6.61, 6.85, 5.73, 6.85, 6.55, 3.87, 6.85, 6.96, 3.02, 3.79, 6.51, 3.02, 10.7, 6.96, 6.68,
    6.85, 6.85, 4.69, 5.73, 4.33, 6.96, 6.51, 9.0, 6.51, 6.51, 5.78, 6.98, 4.99, 6.98, 9.0,
];

/// The width of a text in pixels.
fn text_width(text: &str) -> f64 {
    text.chars()
        .map(|character| {
            u32::from(character)
                .checked_sub(0x20)
                .and_then(|index| WIDTHS.get(index as usize))
                .copied()
                .unwrap_or(10.7)
        })
        .sum()
}

/// The width of one side of the badge: the text and five pixels of padding on each side.
fn segment_width(text: &str) -> u32 {
    // Badge text is at most a few dozen characters, far below any overflow.
    (text_width(text) + 10.0).round() as u32
}

/// Escapes text for XML content and attribute values.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// The `/badges/{file}` route.
pub fn router() -> Router<AppState> {
    Router::new().route("/badges/{file}", get(badge))
}

#[derive(Debug, Default, Deserialize)]
struct Parameters {
    version: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum Format {
    Svg,
    Json,
}

/// `GET /badges/{key}.svg` and `GET /badges/{key}.json`.
async fn badge(
    State(state): State<AppState>,
    Path(file): Path<String>,
    parameters: Result<Query<Parameters>, QueryRejection>,
    headers: HeaderMap,
) -> Response {
    let (key, format) = if let Some(key) = file.strip_suffix(".svg") {
        (key, Format::Svg)
    } else if let Some(key) = file.strip_suffix(".json") {
        (key, Format::Json)
    } else {
        return not_found();
    };
    let Ok(Query(parameters)) = parameters else {
        return not_found();
    };
    // As in the read API, an empty value names the unnamed version.
    let version = parameters.version.as_deref().map(str::trim);
    let summary = match nanobom_domain::badges::summary(&state.database, key, version).await {
        Ok(summary) => summary,
        Err(Error::NotFound) => return not_found(),
        Err(error) => {
            tracing::error!(%error, "cannot read a badge");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let badge = Badge::new(&summary);
    match format {
        Format::Svg => respond(
            &headers,
            "image/svg+xml; charset=utf-8",
            badge.svg(),
            // Opened directly, the image may draw and style itself, and do nothing else.
            Some("default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"),
        ),
        Format::Json => respond(&headers, "application/json", badge.json(), None),
    }
}

fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

/// A badge with its caching headers, or `304` when `If-None-Match` names its tag.
fn respond(
    headers: &HeaderMap,
    content_type: &'static str,
    body: String,
    content_security_policy: Option<&'static str>,
) -> Response {
    let tag: String = Sha256::digest(body.as_bytes())[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let etag = format!("\"{tag}\"");
    let etag_value = HeaderValue::from_str(&etag).expect("hexadecimal digits");
    let cache_control = HeaderValue::from_static("public, max-age=300");
    if if_none_match(headers, &etag) {
        return (
            StatusCode::NOT_MODIFIED,
            [
                (header::ETAG, etag_value),
                (header::CACHE_CONTROL, cache_control),
            ],
        )
            .into_response();
    }
    let mut response = (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (header::ETAG, etag_value),
            (header::CACHE_CONTROL, cache_control),
        ],
        body,
    )
        .into_response();
    if let Some(policy) = content_security_policy {
        response.headers_mut().insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(policy),
        );
    }
    response
}

/// Whether `If-None-Match` names this tag or is `*`. The comparison is weak (RFC 9110, 13.1.2),
/// as the RFC requires for `If-None-Match`: a `W/` prefix on a candidate is ignored.
fn if_none_match(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|candidate| {
                let candidate = candidate.trim();
                candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
            })
        })
}

#[cfg(test)]
mod tests {
    use nanobom_domain::{
        badges::Summary,
        findings::{OpenSummary, SeverityCounts},
    };

    use super::{Badge, Color, escape, segment_width};

    fn badge(counts: SeverityCounts, known_exploited: i64) -> Badge {
        Badge::new(&Summary::Findings(OpenSummary {
            counts,
            known_exploited,
        }))
    }

    #[test]
    fn the_message_lists_open_findings_from_the_worst_and_takes_its_colour() {
        let cases = [
            (SeverityCounts::default(), 0, "none", Color::Green),
            (
                SeverityCounts {
                    critical: 1,
                    high: 2,
                    medium: 3,
                    low: 1,
                    unknown: 1,
                },
                0,
                "1 critical, 2 high, 3 medium, 1 low, 1 unknown",
                Color::Red,
            ),
            (
                SeverityCounts {
                    high: 2,
                    low: 1,
                    ..SeverityCounts::default()
                },
                0,
                "2 high, 1 low",
                Color::Orange,
            ),
            (
                SeverityCounts {
                    medium: 3,
                    ..SeverityCounts::default()
                },
                0,
                "3 medium",
                Color::Yellow,
            ),
            (
                SeverityCounts {
                    low: 1,
                    unknown: 4,
                    ..SeverityCounts::default()
                },
                0,
                "1 low, 4 unknown",
                Color::YellowGreen,
            ),
            (
                SeverityCounts {
                    unknown: 1,
                    ..SeverityCounts::default()
                },
                0,
                "1 unknown",
                Color::Grey,
            ),
            // Known exploited findings come first and turn any badge red.
            (
                SeverityCounts {
                    medium: 2,
                    ..SeverityCounts::default()
                },
                1,
                "1 exploited, 2 medium",
                Color::Red,
            ),
        ];
        for (counts, known_exploited, message, color) in cases {
            let badge = badge(counts, known_exploited);
            assert_eq!(badge.message, message);
            assert_eq!(badge.color, color, "{message}");
        }
        let no_sbom = Badge::new(&Summary::NoSbom);
        assert_eq!(no_sbom.message, "no SBOM");
        assert_eq!(no_sbom.color, Color::Grey);
    }

    #[test]
    fn the_json_follows_the_shields_endpoint_schema() {
        let json: serde_json::Value = serde_json::from_str(
            &badge(
                SeverityCounts {
                    high: 2,
                    ..SeverityCounts::default()
                },
                0,
            )
            .json(),
        )
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "schemaVersion": 1,
                "label": "vulnerabilities",
                "message": "2 high",
                "color": "bc4c00",
            })
        );
    }

    #[test]
    fn the_svg_is_an_accessible_image_with_both_texts() {
        let svg = badge(
            SeverityCounts {
                critical: 1,
                ..SeverityCounts::default()
            },
            0,
        )
        .svg();
        assert!(svg.starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\""));
        assert!(svg.contains(r#"role="img""#));
        assert!(svg.contains(r#"aria-label="vulnerabilities: 1 critical""#));
        assert!(svg.contains("<title>vulnerabilities: 1 critical</title>"));
        assert!(svg.contains(">vulnerabilities</text>"));
        assert!(svg.contains(">1 critical</text>"));
        assert!(svg.contains("fill=\"#cf222e\""));
        assert!(svg.ends_with("</svg>"));
        // Medium and low badges are light: their message is dark, without a shadow.
        let medium = badge(
            SeverityCounts {
                medium: 1,
                ..SeverityCounts::default()
            },
            0,
        )
        .svg();
        assert!(medium.contains(r##"fill="#1f2328" transform="scale(.1)" textLength"##));
    }

    #[test]
    fn text_is_escaped() {
        assert_eq!(
            escape(r#"<a href="x">'&'</a>"#),
            "&lt;a href=&quot;x&quot;&gt;&apos;&amp;&apos;&lt;/a&gt;"
        );
        let svg = Badge {
            message: "<script>&\"".to_owned(),
            color: Color::Grey,
        }
        .svg();
        assert!(!svg.contains("<script>"));
        assert!(svg.contains("&lt;script&gt;&amp;&quot;"));
    }

    #[test]
    fn longer_text_makes_a_wider_badge() {
        assert!(segment_width("none") < segment_width("1 critical"));
        assert!(segment_width("1 critical") < segment_width("1 critical, 2 high"));
        // Narrow and wide letters differ, as in the font.
        assert!(segment_width("iiii") < segment_width("mmmm"));
        // Characters outside ASCII still take room.
        assert!(segment_width("é") > segment_width(""));
        let narrow = Badge::new(&Summary::NoSbom).svg();
        let wide = badge(
            SeverityCounts {
                critical: 10,
                high: 20,
                ..SeverityCounts::default()
            },
            3,
        )
        .svg();
        let width = |svg: &str| -> u32 {
            let start = svg.find("width=\"").unwrap() + 7;
            let end = start + svg[start..].find('"').unwrap();
            svg[start..end].parse().unwrap()
        };
        assert!(width(&narrow) < width(&wide));
        assert_eq!(
            width(&narrow),
            segment_width("vulnerabilities") + segment_width("no SBOM")
        );
    }
}
