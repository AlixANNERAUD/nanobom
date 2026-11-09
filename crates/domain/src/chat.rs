//! Slack and Microsoft Teams renderings of the `findings.new` and `projects.stale` documents.
//!
//! A webhook whose [`Format`](crate::notifications::Format) is `slack` or `teams` receives a
//! message instead of the generic JSON document. The message is rendered once, when the
//! delivery is queued, so a retry sends the same body. Messages are in English: nothing tells
//! the language of the people reading a channel.
//!
//! - **Slack** gets an Incoming Webhook payload: a plain `text` (the notification preview and
//!   the fallback of clients that do not show blocks) and Block Kit `blocks`.
//! - **Teams** gets what the Workflows app (the replacement of the retired Office 365
//!   connectors) accepts: a `message` carrying one Adaptive Card attachment.
//!
//! Both messages show at most [`MAX_ITEMS`] findings or projects and say how many were left
//! out. Everything that comes from the data (names, identifiers, summaries) is escaped for the
//! target syntax and clipped, so that a hostile or merely long value can neither inject
//! formatting nor push a message past the limits of the receiver.

use serde_json::{Value, json};

use crate::notifications::{
    NewFindingsPayload, PayloadFinding, PayloadStaleProject, StaleProjectsPayload,
};

/// How many findings or projects a message lists. A channel is for noticing, not for reading
/// a report: the link at the bottom leads to the complete list.
pub const MAX_ITEMS: usize = 10;

/// Slack accepts at most 3000 characters in the text of a section block and 150 in a header.
const SLACK_SECTION_LIMIT: usize = 3000;
const SLACK_HEADER_LIMIT: usize = 150;

/// Incoming webhooks of Teams refuse messages above 28 KB; stay below it with some room for
/// the envelope.
const TEAMS_SIZE_LIMIT: usize = 24_000;

/// Longest text of each field of a listed item, in characters once escaped.
const NAME_LIMIT: usize = 100;
const COMPONENT_LIMIT: usize = 250;
const SUMMARY_LIMIT: usize = 300;
/// Direct dependencies named in an "introduced via" line; the others are counted.
const VIA_NAMES: usize = 5;

/// Writes `text` with each character mapped through `piece`, clipped to `limit` characters
/// (the escaped text counts) and ended with `...` if anything was left out.
pub(crate) fn clipped(text: &str, limit: usize, piece: impl Fn(char) -> String) -> String {
    let pieces: Vec<String> = text.chars().map(piece).collect();
    let total: usize = pieces.iter().map(|piece| piece.chars().count()).sum();
    if total <= limit {
        return pieces.concat();
    }
    let mut output = String::new();
    let mut length = 0;
    for piece in pieces {
        let width = piece.chars().count();
        if length + width + 3 > limit {
            break;
        }
        output.push_str(&piece);
        length += width;
    }
    output.push_str("...");
    output
}

/// Collapses whitespace, so that a value cannot start a new line or a new block.
pub(crate) fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// Plain text clipped to `limit` characters, for the places where nothing is interpreted
/// (the header of a Slack message).
fn plain(text: &str, limit: usize) -> String {
    clipped(&one_line(text), limit, |character| character.to_string())
}

pub(crate) fn utc(time: chrono::DateTime<chrono::FixedOffset>) -> String {
    time.with_timezone(&chrono::Utc)
        .format("%Y-%m-%d %H:%M UTC")
        .to_string()
}

/// The words that follow a finding's identifier.
fn tags(finding: &PayloadFinding) -> Vec<&'static str> {
    let mut tags = vec![finding.severity.as_str()];
    if finding.reopened {
        tags.push("reopened");
    }
    if finding.known_exploited {
        tags.push(if finding.reason == "exploited" {
            "newly known exploited"
        } else {
            "known exploited"
        });
    }
    tags
}

/// The direct dependencies of a finding, at most [`VIA_NAMES`] of them.
fn via(finding: &PayloadFinding) -> Option<(Vec<&str>, usize)> {
    if finding.introduced_via.is_empty() {
        return None;
    }
    let names = finding
        .introduced_via
        .iter()
        .take(VIA_NAMES)
        .map(String::as_str)
        .collect();
    Some((
        names,
        finding.introduced_via.len().saturating_sub(VIA_NAMES),
    ))
}

fn headline(payload: &NewFindingsPayload) -> String {
    let mut text = format!(
        "{}: {} (highest severity: {}",
        payload.organization.name,
        plural(payload.count, "new finding", "new findings"),
        payload.highest_severity,
    );
    if payload.known_exploited_count > 0 {
        text.push_str(&format!(
            ", {} known exploited",
            payload.known_exploited_count
        ));
    }
    text.push(')');
    text
}

fn stale_headline(payload: &StaleProjectsPayload) -> String {
    format!(
        "{}: {} stopped sending SBOMs",
        payload.organization.name,
        plural(payload.projects.len(), "project", "projects"),
    )
}

fn last_upload(project: &PayloadStaleProject) -> String {
    project.last_upload_at.map_or_else(
        || "never received an SBOM".to_owned(),
        |time| format!("last SBOM {}", utc(time)),
    )
}

fn hidden_line(hidden: usize, noun: &str) -> Option<String> {
    (hidden > 0).then(|| format!("{hidden} more {noun} not shown."))
}

// ---------------------------------------------------------------------------------------------
// Slack
// ---------------------------------------------------------------------------------------------

/// Escapes the three characters Slack reserves in mrkdwn text. Slack knows no other escape:
/// `*`, `_` and `~` in a value still format it, which is harmless.
fn slack_piece(character: char) -> String {
    match character {
        '&' => "&amp;".to_owned(),
        '<' => "&lt;".to_owned(),
        '>' => "&gt;".to_owned(),
        other => other.to_string(),
    }
}

fn slack(text: &str, limit: usize) -> String {
    clipped(&one_line(text), limit, slack_piece)
}

/// A value shown as code. Backticks cannot be escaped inside code, so they are replaced.
fn slack_code(text: &str, limit: usize) -> String {
    format!("`{}`", slack(&text.replace('`', "'"), limit))
}

/// A link target in `<url|label>`: the characters that end the link are percent-encoded.
fn slack_url(url: &str) -> String {
    url.replace('<', "%3C")
        .replace('>', "%3E")
        .replace('|', "%7C")
}

fn slack_link(url: &str, label: &str, limit: usize) -> String {
    format!(
        "<{}|{}>",
        slack_url(url),
        slack(&label.replace('|', "/"), limit)
    )
}

fn slack_finding(finding: &PayloadFinding) -> Value {
    let mut lines = vec![format!(
        "*{}* - {}",
        slack_link(&finding.url, &finding.vulnerability, NAME_LIMIT),
        tags(finding).join(" - "),
    )];
    lines.push(format!(
        "{} in {}",
        slack_code(&finding.component, COMPONENT_LIMIT),
        slack(&finding.project, NAME_LIMIT),
    ));
    if let Some(summary) = &finding.summary {
        lines.push(slack(summary, SUMMARY_LIMIT));
    }
    if let Some((names, more)) = via(finding) {
        let mut line = format!(
            "Introduced via {}",
            names
                .iter()
                .map(|name| slack_code(name, NAME_LIMIT))
                .collect::<Vec<_>>()
                .join(", ")
        );
        if more > 0 {
            line.push_str(&format!(" and {more} more"));
        }
        lines.push(line);
    }
    let text = lines.join("\n");
    json!({"type": "section", "text": {"type": "mrkdwn", "text": clipped(&text, SLACK_SECTION_LIMIT, |c| c.to_string())}})
}

fn slack_message(headline: &str, mut blocks: Vec<Value>, footer: Vec<String>) -> String {
    blocks.insert(
        0,
        json!({"type": "header", "text": {"type": "plain_text", "text": plain(headline, SLACK_HEADER_LIMIT)}}),
    );
    blocks.push(json!({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": footer.join(" ")}],
    }));
    json!({
        "text": slack(headline, SLACK_SECTION_LIMIT),
        "blocks": blocks,
    })
    .to_string()
}

/// The Slack message of a `findings.new` document.
pub fn slack_new_findings(payload: &NewFindingsPayload) -> String {
    let shown = payload.findings.iter().take(MAX_ITEMS);
    let mut footer: Vec<String> =
        hidden_line(payload.findings.len().saturating_sub(MAX_ITEMS), "findings")
            .into_iter()
            .collect();
    footer.push(slack_link(
        &payload.organization.url,
        &format!("Open {} in nanobom", payload.organization.name),
        NAME_LIMIT,
    ));
    slack_message(
        &headline(payload),
        shown.map(slack_finding).collect(),
        footer,
    )
}

/// The Slack message of a `projects.stale` document.
pub fn slack_stale_projects(payload: &StaleProjectsPayload) -> String {
    let blocks = payload
        .projects
        .iter()
        .take(MAX_ITEMS)
        .map(|project| {
            let text = format!(
                "*{}* - {}",
                slack_link(&project.url, &project.project, NAME_LIMIT),
                last_upload(project),
            );
            json!({"type": "section", "text": {"type": "mrkdwn", "text": text}})
        })
        .collect();
    let mut footer: Vec<String> =
        hidden_line(payload.projects.len().saturating_sub(MAX_ITEMS), "projects")
            .into_iter()
            .collect();
    footer.push(slack_link(
        &payload.organization.url,
        &format!("Open {} in nanobom", payload.organization.name),
        NAME_LIMIT,
    ));
    slack_message(&stale_headline(payload), blocks, footer)
}

// ---------------------------------------------------------------------------------------------
// Microsoft Teams
// ---------------------------------------------------------------------------------------------

/// Backslash-escapes what the Markdown subset of Adaptive Cards would interpret.
fn markdown_piece(character: char) -> String {
    if "\\*_[]`<>".contains(character) {
        format!("\\{character}")
    } else {
        character.to_string()
    }
}

fn markdown(text: &str, limit: usize) -> String {
    clipped(&one_line(text), limit, markdown_piece)
}

fn markdown_link(url: &str, label: &str, limit: usize) -> String {
    let url = url
        .replace(' ', "%20")
        .replace('(', "%28")
        .replace(')', "%29");
    format!("[{}]({url})", markdown(label, limit))
}

fn text_block(text: String, extra: Value) -> Value {
    let mut block = json!({"type": "TextBlock", "text": text, "wrap": true});
    if let (Some(block), Some(extra)) = (block.as_object_mut(), extra.as_object()) {
        block.extend(extra.clone());
    }
    block
}

fn teams_finding(finding: &PayloadFinding) -> Value {
    let mut items = vec![text_block(
        format!(
            "**{}** - {}",
            markdown_link(&finding.url, &finding.vulnerability, NAME_LIMIT),
            tags(finding).join(" - "),
        ),
        if finding.known_exploited {
            json!({"color": "Attention"})
        } else {
            json!({})
        },
    )];
    items.push(text_block(
        format!(
            "{} in {}",
            markdown(&finding.component, COMPONENT_LIMIT),
            markdown(&finding.project, NAME_LIMIT),
        ),
        json!({"spacing": "None"}),
    ));
    if let Some(summary) = &finding.summary {
        items.push(text_block(
            markdown(summary, SUMMARY_LIMIT),
            json!({"spacing": "None", "isSubtle": true}),
        ));
    }
    if let Some((names, more)) = via(finding) {
        let mut line = format!(
            "Introduced via {}",
            names
                .iter()
                .map(|name| markdown(name, NAME_LIMIT))
                .collect::<Vec<_>>()
                .join(", ")
        );
        if more > 0 {
            line.push_str(&format!(" and {more} more"));
        }
        items.push(text_block(line, json!({"spacing": "None"})));
    }
    json!({"type": "Container", "separator": true, "spacing": "Medium", "items": items})
}

/// The card of a message, with at most `shown` items out of `total`. The number shown shrinks
/// until the message is small enough: items of non-Latin text weigh several bytes a character.
fn teams_message(
    headline: &str,
    noun: &str,
    open: (&str, &str),
    items: &[Value],
    total: usize,
) -> String {
    let mut shown = items.len().min(MAX_ITEMS);
    loop {
        let mut body = vec![text_block(
            markdown(headline, 200),
            json!({"weight": "Bolder", "size": "Medium"}),
        )];
        body.extend(items[..shown].iter().cloned());
        if let Some(line) = hidden_line(total - shown, noun) {
            body.push(text_block(line, json!({"isSubtle": true})));
        }
        let message = json!({
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": null,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.2",
                    "msteams": {"width": "Full"},
                    "body": body,
                    "actions": [{
                        "type": "Action.OpenUrl",
                        "title": clipped(open.1, 100, |c| c.to_string()),
                        "url": open.0,
                    }],
                },
            }],
        })
        .to_string();
        if message.len() <= TEAMS_SIZE_LIMIT || shown == 0 {
            return message;
        }
        shown -= 1;
    }
}

/// The Teams message of a `findings.new` document.
pub fn teams_new_findings(payload: &NewFindingsPayload) -> String {
    let items: Vec<Value> = payload
        .findings
        .iter()
        .take(MAX_ITEMS)
        .map(teams_finding)
        .collect();
    teams_message(
        &headline(payload),
        "findings",
        (
            &payload.organization.url,
            &format!("Open {} in nanobom", payload.organization.name),
        ),
        &items,
        payload.findings.len(),
    )
}

/// The Teams message of a `projects.stale` document.
pub fn teams_stale_projects(payload: &StaleProjectsPayload) -> String {
    let items: Vec<Value> = payload
        .projects
        .iter()
        .take(MAX_ITEMS)
        .map(|project| {
            json!({"type": "Container", "separator": true, "items": [text_block(
                format!(
                    "**{}** - {}",
                    markdown_link(&project.url, &project.project, NAME_LIMIT),
                    last_upload(project),
                ),
                json!({}),
            )]})
        })
        .collect();
    teams_message(
        &stale_headline(payload),
        "projects",
        (
            &payload.organization.url,
            &format!("Open {} in nanobom", payload.organization.name),
        ),
        &items,
        payload.projects.len(),
    )
}
