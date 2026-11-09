//! Email notifications: each organization can have its `findings.new` and `projects.stale`
//! notifications sent by email, through the SMTP server of the instance.
//!
//! The settings of an organization ([`get`], [`set`], [`delete`]) are a list of recipients (at
//! most [`MAX_RECIPIENTS`]), the language of the emails and the same filters as the webhook
//! (minimum severity, known exploited only). They need [`Permission::ManageWebhook`], like the
//! webhook: both decide where the organization's findings go.
//!
//! An email is a delivery of the queue of [`crate::deliveries`] on the [`Channel::Email`]
//! channel, prepared with the webhook deliveries of the same event ([`crate::notifications`])
//! and retried with the same backoff.
//! The message is rendered when it is queued ([`Message`]: a subject, a plain-text body and an
//! HTML alternative, in the organization's language), so a retry sends the same message.
//!
//! Each recipient has a delivery of its own, with only its address in the SMTP envelope: an
//! SMTP server refuses recipients one by one, and the client gives up the whole transaction at
//! the first refusal, so a single envelope would let one wrong address stop the email for
//! everyone, for good on a 5xx. The `To` header still lists every recipient: they are the
//! organization's own people, and seeing who else was told helps them coordinate.
//!
//! The SMTP server is configured by the operator ([`Mailer`]); without one, email is off, and
//! the settings are neither shown nor used. An SMTP reply in the 5xx range (a mailbox that does
//! not exist, a message refused as spam) is permanent and not retried; 4xx replies and
//! connection failures are.
//!
//! Test emails are limited per organization, per user and for the whole instance
//! ([`Mailer`]): recipients are not verified, and any signed-in user can create an
//! organization, so the button must not turn the instance into a relay. For the same reason the
//! test email carries no free text from users: it names the organization by its slug.
//!
//! Everything in an email that comes from the data (organization and project names, component
//! identifiers, summaries) is clipped, kept on one line, and escaped in the HTML part.

use std::{
    collections::{HashMap, VecDeque},
    fmt::Write as _,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use embedded_i18n::{Locale, t};
use lettre::{
    Address, AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
    address::Envelope,
    message::{Mailbox, MultiPart},
};
use nanobom_entity::{organization_emails, organizations};
use nanobom_osv::Severity;
use reqwest::Url;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectionTrait, EntityTrait, ModelTrait};
use serde::{Deserialize, Serialize};

use crate::{
    access::{Actor, Permission},
    chat::{self, clipped, one_line, utc},
    deliveries::{self, Attempt, Channel},
    error::{Error, Result},
    notifications::{
        NewFindingsPayload, PayloadFinding, PayloadOrganization, StaleProjectsPayload, link,
    },
    problem::{ENGLISH, Problem},
};

/// Most recipients of an organization's emails. Above a handful, a mailing list is the better
/// tool: its members can then change without an admin of nanobom.
pub const MAX_RECIPIENTS: usize = 20;

/// Shortest wait between two test emails of an organization, and between two test emails of
/// a user, so the button cannot be used to flood a mailbox.
pub const TEST_INTERVAL: Duration = Duration::from_secs(30);

/// Most test emails of the whole instance per [`TEST_WINDOW`]: users can create organizations,
/// so the limits per organization and per user alone do not bound what the instance sends.
pub const TEST_LIMIT: usize = 10;
pub const TEST_WINDOW: Duration = Duration::from_secs(10 * 60);

/// How many findings or projects an email lists; the link at the bottom leads to the others.
pub const MAX_ITEMS: usize = 50;

/// Longest wait for one SMTP command, and for a whole message. The whole stays well below the
/// lease of a delivery attempt ([`deliveries::ATTEMPT_LEASE`]).
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const SEND_TIMEOUT: Duration = Duration::from_secs(60);

/// Longest text of each field, in characters.
const NAME_LIMIT: usize = 100;
const COMPONENT_LIMIT: usize = 250;
const SUMMARY_LIMIT: usize = 300;
const SUBJECT_LIMIT: usize = 200;
/// Direct dependencies named in an "introduced via" line; the others are counted.
const VIA_NAMES: usize = 5;

const FRENCH: Locale = Locale::new("fr");

/// The language of an organization's emails.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    #[default]
    English,
    French,
}

impl Language {
    pub const ALL: [Language; 2] = [Language::English, Language::French];

    /// The language tag stored in the database and sent by the settings form.
    pub fn as_str(self) -> &'static str {
        match self {
            Language::English => "en",
            Language::French => "fr",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|language| language.as_str() == value)
    }

    /// The locale this language translates into.
    fn locale(self) -> Locale {
        match self {
            Language::English => ENGLISH,
            Language::French => FRENCH,
        }
    }
}

/// An organization's email settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailSettings {
    /// Addresses the emails go to, in the order they were entered.
    pub recipients: Vec<String>,
    pub language: Language,
    /// Findings below this severity are left out, unless they are known exploited.
    pub minimum_severity: Severity,
    /// Send only known exploited findings.
    pub exploited_only: bool,
}

fn view(model: organization_emails::Model) -> EmailSettings {
    EmailSettings {
        recipients: model
            .recipients
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect(),
        language: Language::parse(&model.language).unwrap_or_default(),
        minimum_severity: model.minimum_severity.parse().unwrap_or(Severity::Unknown),
        exploited_only: model.exploited_only,
    }
}

/// Splits a list of addresses typed in a form: separated by commas, semicolons or whitespace.
pub fn split_recipients(text: &str) -> impl Iterator<Item = &str> {
    text.split(|character: char| character == ',' || character == ';' || character.is_whitespace())
        .filter(|address| !address.is_empty())
}

/// Validates recipients: plain addresses (`name@example.org`, no display name), at least one
/// and at most [`MAX_RECIPIENTS`]. Duplicates, compared without case, are dropped.
pub fn validate_recipients(recipients: &[String]) -> Result<Vec<String>> {
    let mut valid: Vec<String> = Vec::new();
    for recipient in recipients {
        let address = recipient.trim();
        if address.is_empty() {
            continue;
        }
        if address.parse::<lettre::Address>().is_err() {
            return Err(Error::invalid(Problem::InvalidRecipient {
                address: clipped(&one_line(address), NAME_LIMIT, String::from),
            }));
        }
        if !valid
            .iter()
            .any(|known| known.eq_ignore_ascii_case(address))
        {
            valid.push(address.to_owned());
        }
    }
    if valid.is_empty() {
        return Err(Error::invalid(Problem::NoRecipients));
    }
    if valid.len() > MAX_RECIPIENTS {
        return Err(Error::invalid(Problem::TooManyRecipients {
            maximum: MAX_RECIPIENTS,
        }));
    }
    Ok(valid)
}

/// The email settings of an organization, if configured. Requires
/// [`Permission::ManageWebhook`]: members do not see where notifications go.
pub async fn get(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
) -> Result<Option<EmailSettings>> {
    actor
        .authorize(database, organization_id, Permission::ManageWebhook)
        .await?;
    settings(database, organization_id).await
}

/// The email settings of an organization, for the run worker (no actor).
pub(crate) async fn settings(
    database: &impl ConnectionTrait,
    organization_id: i64,
) -> Result<Option<EmailSettings>> {
    Ok(organization_emails::Entity::find_by_id(organization_id)
        .one(database)
        .await?
        .map(view))
}

/// Creates or replaces the email settings of an organization. Changing the recipients abandons
/// the pending emails, as removing the settings does: retries never reach an address the admins
/// took away. Changing the language abandons them too, since they were rendered in the previous
/// one. Requires [`Permission::ManageWebhook`].
pub async fn set(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
    settings: &EmailSettings,
) -> Result<EmailSettings> {
    actor
        .authorize(database, organization_id, Permission::ManageWebhook)
        .await?;
    let recipients = validate_recipients(&settings.recipients)?.join("\n");
    let EmailSettings {
        language,
        minimum_severity,
        exploited_only,
        ..
    } = *settings;
    let existing = organization_emails::Entity::find_by_id(organization_id)
        .one(database)
        .await?;
    let model = match existing {
        Some(model) => {
            if model.recipients != recipients || model.language != language.as_str() {
                deliveries::cancel_pending(database, organization_id, Channel::Email).await?;
            }
            let mut active: organization_emails::ActiveModel = model.into();
            active.recipients = Set(recipients);
            active.language = Set(language.as_str().to_owned());
            active.minimum_severity = Set(minimum_severity.as_str().to_owned());
            active.exploited_only = Set(exploited_only);
            active.update(database).await?
        }
        None => {
            organization_emails::ActiveModel {
                organization_id: Set(organization_id),
                recipients: Set(recipients),
                language: Set(language.as_str().to_owned()),
                minimum_severity: Set(minimum_severity.as_str().to_owned()),
                exploited_only: Set(exploited_only),
            }
            .insert(database)
            .await?
        }
    };
    Ok(view(model))
}

/// Removes the email settings of an organization and abandons its pending emails. Requires
/// [`Permission::ManageWebhook`]; removing missing settings succeeds.
pub async fn delete(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
) -> Result<()> {
    actor
        .authorize(database, organization_id, Permission::ManageWebhook)
        .await?;
    if let Some(model) = organization_emails::Entity::find_by_id(organization_id)
        .one(database)
        .await?
    {
        model.delete(database).await?;
    }
    deliveries::cancel_pending(database, organization_id, Channel::Email).await?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------------------------

/// A rendered email, stored as JSON in the payload of its delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// The addresses of the `To` header: every recipient of the organization, set when the
    /// email is queued. Each delivery sends to one of them only (see the module documentation).
    #[serde(default)]
    pub to: Vec<String>,
    pub subject: String,
    pub text: String,
    pub html: String,
}

/// Replaces the `{name}` placeholders of a translated template in one pass, so that a value
/// containing braces is never read as a placeholder.
fn fill(template: &str, values: &[(&str, &str)]) -> String {
    let mut output = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        output.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let value = after.find('}').and_then(|end| {
            let name = &after[..end];
            values
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (end, *value))
        });
        match value {
            Some((end, value)) => {
                output.push_str(value);
                rest = &after[end + 1..];
            }
            None => {
                output.push('{');
                rest = after;
            }
        }
    }
    output.push_str(rest);
    output
}

/// Escapes text for HTML content and quoted attribute values.
fn escape(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            other => output.push(other),
        }
    }
    output
}

/// A value from the data: on one line, clipped to `limit` characters.
fn value(text: &str, limit: usize) -> String {
    clipped(&one_line(text), limit, String::from)
}

/// A text written once and shown twice: as plain text and as HTML, where every value is
/// escaped and the template, a trusted translation, is escaped as well.
struct Line {
    text: String,
    html: String,
}

impl Line {
    fn new(template: &str, values: &[(&str, &str)]) -> Self {
        let escaped: Vec<(&str, String)> = values
            .iter()
            .map(|(key, value)| (*key, escape(value)))
            .collect();
        let escaped: Vec<(&str, &str)> = escaped
            .iter()
            .map(|(key, value)| (*key, value.as_str()))
            .collect();
        Self {
            text: fill(template, values),
            html: fill(&escape(template), &escaped),
        }
    }
}

fn severity(severity: Severity, locale: Locale) -> &'static str {
    match severity {
        Severity::Critical => t!("email.severity.critical", locale = locale),
        Severity::High => t!("email.severity.high", locale = locale),
        Severity::Medium => t!("email.severity.medium", locale = locale),
        Severity::Low => t!("email.severity.low", locale = locale),
        Severity::Unknown => t!("email.severity.unknown", locale = locale),
    }
}

/// The words that follow a finding's identifier.
fn tags(finding: &PayloadFinding, locale: Locale) -> String {
    let mut tags = vec![severity(finding.severity, locale)];
    if finding.reopened {
        tags.push(t!("email.tags.reopened", locale = locale));
    }
    if finding.known_exploited {
        tags.push(if finding.reason == "exploited" {
            t!("email.tags.newly_known_exploited", locale = locale)
        } else {
            t!("email.tags.known_exploited", locale = locale)
        });
    }
    tags.join(", ")
}

/// The parts of an email that do not depend on the event.
struct Frame<'a> {
    organization: &'a PayloadOrganization,
    locale: Locale,
    language: Language,
}

impl Frame<'_> {
    fn organization_name(&self) -> String {
        value(&self.organization.name, NAME_LIMIT)
    }

    /// Assembles the message: a headline, a summary line, the items, a line about the items
    /// left out, then the link to the organization and why the reader gets the email.
    fn message(
        &self,
        subject: String,
        headline: &str,
        summary: Option<Line>,
        items: &[(Vec<Line>, String)],
        hidden: Option<String>,
    ) -> Message {
        let locale = self.locale;
        let organization = self.organization_name();
        let open = Line::new(
            t!("email.open_organization", locale = locale),
            &[("organization", &organization)],
        );
        let settings = link_in(&self.organization.url, "settings");
        let footer = Line::new(
            t!("email.footer", locale = locale),
            &[("organization", &organization)],
        );

        let mut text = format!("{headline}\n");
        if let Some(summary) = &summary {
            let _ = writeln!(text, "{}", summary.text);
        }
        text.push('\n');
        for (lines, url) in items {
            for (index, line) in lines.iter().enumerate() {
                let prefix = if index == 0 { "- " } else { "  " };
                let _ = writeln!(text, "{prefix}{}", line.text);
            }
            let _ = writeln!(text, "  {url}\n");
        }
        if let Some(hidden) = &hidden {
            let _ = writeln!(text, "{hidden}\n");
        }
        let _ = writeln!(text, "{}: {}", open.text, self.organization.url);
        let _ = writeln!(text, "\n-- \n{}\n{settings}", footer.text);

        let mut html = format!(
            "<!DOCTYPE html>\n<html lang=\"{}\">\n<head><meta charset=\"utf-8\"><title>{}</title></head>\n\
             <body style=\"font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; \
             font-size: 14px; line-height: 1.5; color: #1f2328;\">\n<h2 style=\"font-size: 18px;\">{}</h2>\n",
            self.language.as_str(),
            escape(&subject),
            escape(headline),
        );
        if let Some(summary) = &summary {
            let _ = writeln!(html, "<p>{}</p>", summary.html);
        }
        if !items.is_empty() {
            html.push_str("<ul style=\"padding-left: 20px;\">\n");
            for (lines, url) in items {
                html.push_str("<li style=\"margin-bottom: 12px;\">");
                for (index, line) in lines.iter().enumerate() {
                    if index == 0 {
                        let _ = write!(
                            html,
                            "<a href=\"{}\"><strong>{}</strong></a>",
                            escape(url),
                            line.html
                        );
                    } else {
                        let _ = write!(html, "<br>{}", line.html);
                    }
                }
                html.push_str("</li>\n");
            }
            html.push_str("</ul>\n");
        }
        if let Some(hidden) = &hidden {
            let _ = writeln!(html, "<p>{}</p>", escape(hidden));
        }
        let _ = writeln!(
            html,
            "<p><a href=\"{}\">{}</a></p>",
            escape(&self.organization.url),
            open.html
        );
        let _ = write!(
            html,
            "<hr style=\"border: none; border-top: 1px solid #d0d7de;\">\n\
             <p style=\"font-size: 12px; color: #59636e;\">{} <a href=\"{}\">{}</a></p>\n</body>\n</html>\n",
            footer.html,
            escape(&settings),
            escape(&settings),
        );
        Message {
            to: Vec::new(),
            subject: value(&subject, SUBJECT_LIMIT),
            text,
            html,
        }
    }
}

/// A link to a page below the organization's page.
fn link_in(organization_url: &str, path: &str) -> String {
    format!("{}/{path}", organization_url.trim_end_matches('/'))
}

/// The email of a `findings.new` document.
pub fn new_findings(payload: &NewFindingsPayload, language: Language) -> Message {
    let locale = language.locale();
    let frame = Frame {
        organization: &payload.organization,
        locale,
        language,
    };
    let organization = frame.organization_name();
    // One project: the subject names it, as `organization/project`.
    let mut projects = payload.findings.iter().map(|finding| &finding.project);
    let place = match projects.next() {
        Some(first) if projects.all(|project| project == first) => format!(
            "{}/{}",
            value(&payload.organization.slug, NAME_LIMIT),
            value(first, NAME_LIMIT)
        ),
        _ => organization.clone(),
    };
    let subject = t!(
        "email.new_findings_subject",
        count = payload.count,
        place = place,
        locale = locale
    )
    .to_string();
    let headline = t!(
        "email.new_findings_headline",
        count = payload.count,
        organization = organization,
        locale = locale
    )
    .to_string();
    let mut summary = fill(
        t!("email.highest_severity", locale = locale),
        &[("severity", severity(payload.highest_severity, locale))],
    );
    if payload.known_exploited_count > 0 {
        summary.push_str(", ");
        let _ = write!(
            summary,
            "{}",
            t!(
                "email.known_exploited_count",
                count = payload.known_exploited_count,
                locale = locale
            )
        );
    }
    let items: Vec<(Vec<Line>, String)> = payload
        .findings
        .iter()
        .take(MAX_ITEMS)
        .map(|finding| {
            let mut lines = vec![Line::new(
                "{vulnerability} ({tags})",
                &[
                    ("vulnerability", &value(&finding.vulnerability, NAME_LIMIT)),
                    ("tags", &tags(finding, locale)),
                ],
            )];
            lines.push(Line::new(
                t!("email.component_in_project", locale = locale),
                &[
                    ("component", &value(&finding.component, COMPONENT_LIMIT)),
                    ("project", &value(&finding.project, NAME_LIMIT)),
                ],
            ));
            if let Some((names, more)) =
                chat::versions(finding, t!("email.unnamed_version", locale = locale))
            {
                let mut names: Vec<String> =
                    names.iter().map(|name| value(name, NAME_LIMIT)).collect();
                if more > 0 {
                    names.push(t!("email.more_names", count = more, locale = locale).to_string());
                }
                lines.push(Line::new(
                    t!("email.versions", locale = locale),
                    &[("names", &names.join(", "))],
                ));
            }
            if let Some(summary) = &finding.summary {
                lines.push(Line::new(
                    "{summary}",
                    &[("summary", &value(summary, SUMMARY_LIMIT))],
                ));
            }
            if !finding.introduced_via.is_empty() {
                let mut names: Vec<String> = finding
                    .introduced_via
                    .iter()
                    .take(VIA_NAMES)
                    .map(|name| value(name, NAME_LIMIT))
                    .collect();
                let more = finding.introduced_via.len().saturating_sub(VIA_NAMES);
                if more > 0 {
                    names.push(t!("email.more_names", count = more, locale = locale).to_string());
                }
                lines.push(Line::new(
                    t!("email.introduced_via", locale = locale),
                    &[("names", &names.join(", "))],
                ));
            }
            (lines, finding.url.clone())
        })
        .collect();
    let hidden = payload.findings.len().saturating_sub(MAX_ITEMS);
    let hidden = (hidden > 0)
        .then(|| t!("email.hidden_findings", count = hidden, locale = locale).to_string());
    frame.message(
        subject,
        &headline,
        Some(Line::new("{summary}", &[("summary", &summary)])),
        &items,
        hidden,
    )
}

/// The email of a `projects.stale` document.
pub fn stale_projects(payload: &StaleProjectsPayload, language: Language) -> Message {
    let locale = language.locale();
    let frame = Frame {
        organization: &payload.organization,
        locale,
        language,
    };
    let organization = frame.organization_name();
    let count = payload.projects.len();
    let subject = t!(
        "email.stale_subject",
        count = count,
        organization = organization,
        locale = locale
    )
    .to_string();
    let headline = t!(
        "email.stale_headline",
        count = count,
        organization = organization,
        locale = locale
    )
    .to_string();
    let items: Vec<(Vec<Line>, String)> = payload
        .projects
        .iter()
        .take(MAX_ITEMS)
        .map(|project| {
            let upload = project.last_upload_at.map_or_else(
                || t!("email.never_uploaded", locale = locale).to_owned(),
                |time| {
                    fill(
                        t!("email.last_upload", locale = locale),
                        &[("time", &utc(time))],
                    )
                },
            );
            (
                vec![Line::new(
                    "{project} ({upload})",
                    &[
                        ("project", &value(&project.project, NAME_LIMIT)),
                        ("upload", &upload),
                    ],
                )],
                project.url.clone(),
            )
        })
        .collect();
    let hidden = count.saturating_sub(MAX_ITEMS);
    let hidden = (hidden > 0)
        .then(|| t!("email.hidden_projects", count = hidden, locale = locale).to_string());
    frame.message(subject, &headline, None, &items, hidden)
}

/// The test email of an organization's settings, to `recipients`. The organization's name is
/// shown as given: [`send_test`] passes its slug, so that users cannot put text of their own in
/// a message sent on demand to addresses nobody verified.
pub fn test_message(
    organization: &PayloadOrganization,
    recipients: &[String],
    language: Language,
) -> Message {
    let locale = language.locale();
    let frame = Frame {
        organization,
        locale,
        language,
    };
    let name = frame.organization_name();
    let headline = fill(
        t!("email.test_headline", locale = locale),
        &[("organization", &name)],
    );
    let body = Line::new(
        t!("email.test_body", locale = locale),
        &[("recipients", &recipients.join(", "))],
    );
    let mut message = frame.message(
        t!("email.test_subject", locale = locale).to_owned(),
        &headline,
        Some(body),
        &[],
        None,
    );
    message.to = recipients.to_vec();
    message
}

// ---------------------------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------------------------

/// Why the SMTP settings of the instance cannot work. The messages never repeat the SMTP URL,
/// which may hold a password.
#[derive(Debug, thiserror::Error)]
pub enum ConfigurationError {
    #[error("invalid SMTP URL (NANOBOM_SMTP_URL): {0}")]
    Url(String),
    #[error("invalid sender address (NANOBOM_SMTP_FROM): {0}")]
    From(String),
    #[error(
        "NANOBOM_SMTP_URL has credentials but no TLS: plain smtp:// would send them in clear \
         text; use smtps://, or add ?tls=required (STARTTLS) to the URL"
    )]
    CredentialsWithoutTls,
}

/// Refuses credentials over a connection that may stay in clear text: lettre's `smtp://`
/// without `tls=` never starts TLS, yet authenticates with the user and password of the URL.
fn check_tls(url: &str) -> std::result::Result<(), ConfigurationError> {
    // An unparsable URL is left to lettre, whose error is reported instead.
    let Ok(parsed) = Url::parse(url) else {
        return Ok(());
    };
    let has_credentials = !parsed.username().is_empty() || parsed.password().is_some();
    let tls = parsed
        .query_pairs()
        .find(|(key, _)| key == "tls")
        .map(|(_, value)| value.into_owned());
    let encrypted =
        parsed.scheme() != "smtp" || matches!(tls.as_deref(), Some("required" | "opportunistic"));
    if has_credentials && !encrypted {
        return Err(ConfigurationError::CredentialsWithoutTls);
    }
    Ok(())
}

/// When test emails were sent, to enforce the limits of [`Mailer`].
#[derive(Debug, Default)]
struct TestLog {
    organizations: HashMap<i64, Instant>,
    users: HashMap<i64, Instant>,
    /// The test emails of the instance in the last [`TEST_WINDOW`], the oldest first.
    instance: VecDeque<Instant>,
}

/// Sends emails through the SMTP server of the instance, and test emails at most once per
/// [`TEST_INTERVAL`] per organization and per user, and [`TEST_LIMIT`] per [`TEST_WINDOW`] for
/// the instance. Each message opens its own connection: emails are rare (a few per run), so a
/// pool would only hold idle connections.
#[derive(Clone)]
pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    tests: Arc<Mutex<TestLog>>,
}

/// Leaves the transport out: it holds the SMTP credentials.
impl std::fmt::Debug for Mailer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Mailer")
            .field("from", &self.from.to_string())
            .finish_non_exhaustive()
    }
}

impl Mailer {
    /// A mailer for an SMTP URL in lettre's syntax (`smtps://user:password@host`,
    /// `smtp://host:25?tls=required`...) and a sender (`nanobom@example.org` or
    /// `nanobom <nanobom@example.org>`). Nothing is contacted yet. A `smtp://` URL with
    /// credentials must set `tls=required` or `tls=opportunistic`.
    pub fn new(url: &str, from: &str) -> std::result::Result<Self, ConfigurationError> {
        let from: Mailbox =
            from.trim()
                .parse()
                .map_err(|error: lettre::address::AddressError| {
                    ConfigurationError::From(error.to_string())
                })?;
        check_tls(url.trim())?;
        let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(url.trim())
            .map_err(|error| ConfigurationError::Url(error.to_string()))?
            .timeout(Some(COMMAND_TIMEOUT))
            .build();
        Ok(Self {
            transport,
            from,
            tests: Arc::default(),
        })
    }

    /// Sends a message to one recipient, and tells how the server replied. The `To` header
    /// lists the message's [`Message::to`] (the recipient alone when it is empty); the envelope
    /// holds `recipient` only.
    pub async fn send(&self, recipient: &str, message: &Message) -> Attempt {
        let address = match recipient.parse::<Address>() {
            Ok(address) => address,
            Err(error) => {
                return Attempt::Impossible(format!("invalid recipient {recipient}: {error}"));
            }
        };
        let envelope = match Envelope::new(Some(self.from.email.clone()), vec![address]) {
            Ok(envelope) => envelope,
            Err(error) => return Attempt::Impossible(format!("invalid envelope: {error}")),
        };
        let mut builder = lettre::Message::builder()
            .from(self.from.clone())
            .subject(&message.subject)
            .envelope(envelope);
        let to = if message.to.is_empty() {
            vec![recipient.to_owned()]
        } else {
            message.to.clone()
        };
        for header in &to {
            match header.parse::<Mailbox>() {
                Ok(mailbox) => builder = builder.to(mailbox),
                Err(error) => {
                    return Attempt::Impossible(format!("invalid recipient {header}: {error}"));
                }
            }
        }
        let email = match builder.multipart(MultiPart::alternative_plain_html(
            message.text.clone(),
            message.html.clone(),
        )) {
            Ok(email) => email,
            Err(error) => return Attempt::Impossible(format!("invalid message: {error}")),
        };
        match tokio::time::timeout(SEND_TIMEOUT, self.transport.send(email)).await {
            Err(_) => Attempt::Unreachable("the SMTP server did not finish in time".to_owned()),
            Ok(Ok(response)) => {
                let code = u16::from(response.code());
                Attempt::Replied {
                    code,
                    description: format!("{code} {}", response.first_line().unwrap_or_default())
                        .trim_end()
                        .to_owned(),
                }
            }
            Ok(Err(error)) => match error.status() {
                Some(code) => Attempt::Replied {
                    code: u16::from(code),
                    description: error.to_string(),
                },
                None => Attempt::Unreachable(error.to_string()),
            },
        }
    }

    /// Sends a message stored in a delivery: `recipient` its one address, `payload` a
    /// [`Message`] as JSON.
    pub async fn send_stored(&self, recipient: &str, payload: &str) -> Attempt {
        let Ok(message) = serde_json::from_str::<Message>(payload) else {
            return Attempt::Impossible("the stored email cannot be read".to_owned());
        };
        self.send(recipient.trim(), &message).await
    }

    /// Records a test email of an organization by a user now, unless it would exceed a limit
    /// (see [`Mailer`]); returns the seconds left to wait then. A refused test is not recorded.
    fn allow_test(&self, organization_id: i64, user_id: i64) -> std::result::Result<(), u64> {
        self.allow_test_at(organization_id, user_id, Instant::now())
    }

    fn allow_test_at(
        &self,
        organization_id: i64,
        user_id: i64,
        now: Instant,
    ) -> std::result::Result<(), u64> {
        let mut tests = self.tests.lock().expect("not poisoned");
        let TestLog {
            organizations,
            users,
            instance,
        } = &mut *tests;
        organizations.retain(|_, sent| now.duration_since(*sent) < TEST_INTERVAL);
        users.retain(|_, sent| now.duration_since(*sent) < TEST_INTERVAL);
        while instance
            .front()
            .is_some_and(|sent| now.duration_since(*sent) >= TEST_WINDOW)
        {
            instance.pop_front();
        }
        let interval_left =
            |sent: &Instant| TEST_INTERVAL.saturating_sub(now.duration_since(*sent));
        let mut wait = [
            organizations.get(&organization_id).map(interval_left),
            users.get(&user_id).map(interval_left),
        ]
        .into_iter()
        .flatten()
        .max();
        if instance.len() >= TEST_LIMIT
            && let Some(oldest) = instance.front()
        {
            let left = TEST_WINDOW.saturating_sub(now.duration_since(*oldest));
            wait = wait.max(Some(left));
        }
        if let Some(wait) = wait {
            return Err(wait.as_secs().max(1));
        }
        organizations.insert(organization_id, now);
        users.insert(user_id, now);
        instance.push_back(now);
        Ok(())
    }
}

/// Sends a test email to each saved recipient of an organization, at once, and fails with the
/// SMTP server's replies to the recipients it did not accept. Requires
/// [`Permission::ManageWebhook`]; limited as [`Mailer`] says, whether it succeeded or not.
pub async fn send_test(
    database: &impl ConnectionTrait,
    actor: &Actor,
    organization_id: i64,
    mailer: Option<&Mailer>,
    public_url: &Url,
) -> Result<()> {
    actor
        .authorize(database, organization_id, Permission::ManageWebhook)
        .await?;
    let mailer = mailer.ok_or(Error::invalid(Problem::EmailNotConfigured))?;
    let settings = settings(database, organization_id)
        .await?
        .ok_or(Error::invalid(Problem::NoRecipients))?;
    let organization = organizations::Entity::find_by_id(organization_id)
        .one(database)
        .await?
        .ok_or(Error::NotFound)?;
    mailer
        .allow_test(organization_id, actor.user_id)
        .map_err(|seconds| Error::conflict(Problem::TestEmailTooSoon { seconds }))?;
    // The slug, not the display name: the name is free text of the user's choosing.
    let organization = PayloadOrganization {
        url: link(public_url, &format!("organizations/{}", organization.slug)),
        name: organization.slug.clone(),
        slug: organization.slug,
    };
    let message = test_message(&organization, &settings.recipients, settings.language);
    let mut failures = Vec::new();
    for recipient in &settings.recipients {
        let attempt = mailer.send(recipient, &message).await;
        if attempt.succeeded() {
            continue;
        }
        failures.push(format!("{recipient}: {}", attempt.description()));
        // No reply at all: the server is unreachable for the others too.
        if matches!(attempt, Attempt::Unreachable(_)) {
            break;
        }
    }
    if failures.is_empty() {
        tracing::info!(organization = organization_id, "test email sent");
        Ok(())
    } else {
        let detail = failures.join("; ");
        tracing::warn!(
            organization = organization_id,
            status = %detail,
            "test email failed"
        );
        Err(Error::invalid(Problem::TestEmailFailed { detail }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_are_filled_once() {
        assert_eq!(
            fill("{a} and {b} {c}", &[("a", "{b}"), ("b", "two")]),
            "{b} and two {c}"
        );
        assert_eq!(fill("{unclosed", &[("unclosed", "x")]), "{unclosed");
    }

    #[test]
    fn recipients_are_split_and_validated() {
        let typed: Vec<String> = split_recipients("a@example.org, b@example.org;\nA@example.org")
            .map(str::to_owned)
            .collect();
        assert_eq!(
            validate_recipients(&typed).unwrap(),
            ["a@example.org", "b@example.org"]
        );
        assert!(matches!(
            validate_recipients(&["not an address".to_owned()]),
            Err(Error::Invalid(Problem::InvalidRecipient { .. }))
        ));
        assert!(matches!(
            validate_recipients(&["Name <a@example.org>".to_owned()]),
            Err(Error::Invalid(Problem::InvalidRecipient { .. }))
        ));
        assert!(matches!(
            validate_recipients(&[]),
            Err(Error::Invalid(Problem::NoRecipients))
        ));
        let many: Vec<String> = (0..=MAX_RECIPIENTS)
            .map(|index| format!("user{index}@example.org"))
            .collect();
        assert!(matches!(
            validate_recipients(&many),
            Err(Error::Invalid(Problem::TooManyRecipients { .. }))
        ));
    }

    #[test]
    fn invalid_smtp_settings_fail_without_the_url() {
        let error =
            Mailer::new("smtps://user:secret@smtp.example.org", "not an address").unwrap_err();
        assert!(matches!(error, ConfigurationError::From(_)));
        let error =
            Mailer::new("ftp://user:secret@smtp.example.org", "nanobom@example.org").unwrap_err();
        assert!(!error.to_string().contains("secret"), "{error}");
        let mailer = Mailer::new(
            "smtps://user:secret@smtp.example.org",
            "nanobom <nanobom@example.org>",
        )
        .unwrap();
        assert!(!format!("{mailer:?}").contains("secret"));
    }

    #[test]
    fn credentials_need_tls() {
        for url in [
            "smtp://user:secret@smtp.example.org:587",
            "smtp://user@smtp.example.org",
            "smtp://user:secret@smtp.example.org:587?tls=none",
        ] {
            let error = Mailer::new(url, "nanobom@example.org").unwrap_err();
            assert!(
                matches!(error, ConfigurationError::CredentialsWithoutTls),
                "{url}: {error}"
            );
            assert!(!error.to_string().contains("secret"), "{error}");
        }
        for url in [
            "smtp://user:secret@smtp.example.org:587?tls=required",
            "smtp://user:secret@smtp.example.org:587?tls=opportunistic",
            "smtps://user:secret@smtp.example.org",
            "smtp://relay.internal:25",
        ] {
            assert!(Mailer::new(url, "nanobom@example.org").is_ok(), "{url}");
        }
    }

    #[test]
    fn test_emails_are_limited_per_organization_user_and_instance() {
        let mailer = Mailer::new("smtp://relay.internal:25", "nanobom@example.org").unwrap();
        let start = Instant::now();
        mailer.allow_test_at(1, 1, start).unwrap();
        // The same organization by another user, another organization by the same user.
        assert!(mailer.allow_test_at(1, 2, start).is_err());
        let left = mailer.allow_test_at(2, 1, start).unwrap_err();
        assert_eq!(left, TEST_INTERVAL.as_secs());
        // Refused tests are not recorded: another user and organization still can.
        mailer.allow_test_at(2, 2, start).unwrap();
        let later = start + TEST_INTERVAL;
        mailer.allow_test_at(1, 1, later).unwrap();

        // The instance: TEST_LIMIT tests in the window, whoever sends them.
        let mut tests = 3;
        let mut id = 10;
        while tests < TEST_LIMIT {
            mailer.allow_test_at(id, id, later).unwrap();
            tests += 1;
            id += 1;
        }
        let left = mailer.allow_test_at(id, id, later).unwrap_err();
        assert_eq!(left, (TEST_WINDOW - TEST_INTERVAL).as_secs());
        // Once the oldest leave the window, tests are allowed again, and the log only keeps
        // what still counts.
        mailer.allow_test_at(id, id, start + TEST_WINDOW).unwrap();
        let log = mailer.tests.lock().unwrap();
        assert_eq!(log.instance.len(), TEST_LIMIT - 1);
        assert_eq!(log.organizations.len(), 1);
        assert_eq!(log.users.len(), 1);
    }
}
