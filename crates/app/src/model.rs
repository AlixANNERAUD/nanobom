//! What the pages show. These types travel from server functions to components, so they are
//! defined here, independent of the server-only domain crate.
//!
//! They also compile for the browser bundle, which cannot link the domain crate (it pulls in
//! the database driver). [`Severity`], [`Status`], [`Role`], [`DeliveryState`] and
//! [`LicenseAction`] therefore mirror domain enumerations: keep them in sync, along with the conversions in
//! `crate::server`.
//!
//! Nothing here grants anything: methods such as [`Role::can_manage`] only decide which
//! controls a page shows. The domain checks every action again.

/// The error a server function returns while it redirects to the sign-in page; never shown.
pub const SIGN_IN_REQUIRED: &str = "sign in required";

use chrono::{DateTime, FixedOffset, NaiveDate};
use serde::{Deserialize, Serialize};

use crate::t;

/// Mirror of `nanobom_osv::Severity`, ordered from the least to the most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const DESCENDING: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Unknown,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Unknown => "unknown",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// The name shown in the interface, in the request's language.
    pub fn label(self) -> &'static str {
        match self {
            Severity::Unknown => t!("severity.unknown"),
            Severity::Low => t!("severity.low"),
            Severity::Medium => t!("severity.medium"),
            Severity::High => t!("severity.high"),
            Severity::Critical => t!("severity.critical"),
        }
    }

    /// Parses the name used in query strings ([`Severity::as_str`]).
    pub fn parse(value: &str) -> Option<Self> {
        Self::DESCENDING
            .into_iter()
            .find(|severity| severity.as_str() == value)
    }
}

/// Mirror of `nanobom_domain::findings::Status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Open,
    Ignored,
    Fixed,
}

impl Status {
    pub const ALL: [Status; 3] = [Status::Open, Status::Ignored, Status::Fixed];

    pub fn as_str(self) -> &'static str {
        match self {
            Status::Open => "open",
            Status::Ignored => "ignored",
            Status::Fixed => "fixed",
        }
    }

    /// The name shown in the interface, in the request's language.
    pub fn label(self) -> &'static str {
        match self {
            Status::Open => t!("status.open"),
            Status::Ignored => t!("status.ignored"),
            Status::Fixed => t!("status.fixed"),
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|status| status.as_str() == value)
    }
}

/// Mirror of `nanobom_domain::access::Role`, ordered from the least to the most privileged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer,
    Member,
    Admin,
    Owner,
}

impl Role {
    pub const ALL: [Role; 4] = [Role::Viewer, Role::Member, Role::Admin, Role::Owner];

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Member => "member",
            Role::Admin => "admin",
            Role::Owner => "owner",
        }
    }

    /// The name shown in the interface, in the request's language.
    pub fn label(self) -> &'static str {
        match self {
            Role::Viewer => t!("role.viewer"),
            Role::Member => t!("role.member"),
            Role::Admin => t!("role.admin"),
            Role::Owner => t!("role.owner"),
        }
    }

    /// Whether to show the controls to ignore and restore findings and to start runs.
    pub fn can_triage(self) -> bool {
        self >= Role::Member
    }

    /// Whether to show the organization's settings (members, tokens, webhook, projects).
    pub fn can_manage(self) -> bool {
        self >= Role::Admin
    }
}

/// The signed-in user, for the header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrentUser {
    pub username: String,
    pub display_name: String,
    pub is_instance_administrator: bool,
    pub organizations: Vec<Organization>,
}

/// How users can sign in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignInOptions {
    pub local_accounts: bool,
    /// The label of the single sign-on button, when OpenID Connect is configured.
    pub openid_button: Option<String>,
    pub signed_in: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    pub slug: String,
    pub name: String,
    pub is_personal: bool,
    pub role: Role,
}

/// Open findings by severity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub unknown: u64,
}

impl SeverityCounts {
    pub fn get(&self, severity: Severity) -> u64 {
        match severity {
            Severity::Critical => self.critical,
            Severity::High => self.high,
            Severity::Medium => self.medium,
            Severity::Low => self.low,
            Severity::Unknown => self.unknown,
        }
    }

    pub fn total(&self) -> u64 {
        self.critical + self.high + self.medium + self.low + self.unknown
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRow {
    pub slug: String,
    pub name: String,
    pub last_upload_at: Option<DateTime<FixedOffset>>,
    pub open: SeverityCounts,
    pub ignored: u64,
    /// Open findings with a known exploited CVE.
    pub known_exploited: i64,
    /// No SBOM for longer than the configured threshold.
    pub stale: bool,
    /// Components breaking the organization's license policy; zero without a policy.
    pub licenses: LicenseCounts,
}

/// Mirror of `nanobom_domain::licenses::Action`, from the least to the most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseAction {
    Allow,
    Warn,
    Forbid,
}

impl LicenseAction {
    pub const ALL: [LicenseAction; 3] = [
        LicenseAction::Allow,
        LicenseAction::Warn,
        LicenseAction::Forbid,
    ];

    /// The name sent by forms, as the domain parses it.
    pub fn as_str(self) -> &'static str {
        match self {
            LicenseAction::Allow => "allow",
            LicenseAction::Warn => "warn",
            LicenseAction::Forbid => "forbid",
        }
    }

    /// The name shown in the interface, in the request's language.
    pub fn label(self) -> &'static str {
        match self {
            LicenseAction::Allow => t!("licenses.allow"),
            LicenseAction::Warn => t!("licenses.warn"),
            LicenseAction::Forbid => t!("licenses.forbid"),
        }
    }
    /// The verdict on a component, in the request's language.
    pub fn verdict(self) -> &'static str {
        match self {
            LicenseAction::Allow => t!("licenses.allowed"),
            LicenseAction::Warn => t!("licenses.warned"),
            LicenseAction::Forbid => t!("licenses.forbidden"),
        }
    }
}

/// Components breaking a license policy, by verdict.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseCounts {
    pub forbidden: u64,
    pub warned: u64,
}

/// An organization's license policy, with its rules split by action as the settings form
/// edits them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicensePolicy {
    pub unlisted: LicenseAction,
    pub unknown: LicenseAction,
    pub allowed: Vec<String>,
    pub warned: Vec<String>,
    pub forbidden: Vec<String>,
}

/// A component whose license the policy forbids or warns about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseViolation {
    pub purl: String,
    pub name: String,
    pub version: Option<String>,
    /// As read from the SBOM.
    pub license: Option<String>,
    pub verdict: LicenseAction,
    /// The identifiers that lead to the verdict; empty when the action for unknown licenses alone
    /// gives it.
    pub licenses: Vec<String>,
}

/// The license violations of a project, when its organization has a policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseViolations {
    pub counts: LicenseCounts,
    /// Forbidden first, then warned, at most [`LicenseViolations::LISTED`].
    pub items: Vec<LicenseViolation>,
}

impl LicenseViolations {
    /// Violations listed on the project page; the read API pages through all of them.
    pub const LISTED: usize = 200;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    pub id: i64,
    pub trigger: String,
    pub scope: String,
    pub status: String,
    pub started_at: DateTime<FixedOffset>,
    pub finished_at: Option<DateTime<FixedOffset>>,
    /// For instance-wide runs, a generic message unless the viewer is an instance
    /// administrator.
    pub error: Option<String>,
    /// `None` for instance-wide runs, unless the viewer is an instance administrator: the
    /// counts span every organization.
    pub new_findings: Option<i64>,
    pub fixed_findings: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationData {
    pub organization: Organization,
    pub projects: Vec<ProjectRow>,
    pub runs: Vec<Run>,
}

/// Exploitation data (CISA KEV and FIRST EPSS) of a finding.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Exploitation {
    pub known_exploited: bool,
    pub kev_date_added: Option<NaiveDate>,
    pub kev_due_date: Option<NaiveDate>,
    pub kev_ransomware: bool,
    /// Probability of exploitation in the next 30 days, from 0 to 1.
    pub epss_score: Option<f64>,
    /// Share of scored CVEs with a lower score, from 0 to 1.
    pub epss_percentile: Option<f64>,
    pub epss_date: Option<NaiveDate>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingRow {
    pub id: i64,
    /// The project version the finding belongs to; empty for the unnamed version.
    pub version: String,
    pub component_name: String,
    pub component_version: Option<String>,
    /// `None` when the latest SBOM gives no license, or no longer has the component.
    pub license: Option<String>,
    pub ecosystem: String,
    pub purl: String,
    pub vulnerability_id: String,
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub severity: Severity,
    pub cvss_score: Option<f64>,
    pub status: Status,
    pub first_seen_at: DateTime<FixedOffset>,
    pub fixed_at: Option<DateTime<FixedOffset>>,
    pub ignore_reason: Option<String>,
    pub ignore_expires_at: Option<DateTime<FixedOffset>>,
    /// The CycloneDX name of the ignore's justification (`code_not_reachable`…), or
    /// `false_positive`.
    pub ignore_justification: Option<String>,
    pub exploitation: Exploitation,
    /// The project's direct dependencies that lead to the component, sorted by name; empty
    /// when the SBOM's dependency graph does not say.
    pub introduced_via: Vec<DependencyComponent>,
}

/// A component of a dependency path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyComponent {
    pub purl: String,
    pub name: String,
    pub version: Option<String>,
}

/// How the project pulls in a finding's component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyPaths {
    /// From a direct dependency to the component, shortest first; empty when the graph does not
    /// link the component to the project.
    pub paths: Vec<Vec<DependencyComponent>>,
    /// Direct dependencies leading to the component beyond those of `paths`.
    pub more: usize,
    /// Whether links of the graph could not be followed, so other paths may exist.
    pub partial: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upload {
    /// The project version uploaded to; empty for the unnamed version.
    pub version: String,
    pub uploaded_at: DateTime<FixedOffset>,
    pub specification_version: String,
    pub source_commit: Option<String>,
    pub image_tag: Option<String>,
    pub component_count: i64,
    pub components_without_purl: i64,
}

/// Filters of the project page, from its query string.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingFilter {
    pub severity: Option<String>,
    pub status: Option<String>,
    pub ecosystem: Option<String>,
    /// Only known exploited findings (`exploited=1`).
    pub exploited: bool,
    /// The project version shown (`version=`, empty for the unnamed version); the latest when
    /// `None`.
    pub version: Option<String>,
}

/// A version of a project, for the version selector and the versions table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionOption {
    /// Empty for the unnamed version.
    pub name: String,
    pub latest: bool,
    /// Whether runs evaluate the version; inactive ones stay readable.
    pub active: bool,
    pub last_upload_at: Option<DateTime<FixedOffset>>,
    /// Open findings of the version.
    pub open: SeverityCounts,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProjectData {
    pub organization: Organization,
    pub slug: String,
    pub name: String,
    pub findings: Vec<FindingRow>,
    pub ecosystems: Vec<String>,
    /// The latest uploads of the project, every version included.
    pub uploads: Vec<Upload>,
    /// The project's versions, newest first.
    pub versions: Vec<VersionOption>,
    /// The version shown, which findings, components and license violations are about.
    pub version: VersionOption,
    /// The latest upload of the version shown.
    pub version_upload: Option<Upload>,
    pub component_count: usize,
    pub last_upload_at: Option<DateTime<FixedOffset>>,
    pub created_at: DateTime<FixedOffset>,
    pub stale: bool,
    /// `None` when the organization has no active license policy.
    pub licenses: Option<LicenseViolations>,
    /// The open findings of the version shown by severity. Unlike `findings`, they do not
    /// follow the filters: the summary describes the version, the table what was asked of it.
    pub counts: SeverityCounts,
    /// How many open findings of the version shown are known exploited, whatever the filters.
    pub known_exploited: i64,
}

/// A reference of an advisory. Its address is written by the advisory's author: see
/// [`Reference::target`] before linking to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reference {
    pub kind: String,
    pub url: String,
}

impl Reference {
    /// The address as a link target, or `None` when it must be shown as text only.
    pub fn target(&self) -> Option<&str> {
        link_target(&self.url)
    }
}

/// The target of a link to an address taken from an advisory, or `None` when the address must
/// not become a link: only complete web addresses and `mailto:` are followed. The check is an
/// allow-list on purpose. `javascript:` and `data:` addresses run or show what their author
/// chose within the page; relative addresses would lead into nanobom itself.
///
/// The address is trimmed and the result is what was checked: write the result, not the
/// address. A browser removes tabs and line breaks from an address, and control characters
/// before it, prior to reading its scheme; an address holding any control character is refused
/// rather than interpreted the same way.
pub fn link_target(address: &str) -> Option<&str> {
    let address = address.trim();
    let starts_with = |prefix: &str| {
        address
            .get(..prefix.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
    };
    let allowed = ["http://", "https://", "mailto:"]
        .into_iter()
        .any(starts_with);
    (allowed && !address.chars().any(char::is_control)).then_some(address)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffectedComponent {
    pub finding_id: i64,
    pub organization_slug: String,
    pub project_slug: String,
    /// The project version; empty for the unnamed version.
    pub version: String,
    pub purl: String,
    pub status: Status,
}

/// A version of a finding's project and its status for the finding's vulnerability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionFinding {
    /// Empty for the unnamed version.
    pub name: String,
    pub latest: bool,
    pub active: bool,
    /// The finding's own version.
    pub current: bool,
    /// `None` when the version never had a finding for the vulnerability.
    pub status: Option<Status>,
    pub finding_id: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingEvent {
    pub created_at: DateTime<FixedOffset>,
    /// `opened`, `fixed`, `reopened`, `ignored`, `restored`, `ignore_expired` or `inherited`.
    pub kind: String,
    pub actor: Option<String>,
    /// The upload token that imported a VEX statement.
    pub token: Option<String>,
    pub reason: Option<String>,
    /// The CycloneDX name of the ignore's justification, or `false_positive`.
    pub justification: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FindingData {
    pub finding: FindingRow,
    pub organization_slug: String,
    pub project_slug: String,
    /// Whether the viewer may ignore or restore this finding (shows the controls only).
    pub can_triage: bool,
    /// The advisory's text as HTML, inserted into the page as it is: only ever the result of
    /// `markdown::render` (a server-only module), which makes untrusted Markdown harmless.
    /// `None` when the advisory has no text.
    pub details_html: Option<String>,
    pub published: Option<DateTime<FixedOffset>>,
    pub modified: DateTime<FixedOffset>,
    pub cvss_version: Option<String>,
    pub cvss_vector: Option<String>,
    pub fixed_versions: Vec<String>,
    pub references: Vec<Reference>,
    pub ignored_by: Option<String>,
    /// The upload token that ignored the finding from a VEX document.
    pub ignored_by_token: Option<String>,
    /// Other findings filed under the same identifier, in organizations the viewer can see.
    pub affected_components: Vec<AffectedComponent>,
    /// Every version of the project, newest first.
    pub versions: Vec<VersionFinding>,
    pub events: Vec<FindingEvent>,
    /// `None` when the latest SBOM did not say which components the project depends on
    /// directly.
    pub dependency_paths: Option<DependencyPaths>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentMatch {
    pub organization_slug: String,
    pub project_slug: String,
    /// The project version; empty for the unnamed version.
    pub project_version: String,
    pub project_version_active: bool,
    pub purl: String,
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
    pub license: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub user_id: i64,
    pub username: String,
    pub display_name: String,
    pub email: Option<String>,
    pub role: Role,
    pub manual_role: Option<Role>,
    pub synchronized_role: Option<Role>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadToken {
    pub id: i64,
    pub name: String,
    pub prefix: String,
    pub project_slug: Option<String>,
    /// A read token, which cannot upload.
    pub read_only: bool,
    pub created_at: DateTime<FixedOffset>,
    pub last_used_at: Option<DateTime<FixedOffset>>,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Webhook {
    pub url: String,
    pub minimum_severity: Severity,
    pub enabled: bool,
    pub exploited_only: bool,
    /// `json`, `slack` or `teams`: the names of `nanobom_domain::notifications::Format`.
    pub format: String,
}

/// Where an organization's notifications are emailed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailSettings {
    pub recipients: Vec<String>,
    /// `en` or `fr`: the tags of `nanobom_domain::email::Language`.
    pub language: String,
    pub minimum_severity: Severity,
    pub exploited_only: bool,
}

/// Where a webhook or email delivery stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryState {
    /// The first attempt is about to be made or in progress.
    Sending,
    /// Another attempt is scheduled.
    Pending,
    Delivered,
    /// Refused by the receiver, or every retry failed.
    Failed,
    /// Cancelled before any attempt was recorded.
    Cancelled,
}

impl DeliveryState {
    /// The name shown in the interface, in the request's language.
    pub fn label(self) -> &'static str {
        match self {
            DeliveryState::Sending => t!("settings.delivery_sending"),
            DeliveryState::Pending => t!("settings.delivery_pending"),
            DeliveryState::Delivered => t!("settings.delivery_delivered"),
            DeliveryState::Failed => t!("settings.delivery_failed"),
            DeliveryState::Cancelled => t!("settings.delivery_cancelled"),
        }
    }
}

/// A recent delivery of the organization's notifications, to its webhook or by email.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookDelivery {
    pub id: i64,
    /// The recipient of an email; `None` for a webhook post.
    pub recipient: Option<String>,
    pub event: String,
    pub state: DeliveryState,
    pub attempts: i64,
    pub created_at: DateTime<FixedOffset>,
    pub last_attempt_at: Option<DateTime<FixedOffset>>,
    pub last_status: Option<String>,
    pub next_attempt_at: Option<DateTime<FixedOffset>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsData {
    pub organization: Organization,
    pub current_user_id: i64,
    pub members: Vec<Member>,
    pub tokens: Vec<UploadToken>,
    pub projects: Vec<String>,
    pub webhook: Option<Webhook>,
    pub email: Option<EmailSettings>,
    /// Whether the instance sends email (an SMTP server is configured).
    pub email_available: bool,
    /// The latest deliveries to the webhook and by email, the newest first.
    pub deliveries: Vec<WebhookDelivery>,
    pub license_policy: LicensePolicy,
    /// A token created just before, shown once.
    pub new_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRow {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub email: Option<String>,
    pub is_instance_administrator: bool,
    pub is_disabled: bool,
    pub has_password: bool,
    pub last_login_at: Option<DateTime<FixedOffset>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdministrationData {
    pub current_user_id: i64,
    pub users: Vec<UserRow>,
    pub organizations: Vec<Organization>,
    pub local_accounts: bool,
    pub password_minimum_length: usize,
}

#[cfg(test)]
mod tests {
    use super::link_target;

    #[test]
    fn web_and_mail_addresses_are_link_targets() {
        for address in [
            "http://example.org",
            "https://example.org/a?b=1&c=2#d",
            "HTTPS://EXAMPLE.ORG",
            "hTtP://example.org",
            "https://example.org/a b",
            "https://example.org/é",
            "mailto:security@example.org",
            "MAILTO:security@example.org?subject=x",
        ] {
            assert_eq!(link_target(address), Some(address), "{address}");
        }
        assert_eq!(
            link_target("  https://example.org\n"),
            Some("https://example.org")
        );
        // Whitespace around the address is not part of the target, whatever its kind.
        for address in [
            "\u{a0}https://example.org\u{3000}",
            "https://example.org\u{85}",
        ] {
            assert_eq!(link_target(address), Some("https://example.org"));
        }
    }

    #[test]
    fn other_addresses_are_not_link_targets() {
        for address in [
            "",
            " ",
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            " javascript:alert(1)",
            "\tjavascript:alert(1)",
            "\u{1}javascript:alert(1)",
            "java\tscript:alert(1)",
            "java\nscript:alert(1)",
            "javascript://example.org/%0Aalert(1)",
            "data:text/html,hi",
            "vbscript:x",
            "file:///etc/passwd",
            "ftp://example.org",
            "blob:https://example.org/1",
            "view-source:https://example.org",
            "//example.org",
            "/organizations",
            "../settings",
            "example.org",
            "#fragment",
            "?query",
            "http",
            "https",
            "https:",
            "https:/",
            "https:example.org",
            "https:/example.org",
            "https:\\\\example.org",
            "http:javascript:alert(1)",
            "mailto",
            // A browser drops tabs and line breaks from an address before reading its scheme, and
            // control characters before it.
            "ht\ttps://example.org",
            "https\n://example.org",
            "https://example.org/\u{0}",
            "https://example.org/\r\nx",
            "https://example.org/\u{7f}",
            "https://example.org/\u{85}x",
            "\u{1}https://example.org",
            "ht\u{200b}tps://example.org",
            "é://example.org",
            "ｈttps://example.org",
        ] {
            assert_eq!(link_target(address), None, "{address:?}");
        }
    }
}
