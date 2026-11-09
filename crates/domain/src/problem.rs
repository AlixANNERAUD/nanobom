//! Why an operation was refused, in words the user can act on. Each problem renders in every
//! embedded locale: the interface shows it in the reader's language, while the API and logs use
//! English through `Display`.
//!
//! Messages live in `crates/domain/locales/*.json` and are embedded at compile time; a key
//! missing from a locale fails the build (`strict` in the crate's `i18n!`). They are written as
//! lower-case clauses (`the project name must be 1 to 200 characters`), which the interface turns
//! into sentences.

use std::fmt;

use embedded_i18n::{Locale, t};

/// English, the language of the API and the logs.
pub const ENGLISH: Locale = Locale::new("en");

/// A value the user entered, named in [`Problem`] messages that concern it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Username,
    DisplayName,
    OrganizationSlug,
    OrganizationName,
    ProjectSlug,
    ProjectName,
    TokenName,
    SourceCommit,
    ImageTag,
}

impl Field {
    /// The field's name, as it appears inside a sentence.
    pub fn name(self, locale: Locale) -> &'static str {
        match self {
            Field::Username => t!("fields.username", locale = locale),
            Field::DisplayName => t!("fields.display_name", locale = locale),
            Field::OrganizationSlug => t!("fields.organization_slug", locale = locale),
            Field::OrganizationName => t!("fields.organization_name", locale = locale),
            Field::ProjectSlug => t!("fields.project_slug", locale = locale),
            Field::ProjectName => t!("fields.project_name", locale = locale),
            Field::TokenName => t!("fields.token_name", locale = locale),
            Field::SourceCommit => t!("fields.source_commit", locale = locale),
            Field::ImageTag => t!("fields.image_tag", locale = locale),
        }
    }
}

/// A reason to refuse an operation, carried by [`crate::Error::Invalid`] and
/// [`crate::Error::Conflict`]. Variant names follow the locale keys (`problems.<snake_case>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    InvalidSlug(Field),
    InvalidName(Field),
    InvalidLabel(Field),
    InvalidEmail,
    PasswordTooShort { minimum: usize },
    PasswordTooLong { maximum: usize },
    SbomNotJson { detail: String },
    SbomXml,
    SpdxTagValue,
    SpdxRdf,
    UnknownSbomFormat,
    UnsupportedSpecificationVersion { version: String },
    UnsupportedSpdxVersion { version: String },
    InvalidCycloneDx { detail: String },
    InvalidSpdx { detail: String },
    VexNotJson { detail: String },
    VexNotCycloneDx,
    UnsupportedVexVersion { version: String },
    InvalidVex { detail: String },
    UsernameTaken { username: String },
    EmailTaken { email: String },
    OwnAccountStatus,
    OrganizationExists { slug: String },
    LastOwner,
    UnknownUser { login: String },
    AlreadyMember { username: String },
    ProjectExists { slug: String },
    UnknownProject { slug: String },
    UnknownOrganization { slug: String },
    UnknownRole { role: String },
    UnknownSeverity,
    UnknownJustification { justification: String },
    UnknownTokenScope { scope: String },
    ReasonRequired,
    ReasonTooLong { maximum: usize },
    ExpiryNotInFuture,
    OnlyOpenCanBeIgnored,
    OnlyIgnoredCanBeRestored,
    InvalidWebhookUrl,
    WebhookScheme,
    UnknownWebhookFormat,
    InvalidRecipient { address: String },
    NoRecipients,
    TooManyRecipients { maximum: usize },
    UnknownEmailLanguage,
    EmailNotConfigured,
    TestEmailTooSoon { seconds: u64 },
    TestEmailFailed { detail: String },
    UnknownLicenseId { license: String },
    UnknownLicenseAction { action: String },
    ConflictingLicenseRule { license: String },
    TooManyLicenseRules { maximum: usize },
    InvalidVersionName { maximum: usize },
    TooManyVersions { maximum: u64 },
    LatestVersionInactive,
    InactiveVersionLatest,
    LatestVersionDeleted,
    LastVersion,
}

impl Problem {
    /// Writes the problem in a locale: the embedded locale matching it (same tag, else same
    /// language), English otherwise.
    pub fn write(&self, output: &mut impl fmt::Write, locale: Locale) -> fmt::Result {
        use Problem as P;
        match self {
            P::InvalidSlug(field) => write!(
                output,
                "{}",
                t!(
                    "problems.invalid_slug",
                    field = field.name(locale),
                    maximum = crate::names::MAXIMUM_LENGTH,
                    locale = locale
                )
            ),
            P::InvalidName(field) => write!(
                output,
                "{}",
                t!(
                    "problems.invalid_name",
                    field = field.name(locale),
                    locale = locale
                )
            ),
            P::InvalidLabel(field) => write!(
                output,
                "{}",
                t!(
                    "problems.invalid_label",
                    field = field.name(locale),
                    locale = locale
                )
            ),
            P::InvalidEmail => output.write_str(t!("problems.invalid_email", locale = locale)),
            P::PasswordTooShort { minimum } => write!(
                output,
                "{}",
                t!(
                    "problems.password_too_short",
                    minimum = minimum,
                    locale = locale
                )
            ),
            P::PasswordTooLong { maximum } => write!(
                output,
                "{}",
                t!(
                    "problems.password_too_long",
                    maximum = maximum,
                    locale = locale
                )
            ),
            P::SbomNotJson { detail } => write!(
                output,
                "{}",
                t!("problems.sbom_not_json", detail = detail, locale = locale)
            ),
            P::SbomXml => output.write_str(t!("problems.sbom_xml", locale = locale)),
            P::SpdxTagValue => output.write_str(t!("problems.spdx_tag_value", locale = locale)),
            P::SpdxRdf => output.write_str(t!("problems.spdx_rdf", locale = locale)),
            P::UnknownSbomFormat => {
                output.write_str(t!("problems.unknown_sbom_format", locale = locale))
            }
            P::UnsupportedSpecificationVersion { version } => write!(
                output,
                "{}",
                t!(
                    "problems.unsupported_specification_version",
                    version = version,
                    supported = crate::inventory::SUPPORTED_SPECIFICATION_VERSIONS.join(", "),
                    locale = locale
                )
            ),
            P::UnsupportedSpdxVersion { version } => write!(
                output,
                "{}",
                t!(
                    "problems.unsupported_spdx_version",
                    version = version,
                    supported = crate::inventory::SUPPORTED_SPDX_VERSIONS.join(", "),
                    locale = locale
                )
            ),
            P::InvalidCycloneDx { detail } => write!(
                output,
                "{}",
                t!(
                    "problems.invalid_cyclonedx",
                    detail = detail,
                    locale = locale
                )
            ),
            P::InvalidSpdx { detail } => write!(
                output,
                "{}",
                t!("problems.invalid_spdx", detail = detail, locale = locale)
            ),
            P::VexNotJson { detail } => write!(
                output,
                "{}",
                t!("problems.vex_not_json", detail = detail, locale = locale)
            ),
            P::VexNotCycloneDx => {
                output.write_str(t!("problems.vex_not_cyclonedx", locale = locale))
            }
            P::UnsupportedVexVersion { version } => write!(
                output,
                "{}",
                t!(
                    "problems.unsupported_vex_version",
                    version = version,
                    supported = crate::inventory::SUPPORTED_VEX_VERSIONS.join(", "),
                    locale = locale
                )
            ),
            P::InvalidVex { detail } => write!(
                output,
                "{}",
                t!("problems.invalid_vex", detail = detail, locale = locale)
            ),
            P::UsernameTaken { username } => write!(
                output,
                "{}",
                t!(
                    "problems.username_taken",
                    username = username,
                    locale = locale
                )
            ),
            P::EmailTaken { email } => write!(
                output,
                "{}",
                t!("problems.email_taken", email = email, locale = locale)
            ),
            P::OwnAccountStatus => {
                output.write_str(t!("problems.own_account_status", locale = locale))
            }
            P::OrganizationExists { slug } => write!(
                output,
                "{}",
                t!("problems.organization_exists", slug = slug, locale = locale)
            ),
            P::LastOwner => output.write_str(t!("problems.last_owner", locale = locale)),
            P::UnknownUser { login } => write!(
                output,
                "{}",
                t!("problems.unknown_user", login = login, locale = locale)
            ),
            P::AlreadyMember { username } => write!(
                output,
                "{}",
                t!(
                    "problems.already_member",
                    username = username,
                    locale = locale
                )
            ),
            P::ProjectExists { slug } => write!(
                output,
                "{}",
                t!("problems.project_exists", slug = slug, locale = locale)
            ),
            P::UnknownProject { slug } => write!(
                output,
                "{}",
                t!("problems.unknown_project", slug = slug, locale = locale)
            ),
            P::UnknownOrganization { slug } => write!(
                output,
                "{}",
                t!(
                    "problems.unknown_organization",
                    slug = slug,
                    locale = locale
                )
            ),
            P::UnknownRole { role } => write!(
                output,
                "{}",
                t!("problems.unknown_role", role = role, locale = locale)
            ),
            P::UnknownSeverity => {
                output.write_str(t!("problems.unknown_severity", locale = locale))
            }
            P::UnknownJustification { justification } => write!(
                output,
                "{}",
                t!(
                    "problems.unknown_justification",
                    justification = justification,
                    locale = locale
                )
            ),
            P::UnknownTokenScope { scope } => write!(
                output,
                "{}",
                t!(
                    "problems.unknown_token_scope",
                    scope = scope,
                    locale = locale
                )
            ),
            P::ReasonRequired => output.write_str(t!("problems.reason_required", locale = locale)),
            P::ReasonTooLong { maximum } => write!(
                output,
                "{}",
                t!(
                    "problems.reason_too_long",
                    maximum = maximum,
                    locale = locale
                )
            ),
            P::ExpiryNotInFuture => {
                output.write_str(t!("problems.expiry_not_in_future", locale = locale))
            }
            P::OnlyOpenCanBeIgnored => {
                output.write_str(t!("problems.only_open_can_be_ignored", locale = locale))
            }
            P::OnlyIgnoredCanBeRestored => {
                output.write_str(t!("problems.only_ignored_can_be_restored", locale = locale))
            }
            P::InvalidWebhookUrl => {
                output.write_str(t!("problems.invalid_webhook_url", locale = locale))
            }
            P::WebhookScheme => output.write_str(t!("problems.webhook_scheme", locale = locale)),
            P::UnknownWebhookFormat => {
                output.write_str(t!("problems.unknown_webhook_format", locale = locale))
            }
            P::InvalidRecipient { address } => write!(
                output,
                "{}",
                t!(
                    "problems.invalid_recipient",
                    address = address,
                    locale = locale
                )
            ),
            P::NoRecipients => output.write_str(t!("problems.no_recipients", locale = locale)),
            P::TooManyRecipients { maximum } => write!(
                output,
                "{}",
                t!(
                    "problems.too_many_recipients",
                    maximum = maximum,
                    locale = locale
                )
            ),
            P::UnknownEmailLanguage => {
                output.write_str(t!("problems.unknown_email_language", locale = locale))
            }
            P::EmailNotConfigured => {
                output.write_str(t!("problems.email_not_configured", locale = locale))
            }
            P::TestEmailTooSoon { seconds } => write!(
                output,
                "{}",
                t!(
                    "problems.test_email_too_soon",
                    seconds = seconds,
                    locale = locale
                )
            ),
            P::TestEmailFailed { detail } => write!(
                output,
                "{}",
                t!(
                    "problems.test_email_failed",
                    detail = detail,
                    locale = locale
                )
            ),
            P::UnknownLicenseId { license } => write!(
                output,
                "{}",
                t!(
                    "problems.unknown_license_id",
                    license = license,
                    locale = locale
                )
            ),
            P::UnknownLicenseAction { action } => write!(
                output,
                "{}",
                t!(
                    "problems.unknown_license_action",
                    action = action,
                    locale = locale
                )
            ),
            P::ConflictingLicenseRule { license } => write!(
                output,
                "{}",
                t!(
                    "problems.conflicting_license_rule",
                    license = license,
                    locale = locale
                )
            ),
            P::TooManyLicenseRules { maximum } => write!(
                output,
                "{}",
                t!(
                    "problems.too_many_license_rules",
                    maximum = maximum,
                    locale = locale
                )
            ),
            P::InvalidVersionName { maximum } => write!(
                output,
                "{}",
                t!(
                    "problems.invalid_version_name",
                    maximum = maximum,
                    locale = locale
                )
            ),
            P::TooManyVersions { maximum } => write!(
                output,
                "{}",
                t!(
                    "problems.too_many_versions",
                    maximum = maximum,
                    locale = locale
                )
            ),
            P::LatestVersionInactive => {
                output.write_str(t!("problems.latest_version_inactive", locale = locale))
            }
            P::InactiveVersionLatest => {
                output.write_str(t!("problems.inactive_version_latest", locale = locale))
            }
            P::LatestVersionDeleted => {
                output.write_str(t!("problems.latest_version_deleted", locale = locale))
            }
            P::LastVersion => output.write_str(t!("problems.last_version", locale = locale)),
        }
    }

    /// The problem in a locale, as [`Problem::write`] writes it.
    pub fn message(&self, locale: Locale) -> String {
        let mut message = String::new();
        // Writing into a `String` cannot fail.
        let _ = self.write(&mut message, locale);
        message
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write(formatter, ENGLISH)
    }
}
