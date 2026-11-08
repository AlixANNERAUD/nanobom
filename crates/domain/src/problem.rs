//! Why an operation was refused, in words the user can act on. Each problem renders in every
//! embedded locale: the interface shows it in the reader's language, while the API and logs use
//! English through `Display`.
//!
//! Messages live in `crates/domain/locales/*.json` and are embedded at compile time; a key
//! missing from a locale fails the build (`EMBEDDED_I18N_STRICT` in `.cargo/config.toml`). They
//! are written as lower-case clauses (`the project name must be 1 to 200 characters`), which the
//! interface turns into sentences.

use std::fmt;

use embedded_i18n::{translate, translate_write};

embedded_i18n::track_locales!();

/// Index of English among the embedded locales.
pub const ENGLISH: usize = match embedded_i18n::find_locale("en") {
    Some(index) => index,
    None => embedded_i18n::DEFAULT_LOCALE_INDEX,
};

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
    pub fn name(self, locale: usize) -> &'static str {
        match self {
            Field::Username => translate!(locale = locale, "fields.username"),
            Field::DisplayName => translate!(locale = locale, "fields.display_name"),
            Field::OrganizationSlug => translate!(locale = locale, "fields.organization_slug"),
            Field::OrganizationName => translate!(locale = locale, "fields.organization_name"),
            Field::ProjectSlug => translate!(locale = locale, "fields.project_slug"),
            Field::ProjectName => translate!(locale = locale, "fields.project_name"),
            Field::TokenName => translate!(locale = locale, "fields.token_name"),
            Field::SourceCommit => translate!(locale = locale, "fields.source_commit"),
            Field::ImageTag => translate!(locale = locale, "fields.image_tag"),
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
    SbomNotCycloneDx,
    UnsupportedSpecificationVersion { version: String },
    InvalidCycloneDx { detail: String },
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
    ReasonRequired,
    ReasonTooLong { maximum: usize },
    ExpiryNotInFuture,
    OnlyOpenCanBeIgnored,
    OnlyIgnoredCanBeRestored,
    InvalidWebhookUrl,
    WebhookScheme,
    UnknownWebhookFormat,
}

impl Problem {
    /// Writes the problem in the locale with this index (see `embedded_i18n::LOCALES`; [`ENGLISH`]
    /// is one of them).
    pub fn write(&self, output: &mut impl fmt::Write, locale: usize) -> fmt::Result {
        use Problem as P;
        match self {
            P::InvalidSlug(field) => translate_write!(
                output,
                locale = locale,
                "problems.invalid_slug",
                field = field.name(locale),
                maximum = crate::names::MAXIMUM_LENGTH
            ),
            P::InvalidName(field) => translate_write!(
                output,
                locale = locale,
                "problems.invalid_name",
                field = field.name(locale)
            ),
            P::InvalidLabel(field) => translate_write!(
                output,
                locale = locale,
                "problems.invalid_label",
                field = field.name(locale)
            ),
            P::InvalidEmail => {
                output.write_str(translate!(locale = locale, "problems.invalid_email"))
            }
            P::PasswordTooShort { minimum } => translate_write!(
                output,
                locale = locale,
                "problems.password_too_short",
                minimum = minimum
            ),
            P::PasswordTooLong { maximum } => translate_write!(
                output,
                locale = locale,
                "problems.password_too_long",
                maximum = maximum
            ),
            P::SbomNotJson { detail } => translate_write!(
                output,
                locale = locale,
                "problems.sbom_not_json",
                detail = detail
            ),
            P::SbomNotCycloneDx => {
                output.write_str(translate!(locale = locale, "problems.sbom_not_cyclonedx"))
            }
            P::UnsupportedSpecificationVersion { version } => translate_write!(
                output,
                locale = locale,
                "problems.unsupported_specification_version",
                version = version,
                supported = crate::inventory::SUPPORTED_SPECIFICATION_VERSIONS.join(", ")
            ),
            P::InvalidCycloneDx { detail } => translate_write!(
                output,
                locale = locale,
                "problems.invalid_cyclonedx",
                detail = detail
            ),
            P::UsernameTaken { username } => translate_write!(
                output,
                locale = locale,
                "problems.username_taken",
                username = username
            ),
            P::EmailTaken { email } => translate_write!(
                output,
                locale = locale,
                "problems.email_taken",
                email = email
            ),
            P::OwnAccountStatus => {
                output.write_str(translate!(locale = locale, "problems.own_account_status"))
            }
            P::OrganizationExists { slug } => translate_write!(
                output,
                locale = locale,
                "problems.organization_exists",
                slug = slug
            ),
            P::LastOwner => output.write_str(translate!(locale = locale, "problems.last_owner")),
            P::UnknownUser { login } => translate_write!(
                output,
                locale = locale,
                "problems.unknown_user",
                login = login
            ),
            P::AlreadyMember { username } => translate_write!(
                output,
                locale = locale,
                "problems.already_member",
                username = username
            ),
            P::ProjectExists { slug } => translate_write!(
                output,
                locale = locale,
                "problems.project_exists",
                slug = slug
            ),
            P::UnknownProject { slug } => translate_write!(
                output,
                locale = locale,
                "problems.unknown_project",
                slug = slug
            ),
            P::UnknownOrganization { slug } => translate_write!(
                output,
                locale = locale,
                "problems.unknown_organization",
                slug = slug
            ),
            P::UnknownRole { role } => translate_write!(
                output,
                locale = locale,
                "problems.unknown_role",
                role = role
            ),
            P::UnknownSeverity => {
                output.write_str(translate!(locale = locale, "problems.unknown_severity"))
            }
            P::ReasonRequired => {
                output.write_str(translate!(locale = locale, "problems.reason_required"))
            }
            P::ReasonTooLong { maximum } => translate_write!(
                output,
                locale = locale,
                "problems.reason_too_long",
                maximum = maximum
            ),
            P::ExpiryNotInFuture => {
                output.write_str(translate!(locale = locale, "problems.expiry_not_in_future"))
            }
            P::OnlyOpenCanBeIgnored => output.write_str(translate!(
                locale = locale,
                "problems.only_open_can_be_ignored"
            )),
            P::OnlyIgnoredCanBeRestored => output.write_str(translate!(
                locale = locale,
                "problems.only_ignored_can_be_restored"
            )),
            P::InvalidWebhookUrl => {
                output.write_str(translate!(locale = locale, "problems.invalid_webhook_url"))
            }
            P::WebhookScheme => {
                output.write_str(translate!(locale = locale, "problems.webhook_scheme"))
            }
            P::UnknownWebhookFormat => output.write_str(translate!(
                locale = locale,
                "problems.unknown_webhook_format"
            )),
        }
    }

    /// The problem in the locale with this index.
    pub fn message(&self, locale: usize) -> String {
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
