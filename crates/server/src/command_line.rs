//! Command line and configuration. Every option can also be set with an environment variable.
//!
//! The doc comments of the fields and variants below are the `--help` text: keep them short and
//! written for operators, and document the variable in the README's configuration table too.
//! Boolean options take an explicit value (`--local-accounts false`) so they can be turned off
//! from the command line as well as from the environment.

use std::{net::SocketAddr, path::PathBuf};

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "nanobom", version, about)]
pub struct CommandLine {
    /// Database URL: `sqlite://<path>` or `postgres://<user>:<password>@<host>/<database>`.
    #[arg(
        long,
        env = "NANOBOM_DATABASE_URL",
        default_value = "sqlite:///data/nanobom.db",
        global = true
    )]
    pub database_url: String,

    #[command(flatten)]
    pub logging: LoggingOptions,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Args)]
pub struct LoggingOptions {
    /// Log format: JSON lines for collectors, or human-readable text.
    #[arg(
        long,
        env = "NANOBOM_LOG_FORMAT",
        default_value = "json",
        global = true
    )]
    pub log_format: LogFormat,

    /// Log filter, in the `tracing` directive syntax (for example `info,nanobom=debug`).
    #[arg(long, env = "NANOBOM_LOG_LEVEL", default_value = "info", global = true)]
    pub log_level: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LogFormat {
    Json,
    Text,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Apply pending migrations, then serve the web interface and the API.
    Serve(Box<ServeOptions>),
    /// Apply pending database migrations and exit.
    Migrate,
    /// Write a consistent copy of the live SQLite database to a new file (use pg_dump for
    /// PostgreSQL).
    Backup {
        /// Destination file; it must not exist yet.
        #[arg(env = "NANOBOM_BACKUP_DESTINATION")]
        destination: PathBuf,
    },
    /// Create a local instance administrator, typically the first one.
    CreateAdministrator(CreateAdministratorOptions),
    /// Manage API tokens (upload and read).
    #[command(subcommand)]
    Token(TokenCommand),
    /// Exit successfully when the running server reports itself healthy; for container health
    /// checks. Does not open the database.
    Healthcheck(HealthcheckOptions),
}

#[derive(Debug, Args)]
pub struct HealthcheckOptions {
    /// The server's listen address; its health endpoint is reached over loopback when it
    /// listens on every interface.
    #[arg(long, env = "NANOBOM_LISTEN_ADDRESS", default_value = "0.0.0.0:8080")]
    pub listen_address: SocketAddr,

    /// Health endpoint to check instead of the one derived from the listen address.
    #[arg(long, env = "NANOBOM_HEALTHCHECK_URL")]
    pub url: Option<reqwest::Url>,

    /// Seconds to wait for an answer.
    #[arg(long, default_value_t = 5)]
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Args)]
pub struct AccountOptions {
    /// Give each new user a personal organization they own.
    #[arg(long, env = "NANOBOM_PERSONAL_ORGANIZATIONS", default_value_t = true, action = ArgAction::Set)]
    pub personal_organizations: bool,

    /// Minimum length of local account passwords.
    #[arg(long, env = "NANOBOM_PASSWORD_MINIMUM_LENGTH", default_value_t = 12)]
    pub password_minimum_length: usize,
}

#[derive(Debug, Args)]
pub struct CreateAdministratorOptions {
    /// Username of the new administrator, also used to sign in.
    #[arg(long, env = "NANOBOM_ADMINISTRATOR_USERNAME")]
    pub username: String,

    /// Email address, which can also be used to sign in.
    #[arg(long, env = "NANOBOM_ADMINISTRATOR_EMAIL")]
    pub email: Option<String>,

    /// The password; read from standard input when not set.
    #[arg(long, env = "NANOBOM_ADMINISTRATOR_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,

    #[command(flatten)]
    pub accounts: AccountOptions,
}

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Create a token and print it; it cannot be shown again.
    Create {
        /// Organization slug.
        #[arg(long, env = "NANOBOM_TOKEN_ORGANIZATION")]
        organization: String,
        /// Limit the token to this project; without it, the token covers the organization and
        /// may create projects.
        #[arg(long, env = "NANOBOM_TOKEN_PROJECT")]
        project: Option<String>,
        /// A name to recognize the token by.
        #[arg(long, env = "NANOBOM_TOKEN_NAME")]
        name: String,
        /// What the token may do: `upload` sends SBOMs and VEX documents and reads, `read` only
        /// reads, through the read API.
        #[arg(long, env = "NANOBOM_TOKEN_SCOPE", value_enum, default_value_t = TokenScope::Upload)]
        scope: TokenScope,
    },
    /// List the tokens of an organization.
    List {
        /// Organization slug.
        #[arg(long, env = "NANOBOM_TOKEN_ORGANIZATION")]
        organization: String,
    },
    /// Revoke a token.
    Revoke {
        /// Token identifier, as listed.
        #[arg(long)]
        id: i64,
    },
}

/// The scope of a new token, [`nanobom_domain::tokens::Scope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum TokenScope {
    Upload,
    Read,
}

impl From<TokenScope> for nanobom_domain::tokens::Scope {
    fn from(scope: TokenScope) -> Self {
        match scope {
            TokenScope::Upload => Self::Upload,
            TokenScope::Read => Self::Read,
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct ServeOptions {
    /// Address and port to listen on.
    #[arg(long, env = "NANOBOM_LISTEN_ADDRESS", default_value = "0.0.0.0:8080")]
    pub listen_address: SocketAddr,

    /// The address users reach nanobom at, used for links, OpenID Connect redirects, secure
    /// cookies and cross-site request checks.
    #[arg(
        long,
        env = "NANOBOM_PUBLIC_URL",
        default_value = "http://localhost:8080"
    )]
    pub public_url: reqwest::Url,

    /// Directory holding the web interface's assets (the `site` directory of the build).
    #[arg(long, env = "NANOBOM_SITE_ROOT", default_value = "site")]
    pub site_root: PathBuf,

    /// Largest accepted SBOM, in mebibytes. Parsing needs a few times this much memory.
    #[arg(long, env = "NANOBOM_MAXIMUM_SBOM_SIZE", default_value_t = 16)]
    pub maximum_sbom_size: usize,

    /// When every project is re-evaluated: a cron expression in UTC (minute hour day month
    /// weekday), or `off`.
    #[arg(long, env = "NANOBOM_SCHEDULE", default_value = "0 3 * * *")]
    pub schedule: String,

    /// Evaluate a project right after each SBOM upload.
    #[arg(long, env = "NANOBOM_RUN_AFTER_UPLOAD", default_value_t = true, action = ArgAction::Set)]
    pub run_after_upload: bool,

    /// Longest time an upload with `wait` or `fail_on` waits for its project's evaluation, in
    /// seconds.
    #[arg(long, env = "NANOBOM_UPLOAD_WAIT_SECONDS", default_value_t = 300)]
    pub upload_wait_seconds: u64,

    /// Most uploads waiting for their evaluation at once (`wait` or `fail_on`); more are
    /// refused with 503 and `Retry-After` until one finishes. Uploads that do not wait are not
    /// counted.
    #[arg(long, env = "NANOBOM_MAX_WAITING_UPLOADS", default_value_t = 32, value_parser = clap::value_parser!(u32).range(1..))]
    pub max_waiting_uploads: u32,

    /// Address of the OSV API.
    #[arg(long, env = "NANOBOM_OSV_URL", default_value = "https://api.osv.dev/")]
    pub osv_url: reqwest::Url,

    /// Download exploitation data (CISA KEV, FIRST EPSS) after each run.
    #[arg(long, env = "NANOBOM_EXPLOITATION_DATA", default_value_t = true, action = ArgAction::Set)]
    pub exploitation_data: bool,

    /// Days without an SBOM after which a project is flagged stale and its organization's
    /// webhook notified (0 disables the feature).
    #[arg(long, env = "NANOBOM_STALE_AFTER_DAYS", default_value_t = 30)]
    pub stale_after_days: u32,

    /// Address of CISA's Known Exploited Vulnerabilities catalog (JSON).
    #[arg(
        long,
        env = "NANOBOM_KEV_URL",
        default_value = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )]
    pub kev_url: reqwest::Url,

    /// Address of the FIRST EPSS API.
    #[arg(
        long,
        env = "NANOBOM_EPSS_URL",
        default_value = "https://api.first.org/data/v1/epss"
    )]
    pub epss_url: reqwest::Url,

    /// Webhook receiving a JSON payload when a run fails (OSV unreachable, for example).
    #[arg(long, env = "NANOBOM_FAILURE_WEBHOOK_URL")]
    pub failure_webhook_url: Option<reqwest::Url>,

    /// Allow sign-in with local accounts (username or email address and password).
    #[arg(long, env = "NANOBOM_LOCAL_ACCOUNTS", default_value_t = true, action = ArgAction::Set)]
    pub local_accounts: bool,

    /// Sign users out after this many days without activity.
    #[arg(long, env = "NANOBOM_SESSION_INACTIVITY_DAYS", default_value_t = 7)]
    pub session_inactivity_days: i64,

    /// Read client addresses from X-Forwarded-For and similar headers, for sign-in rate
    /// limiting. Enable only behind a reverse proxy that sets them.
    #[arg(long, env = "NANOBOM_TRUST_FORWARDED_HEADERS", default_value_t = false, action = ArgAction::Set)]
    pub trust_forwarded_headers: bool,

    #[command(flatten)]
    pub accounts: AccountOptions,

    #[command(flatten)]
    pub openid: OpenIdOptions,
}

/// OpenID Connect sign-in, enabled by setting the issuer and the client identifier.
#[derive(Debug, Clone, Args)]
pub struct OpenIdOptions {
    /// Issuer URL of the provider (its discovery document is read from it).
    #[arg(long, env = "NANOBOM_OIDC_ISSUER")]
    pub oidc_issuer: Option<String>,

    /// Client identifier registered with the provider.
    #[arg(long, env = "NANOBOM_OIDC_CLIENT_ID")]
    pub oidc_client_id: Option<String>,

    /// Client secret, for confidential clients; public clients rely on PKCE alone.
    #[arg(long, env = "NANOBOM_OIDC_CLIENT_SECRET", hide_env_values = true)]
    pub oidc_client_secret: Option<String>,

    /// Scopes to request, separated by spaces.
    #[arg(
        long,
        env = "NANOBOM_OIDC_SCOPES",
        default_value = "openid profile email"
    )]
    pub oidc_scopes: String,

    /// Create users at their first sign-in.
    #[arg(long, env = "NANOBOM_OIDC_CREATE_USERS", default_value_t = true, action = ArgAction::Set)]
    pub oidc_create_users: bool,

    /// Claim granting instance administration (for example `groups` or
    /// `urn:zitadel:iam:org:project:roles`); applied at each sign-in.
    #[arg(long, env = "NANOBOM_OIDC_ADMINISTRATOR_CLAIM")]
    pub oidc_administrator_claim: Option<String>,

    /// Value the administrator claim must contain; without it, the claim must be `true`.
    #[arg(long, env = "NANOBOM_OIDC_ADMINISTRATOR_VALUE")]
    pub oidc_administrator_value: Option<String>,

    /// Claim listing the user's groups or roles, for organization mapping.
    #[arg(long, env = "NANOBOM_OIDC_GROUPS_CLAIM")]
    pub oidc_groups_claim: Option<String>,

    /// Organization roles granted by groups: `group=organization:role` entries separated by
    /// `;`.
    #[arg(long, env = "NANOBOM_OIDC_GROUP_MAPPING", default_value = "")]
    pub oidc_group_mapping: String,

    /// Label of the sign-in button.
    #[arg(
        long,
        env = "NANOBOM_OIDC_BUTTON_LABEL",
        default_value = "Sign in with single sign-on"
    )]
    pub oidc_button_label: String,
}
