//! Command line and configuration. Every option can also be set with an environment variable.

use std::{net::SocketAddr, path::PathBuf};

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "nanobom", version, about)]
pub struct CommandLine {
    /// Database URL. SQLite is the supported database.
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
    /// Write a consistent copy of the live SQLite database to a new file.
    Backup {
        /// Destination file; it must not exist yet.
        #[arg(env = "NANOBOM_BACKUP_DESTINATION")]
        destination: PathBuf,
    },
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

    /// Address of the OSV API.
    #[arg(long, env = "NANOBOM_OSV_URL", default_value = "https://api.osv.dev/")]
    pub osv_url: reqwest::Url,

    /// Webhook receiving a JSON payload when a run fails (OSV unreachable, for example).
    #[arg(long, env = "NANOBOM_FAILURE_WEBHOOK_URL")]
    pub failure_webhook_url: Option<reqwest::Url>,
}
