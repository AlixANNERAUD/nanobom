//! Command line and configuration. Every option can also be set with an environment variable.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

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
    Serve,
    /// Apply pending database migrations and exit.
    Migrate,
    /// Write a consistent copy of the live SQLite database to a new file.
    Backup {
        /// Destination file; it must not exist yet.
        #[arg(env = "NANOBOM_BACKUP_DESTINATION")]
        destination: PathBuf,
    },
}
