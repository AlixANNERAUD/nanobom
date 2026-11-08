//! Structured logs on standard output.
//!
//! JSON lines by default, flattened so each event's fields sit at the top level, as log
//! collectors expect. Nothing is logged before [`initialize`] runs.

use tracing::Level;
use tracing_subscriber::{EnvFilter, filter::Targets, fmt};

use crate::command_line::{LogFormat, LoggingOptions};

/// Installs the global subscriber. An invalid filter falls back to `info`, with a warning on
/// standard error, rather than refusing to start. Panics if called twice.
pub fn initialize(options: &LoggingOptions) {
    let builder = fmt()
        .with_env_filter(filter(&options.log_level))
        .with_writer(std::io::stdout);
    match options.log_format {
        LogFormat::Json => builder
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .init(),
        LogFormat::Text => builder.init(),
    }
}

/// The filter for `NANOBOM_LOG_LEVEL`. PostgreSQL answers `CREATE TABLE IF NOT EXISTS` on an
/// existing table with a notice, which sqlx logs at INFO, so each start would log "relation
/// "seaql_migrations" already exists, skipping" from the migrations. Where the filter lets those
/// notices through at INFO, they are raised to WARN; the directive only ever lowers sqlx's
/// verbosity, so a filter that hides them (`error`, `off`) or that configures `sqlx` itself is
/// left as written.
fn filter(log_level: &str) -> EnvFilter {
    let (filter, log_level) = match EnvFilter::try_new(log_level) {
        Ok(filter) => (filter, log_level),
        Err(error) => {
            eprintln!("invalid log filter {log_level:?} ({error}), using \"info\"");
            (EnvFilter::new("info"), "info")
        }
    };
    if quiets_notices(log_level) {
        filter.add_directive(
            format!("{NOTICE_TARGET}=warn")
                .parse()
                .expect("a valid directive"),
        )
    } else {
        filter
    }
}

/// Where sqlx logs the notices of PostgreSQL.
const NOTICE_TARGET: &str = "sqlx::postgres::notice";

/// Whether the notice directive applies: the filter enables the notices at INFO and does not
/// mention sqlx. Filters `Targets` cannot represent (span and field directives) are left alone.
fn quiets_notices(log_level: &str) -> bool {
    let Ok(targets) = log_level.parse::<Targets>() else {
        return false;
    };
    let mentions_sqlx = targets
        .iter()
        .any(|(target, _)| target == "sqlx" || target.starts_with("sqlx::"));
    !mentions_sqlx && targets.would_enable(NOTICE_TARGET, &Level::INFO)
}

#[cfg(test)]
mod tests {
    use super::filter;

    fn quiets(log_level: &str) -> bool {
        filter(log_level)
            .to_string()
            .contains("sqlx::postgres::notice=warn")
    }

    #[test]
    fn postgresql_notices_are_raised_to_warn_where_they_would_be_logged_at_info() {
        assert!(quiets("info"));
        assert!(quiets("debug"));
        assert!(quiets("info,nanobom=debug"));
        assert!(
            quiets("nanobom=bogus"),
            "an invalid filter falls back to info"
        );
    }

    #[test]
    fn the_notice_directive_never_makes_logs_more_verbose() {
        assert!(!quiets("warn"));
        assert!(!quiets("error"));
        assert!(!quiets("off"));
        assert!(!quiets("error,nanobom=debug"));
        assert!(!quiets("warn,nanobom=debug"));
    }

    #[test]
    fn a_filter_configuring_sqlx_is_left_as_written() {
        assert!(!quiets("info,sqlx=debug"));
        assert!(!quiets("sqlx::postgres::notice=info"));
    }
}
