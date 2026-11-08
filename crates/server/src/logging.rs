//! Structured logs on standard error.
//!
//! JSON lines by default, flattened so each event's fields sit at the top level, as log
//! collectors expect. Standard output is left to command results (a new token's secret, the
//! token list), which scripts capture. Nothing is logged before [`initialize`] runs.

use tracing_subscriber::{EnvFilter, fmt};

use crate::command_line::{LogFormat, LoggingOptions};

/// Installs the global subscriber, writing to standard error. An invalid filter falls back to
/// `info`, with a warning on standard error, rather than refusing to start. Panics if called
/// twice.
pub fn initialize(options: &LoggingOptions) {
    let builder = fmt()
        .with_env_filter(filter(&options.log_level))
        .with_writer(std::io::stderr);
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
/// "seaql_migrations" already exists, skipping" from the migrations; notices are kept from WARN
/// up, unless the filter sets sqlx's level itself.
fn filter(log_level: &str) -> EnvFilter {
    let filter = EnvFilter::try_new(log_level).unwrap_or_else(|error| {
        eprintln!("invalid log filter {log_level:?} ({error}), using \"info\"");
        EnvFilter::new("info")
    });
    if log_level.contains("sqlx") {
        filter
    } else {
        filter.add_directive(
            "sqlx::postgres::notice=warn"
                .parse()
                .expect("a valid directive"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::filter;

    #[test]
    fn postgresql_notices_are_quiet_unless_sqlx_is_configured() {
        assert!(
            filter("info")
                .to_string()
                .contains("sqlx::postgres::notice=warn")
        );
        assert!(
            !filter("info,sqlx=debug")
                .to_string()
                .contains("sqlx::postgres::notice")
        );
    }
}
