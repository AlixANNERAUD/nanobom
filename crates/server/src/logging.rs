//! Structured logs on standard output.

use tracing_subscriber::{EnvFilter, fmt};

use crate::command_line::{LogFormat, LoggingOptions};

pub fn initialize(options: &LoggingOptions) {
    let filter = EnvFilter::try_new(&options.log_level).unwrap_or_else(|error| {
        eprintln!(
            "invalid log filter {:?} ({error}), using \"info\"",
            options.log_level
        );
        EnvFilter::new("info")
    });
    let builder = fmt().with_env_filter(filter).with_writer(std::io::stdout);
    match options.log_format {
        LogFormat::Json => builder
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .init(),
        LogFormat::Text => builder.init(),
    }
}
