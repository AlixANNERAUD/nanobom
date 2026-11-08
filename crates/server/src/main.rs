//! The nanobom binary: parses the command line, sets up logging and hands over to
//! [`nanobom::run`]. Everything else lives in the library, so integration tests can drive it.

use std::process::ExitCode;

use clap::Parser;
use nanobom::command_line::CommandLine;

#[tokio::main]
async fn main() -> ExitCode {
    let command_line = CommandLine::parse();
    nanobom::logging::initialize(&command_line.logging);
    match nanobom::run(command_line).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "nanobom stopped");
            ExitCode::FAILURE
        }
    }
}
