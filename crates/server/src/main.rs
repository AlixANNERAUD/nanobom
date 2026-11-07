//! The nanobom binary.

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
