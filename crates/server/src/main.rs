//! The nanobom server and its command line.

mod command_line;
mod logging;
mod serve;

use std::process::ExitCode;

use clap::Parser;
use nanobom_domain::database;

use crate::command_line::{Command, CommandLine};

#[tokio::main]
async fn main() -> ExitCode {
    let command_line = CommandLine::parse();
    logging::initialize(&command_line.logging);
    match run(command_line).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "nanobom stopped");
            ExitCode::FAILURE
        }
    }
}

type Failure = Box<dyn std::error::Error + Send + Sync>;

async fn run(command_line: CommandLine) -> Result<(), Failure> {
    let connection = database::connect(&command_line.database_url).await?;
    match command_line.command {
        Command::Serve => {
            database::migrate(&connection).await?;
            serve::run().await
        }
        Command::Migrate => {
            database::migrate(&connection).await?;
            tracing::info!("database migrated");
            Ok(())
        }
        Command::Backup { destination } => {
            database::backup(&connection, &destination).await?;
            tracing::info!(destination = %destination.display(), "backup written");
            Ok(())
        }
    }
}
