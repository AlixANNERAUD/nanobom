//! The nanobom server: command line, HTTP API, authentication and the web interface.

pub mod api;
pub mod command_line;
pub mod logging;
pub mod serve;
pub mod state;

use nanobom_domain::database;

use crate::command_line::{Command, CommandLine};

pub type Failure = Box<dyn std::error::Error + Send + Sync>;

pub async fn run(command_line: CommandLine) -> Result<(), Failure> {
    let connection = database::connect(&command_line.database_url).await?;
    match command_line.command {
        Command::Serve(options) => {
            database::migrate(&connection).await?;
            serve::run(connection, options).await
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
