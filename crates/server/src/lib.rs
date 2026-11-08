//! The nanobom server: command line, HTTP API, authentication and the web interface.

pub mod administration;
pub mod api;
pub mod authentication;
pub mod command_line;
pub mod deliveries;
pub mod healthcheck;
pub mod http;
pub mod logging;
pub mod metrics;
pub mod operations;
pub mod runner;
pub mod serve;
pub mod state;

use nanobom_domain::database;

use crate::command_line::{Command, CommandLine};

pub type Failure = Box<dyn std::error::Error + Send + Sync>;

pub async fn run(command_line: CommandLine) -> Result<(), Failure> {
    let database_url = command_line.database_url;
    let connect = || database::connect(&database_url);
    match command_line.command {
        Command::Healthcheck(options) => healthcheck::run(options).await,
        Command::Serve(options) => {
            let connection = connect().await?;
            database::migrate(&connection).await?;
            serve::run(connection, *options).await
        }
        Command::Migrate => {
            database::migrate(&connect().await?).await?;
            tracing::info!("database migrated");
            Ok(())
        }
        Command::Backup { destination } => {
            database::backup(&connect().await?, &destination).await?;
            tracing::info!(destination = %destination.display(), "backup written");
            Ok(())
        }
        Command::CreateAdministrator(options) => {
            let connection = connect().await?;
            database::migrate(&connection).await?;
            administration::create_administrator(&connection, options).await
        }
        Command::Token(command) => {
            let connection = connect().await?;
            database::migrate(&connection).await?;
            administration::token(&connection, command).await
        }
    }
}
