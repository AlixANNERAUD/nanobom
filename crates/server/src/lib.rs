//! The nanobom server: command line, HTTP API, authentication and the web interface.
//!
//! This crate builds the `nanobom` binary and wires the other crates together; it holds little
//! logic of its own. Everything that touches organization data goes through `nanobom-domain`,
//! which checks permissions; pages and forms come from `nanobom-app`, rendered on the server by
//! Leptos; sign-in comes from `nanobom-authentication`.
//!
//! # Request paths
//!
//! - **Interface** (`/organizations/…`, `/login`, and the app's server functions under `/api/`):
//!   Leptos routes behind sessions, cross-site request checks and the sign-in routes
//!   ([`authentication::layer`]). The app acts as the signed-in user.
//! - **Upload API** (`PUT /api/organizations/{organization}/projects/{project}/sbom`): CI sends
//!   an SBOM with a bearer upload token ([`api`]). No session is involved.
//! - **Dependency-Track API** (`/api/v1/bom`, `/api/v1/event/token/…`): the same uploads from
//!   clients written for Dependency-Track, with the upload token in `X-Api-Key`
//!   ([`dependency_track`]).
//! - **Read API** (`GET /api/organizations…`, `/api/findings/…`, `/api/components`): JSON
//!   reads with a token of either scope or the session ([`read_api`]), next to the VEX
//!   documents of a project ([`vex`]) and its vulnerability report in HTML ([`report`]).
//! - **Operations** (`/healthz`, `/metrics`): unauthenticated ([`operations`]).
//!
//! Every response goes through [`http::layers`] (security headers, compression, request logs).
//!
//! # Background work
//!
//! Runs are queued on the [`runner::Runner`] by the schedule, after uploads, or from the
//! interface. It executes them one at a time, then refreshes exploitation data, sends webhooks
//! and updates [`metrics`]. Webhook deliveries that fail are retried by the loop of
//! [`deliveries`]. At startup, before either starts, [`serve::run`] closes the runs a previous
//! process left `running`; the server therefore expects to be the only process on its database.
//!
//! # Where to start reading
//!
//! [`run`] dispatches the [`command_line::Command`]s; [`serve::run`] starts the server and
//! [`serve::router`] assembles the routes.

pub mod administration;
pub mod api;
pub mod authentication;
pub mod command_line;
pub mod deliveries;
pub mod dependency_track;
pub mod healthcheck;
pub mod http;
pub mod logging;
pub mod metrics;
pub mod operations;
pub mod read_api;
pub mod report;
pub mod runner;
pub mod serve;
pub mod state;
pub mod vex;

use nanobom_domain::database;

use crate::command_line::{Command, CommandLine};

/// Any error that stops a command; it is logged and the process exits with a failure status.
pub type Failure = Box<dyn std::error::Error + Send + Sync>;

/// Runs a command. Commands that use the database apply pending migrations first, except
/// `backup`, which copies the database as it is, and `healthcheck`, which does not open it.
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
