//! Command line administration: the first administrator and upload tokens.
//!
//! These commands use the database directly, without an actor: whoever can run them can read
//! the database anyway. Results go to standard output (a new token's secret alone, so scripts
//! can capture it) and messages to the logs.

use std::io::BufRead;

use nanobom_domain::{
    passwords::{self, PasswordPolicy},
    tokens,
    users::{self, NewUser},
};
use sea_orm::DatabaseConnection;

use crate::command_line::{CreateAdministratorOptions, TokenCommand};

/// Creates a local instance administrator. The password comes from the options or, when
/// missing, from the first line of standard input, and must follow the password policy.
pub async fn create_administrator(
    database: &DatabaseConnection,
    options: CreateAdministratorOptions,
) -> Result<(), crate::Failure> {
    let password = match options.password {
        Some(password) => password,
        None => {
            eprintln!("Password (read from standard input):");
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            line.trim_end_matches(['\r', '\n']).to_owned()
        }
    };
    PasswordPolicy {
        minimum_length: options.accounts.password_minimum_length,
    }
    .validate(&password)?;
    let user = users::create(
        database,
        NewUser {
            username: options.username,
            email: options.email,
            display_name: None,
            password_hash: Some(passwords::hash(password).await),
            is_instance_administrator: true,
        },
        options.accounts.personal_organizations,
    )
    .await?;
    tracing::info!(user = %user.username, "instance administrator created");
    Ok(())
}

/// Runs a `token` subcommand. `list` prints one tab-separated line per token: identifier,
/// prefix, name, project, last use and status.
pub async fn token(
    database: &DatabaseConnection,
    command: TokenCommand,
) -> Result<(), crate::Failure> {
    match command {
        TokenCommand::Create {
            organization,
            project,
            name,
        } => {
            let created = tokens::create_from_command_line(
                database,
                &organization,
                project.as_deref(),
                &name,
            )
            .await?;
            tracing::info!(
                organization = %organization,
                project = project.as_deref().unwrap_or("(all)"),
                id = created.token.id,
                "upload token created"
            );
            // The secret goes to standard output alone, so scripts can capture it.
            println!("{}", created.secret);
        }
        TokenCommand::List { organization } => {
            for token in tokens::list_from_command_line(database, &organization).await? {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    token.id,
                    token.prefix,
                    token.name,
                    token.project_slug.as_deref().unwrap_or("(organization)"),
                    token
                        .last_used_at
                        .map_or_else(|| "never used".to_owned(), |date| date.to_rfc3339()),
                    if token.revoked_at.is_some() {
                        "revoked"
                    } else {
                        "active"
                    },
                );
            }
        }
        TokenCommand::Revoke { id } => {
            tokens::revoke_from_command_line(database, id).await?;
            tracing::info!(id, "upload token revoked");
        }
    }
    Ok(())
}
