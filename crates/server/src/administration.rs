//! Command line administration: the first administrator, API tokens and projects.
//!
//! These commands use the database directly, without an actor: whoever can run them can read
//! the database anyway. A new token's secret is printed on standard output alone: logs go to
//! standard error, so a script can capture the secret.

use std::io::BufRead;

use nanobom_domain::{
    passwords::{self, PasswordPolicy},
    projects, tokens,
    users::{self, NewUser},
};
use sea_orm::DatabaseConnection;

use crate::command_line::{CreateAdministratorOptions, ProjectCommand, TokenCommand};

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
/// prefix, name, project, last use, status and scope (last, so scripts written before scopes
/// keep their columns). A project's own token is listed under [`tokens::PROJECT_TOKEN_NAME`]
/// and cannot be revoked: `project token --renew` replaces it.
pub async fn token(
    database: &DatabaseConnection,
    command: TokenCommand,
) -> Result<(), crate::Failure> {
    match command {
        TokenCommand::Create {
            organization,
            project,
            name,
            scope,
        } => {
            let created = tokens::create_from_command_line(
                database,
                &organization,
                project.as_deref(),
                &name,
                scope.into(),
            )
            .await?;
            tracing::info!(
                organization = %organization,
                project = project.as_deref().unwrap_or("(all)"),
                scope = created.token.scope.as_str(),
                id = created.token.id,
                "token created"
            );
            // The secret goes to standard output alone, so scripts can capture it.
            println!("{}", created.secret);
        }
        TokenCommand::List { organization } => {
            for token in tokens::list_from_command_line(database, &organization).await? {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}",
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
                    token.scope.as_str(),
                );
            }
        }
        TokenCommand::Revoke { id } => {
            tokens::revoke_from_command_line(database, id).await?;
            tracing::info!(id, "token revoked");
        }
    }
    Ok(())
}

/// Runs a `project` subcommand. Both print the project's upload token alone on standard output,
/// like `token create`, so `TOKEN=$(nanobom project create …)` captures it.
pub async fn project(
    database: &DatabaseConnection,
    command: ProjectCommand,
) -> Result<(), crate::Failure> {
    let token = match command {
        ProjectCommand::Create {
            organization,
            project,
            name,
        } => {
            let created = projects::create_from_command_line(
                database,
                &organization,
                &project,
                name.as_deref(),
            )
            .await?;
            tracing::info!(organization = %organization, project = %created.slug, "project created");
            tokens::project_token_from_command_line(database, &organization, &created.slug, false)
                .await?
        }
        ProjectCommand::Token {
            organization,
            project,
            renew,
        } => {
            let token =
                tokens::project_token_from_command_line(database, &organization, &project, renew)
                    .await?;
            if renew {
                tracing::info!(organization = %organization, project = %project, id = token.token.id, "project token renewed");
            }
            token
        }
    };
    println!("{}", token.secret);
    Ok(())
}
