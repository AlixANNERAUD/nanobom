//! Opening the database, applying migrations and taking backups.
//!
//! SQLite is the supported database: one file, no server. Queries are nevertheless written with
//! SeaORM's builder rather than SQLite-specific SQL, and the test suite can run against
//! PostgreSQL (see the `testing` module), so the domain stays portable; [`backup`] is the one
//! SQLite-only operation.

use std::{path::Path, time::Duration};

use nanobom_migration::{Migrator, MigratorTrait};
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, DbErr,
    Statement,
};

/// Opens a connection pool; the URL scheme picks the backend. SQLite databases are created if
/// missing, use write-ahead logging so readers never block the writer, and enforce foreign keys
/// (deleting an organization or a project relies on cascades). The schema is not touched: call
/// [`migrate`] afterwards.
pub async fn connect(url: &str) -> Result<DatabaseConnection, DbErr> {
    let mut options = ConnectOptions::new(url);
    options
        .max_connections(8)
        .min_connections(1)
        .connect_timeout(Duration::from_secs(10))
        .sqlx_logging(false)
        .map_sqlx_sqlite_opts(|options| {
            options
                .create_if_missing(true)
                .foreign_keys(true)
                .busy_timeout(Duration::from_secs(10))
                .pragma("journal_mode", "WAL")
                .pragma("synchronous", "NORMAL")
        });
    Database::connect(options).await
}

/// Applies every pending migration of [`nanobom_migration::Migrator`]. Migrations only move
/// forward; there is no automatic downgrade.
pub async fn migrate(database: &DatabaseConnection) -> Result<(), DbErr> {
    Migrator::up(database, None).await
}

/// Why [`backup`] refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("backups use SQLite's VACUUM INTO; use the database's own tools (pg_dump) for {0:?}")]
    UnsupportedBackend(DatabaseBackend),
    #[error("the backup destination {0} already exists")]
    DestinationExists(String),
    #[error(transparent)]
    Database(#[from] DbErr),
}

/// Writes a consistent copy of a live SQLite database to `destination` with `VACUUM INTO`, which
/// runs inside a read transaction and does not block other connections.
///
/// The destination must not exist (`VACUUM INTO` would fail on a non-empty file, and refusing
/// up front avoids overwriting an earlier backup). PostgreSQL databases are refused with
/// [`BackupError::UnsupportedBackend`]: use `pg_dump`.
pub async fn backup(database: &DatabaseConnection, destination: &Path) -> Result<(), BackupError> {
    let backend = database.get_database_backend();
    if backend != DatabaseBackend::Sqlite {
        return Err(BackupError::UnsupportedBackend(backend));
    }
    if destination.exists() {
        return Err(BackupError::DestinationExists(
            destination.display().to_string(),
        ));
    }
    database
        .execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "VACUUM INTO ?",
            [destination.to_string_lossy().into_owned().into()],
        ))
        .await?;
    Ok(())
}
