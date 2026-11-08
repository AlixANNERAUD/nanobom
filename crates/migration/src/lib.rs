//! Database migrations of nanobom, written with SeaORM's schema builder so they run on every
//! database SeaORM supports. They are embedded in the binary and applied at startup.
//!
//! To change the schema, add a migration rather than editing one that was released: databases
//! that already applied it would never see the change. Name it `mYYYYMMDD_NNNNNN_purpose`,
//! append it to [`Migrator::migrations`], then run `mise run entities` to regenerate the
//! `nanobom-entity` crate from the migrated schema (entities are never edited by hand).
//!
//! SQLite can only add one column per `ALTER TABLE` and cannot add foreign keys to an existing
//! table, so migrations alter tables one column at a time and new relations get new tables.

pub use sea_orm_migration::prelude::*;

mod m20261107_000001_initial_schema;
mod m20261108_000001_prioritization;
mod m20261108_000002_webhook_deliveries;
mod m20261108_000003_component_dependencies;

/// Every migration of nanobom, in the order they apply; used by
/// `nanobom_domain::database::migrate` and by the `migrate` command.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20261107_000001_initial_schema::Migration),
            Box::new(m20261108_000001_prioritization::Migration),
            Box::new(m20261108_000002_webhook_deliveries::Migration),
            Box::new(m20261108_000003_component_dependencies::Migration),
        ]
    }
}
