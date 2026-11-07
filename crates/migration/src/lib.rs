//! Database migrations of nanobom, written with SeaORM's schema builder so they run on every
//! database SeaORM supports. They are embedded in the binary and applied at startup.

pub use sea_orm_migration::prelude::*;

mod m20261107_000001_initial_schema;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m20261107_000001_initial_schema::Migration)]
    }
}
