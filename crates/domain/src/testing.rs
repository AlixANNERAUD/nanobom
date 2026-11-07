//! Helpers for tests: a fresh, migrated database per test.
//!
//! Tests use a private in-memory SQLite database by default. Set `NANOBOM_TEST_DATABASE_URL` to
//! run them against another database such as PostgreSQL; the schema is then dropped and recreated
//! for each test, so run them one at a time (`--test-threads 1`).

use std::sync::atomic::{AtomicU64, Ordering};

use nanobom_migration::{Migrator, MigratorTrait};
use sea_orm::DatabaseConnection;

static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);

/// Returns a connection to an empty database with every migration applied.
pub async fn database() -> DatabaseConnection {
    match std::env::var("NANOBOM_TEST_DATABASE_URL") {
        Ok(url) => {
            let database = crate::database::connect(&url)
                .await
                .expect("connect to the test database");
            Migrator::fresh(&database)
                .await
                .expect("recreate the test schema");
            database
        }
        Err(_) => {
            let number = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
            let url = format!(
                "sqlite:file:nanobom-test-{}-{number}?mode=memory&cache=shared",
                std::process::id()
            );
            let database = crate::database::connect(&url)
                .await
                .expect("open the in-memory test database");
            crate::database::migrate(&database)
                .await
                .expect("migrate the test database");
            database
        }
    }
}

/// An in-memory vulnerability source: records are attached to package URLs and can change
/// between runs, and the source can be told to fail.
#[derive(Default)]
pub struct FakeSource {
    state: std::sync::Mutex<FakeState>,
}

#[derive(Default)]
struct FakeState {
    affected: std::collections::BTreeMap<String, Vec<String>>,
    records: std::collections::BTreeMap<String, nanobom_osv::Vulnerability>,
    failing: bool,
    fetches: Vec<String>,
}

impl FakeSource {
    /// Adds or replaces a record, affecting the given package URLs.
    pub fn publish(&self, record: serde_json::Value, purls: &[&str]) {
        let record: nanobom_osv::Vulnerability =
            serde_json::from_value(record).expect("a valid OSV record");
        let mut state = self.state.lock().expect("not poisoned");
        for purl in purls {
            let identifiers = state.affected.entry((*purl).to_owned()).or_default();
            if !identifiers.contains(&record.id) {
                identifiers.push(record.id.clone());
            }
        }
        state.records.insert(record.id.clone(), record);
    }

    /// Stops reporting a vulnerability for a package URL, as when OSV narrows a range.
    pub fn retract(&self, id: &str, purl: &str) {
        let mut state = self.state.lock().expect("not poisoned");
        if let Some(identifiers) = state.affected.get_mut(purl) {
            identifiers.retain(|identifier| identifier != id);
        }
    }

    pub fn set_failing(&self, failing: bool) {
        self.state.lock().expect("not poisoned").failing = failing;
    }

    /// The identifiers whose details were fetched, in order.
    pub fn fetches(&self) -> Vec<String> {
        self.state.lock().expect("not poisoned").fetches.clone()
    }
}

impl nanobom_osv::VulnerabilitySource for FakeSource {
    async fn query(
        &self,
        purls: &[String],
    ) -> Result<Vec<Vec<nanobom_osv::VulnerabilityReference>>, nanobom_osv::SourceError> {
        let state = self.state.lock().expect("not poisoned");
        if state.failing {
            return Err(nanobom_osv::SourceError::InvalidResponse {
                url: "fake".to_owned(),
                message: "the source is unreachable".to_owned(),
            });
        }
        Ok(purls
            .iter()
            .map(|purl| {
                state
                    .affected
                    .get(purl)
                    .into_iter()
                    .flatten()
                    .map(|id| nanobom_osv::VulnerabilityReference {
                        id: id.clone(),
                        modified: state.records[id].modified,
                    })
                    .collect()
            })
            .collect())
    }

    async fn vulnerability(
        &self,
        id: &str,
    ) -> Result<nanobom_osv::Vulnerability, nanobom_osv::SourceError> {
        let mut state = self.state.lock().expect("not poisoned");
        state.fetches.push(id.to_owned());
        state
            .records
            .get(id)
            .cloned()
            .ok_or_else(|| nanobom_osv::SourceError::InvalidResponse {
                url: "fake".to_owned(),
                message: format!("{id} is unknown"),
            })
    }
}
