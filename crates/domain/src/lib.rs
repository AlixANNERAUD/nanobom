//! Domain of nanobom: SBOM inventory, vulnerability matching against OSV, the finding lifecycle
//! and organizations. Every database access goes through this crate, which enforces isolation
//! between organizations: functions that read or change organization data take an
//! [`access::Actor`] and check its role first.

pub mod access;
pub mod database;
pub mod error;
pub mod evaluation;
pub mod exploitation;
pub mod findings;
pub mod inventory;
pub mod memberships;
pub mod names;
pub mod notifications;
pub mod organizations;
pub mod passwords;
pub mod problem;
pub mod projects;
pub mod staleness;
pub mod tokens;
pub mod users;

pub use error::{Error, Result};
pub use problem::{Field, Problem};

#[cfg(any(test, feature = "testing"))]
pub mod testing;
