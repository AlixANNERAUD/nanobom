//! Domain of nanobom: SBOM inventory, vulnerability matching against OSV, the finding lifecycle
//! and organizations.
//!
//! Every read and write of organization data goes through this crate; the `server` and `app`
//! crates do not query [`nanobom_entity`] tables themselves (the one exception is an
//! instance-wide metric in the server). That keeps one rule in one place: **isolation between
//! organizations**. Functions that read or change organization data take an [`access::Actor`]
//! and check its [`access::Role`] in the organization before touching anything (see [`access`]
//! for the role and permission table). A resource of an organization the actor does not belong
//! to is reported as [`Error::NotFound`], never [`Error::Forbidden`], so its existence does not
//! leak.
//!
//! Functions without an actor fall in three groups:
//!
//! - the caller is authenticated by other means: an upload token ([`tokens::authenticate`],
//!   then [`inventory::ingest`] and [`findings::open_for_upload_token`]), a password or an
//!   identity provider at sign-in ([`users`], [`memberships::synchronize`]), or the operator on
//!   the command line (the `*_from_command_line` functions of [`tokens`]);
//! - background work of the server over the whole instance: runs ([`evaluation::Evaluator`],
//!   which trusts its caller to have checked [`evaluation::authorize`]), exploitation data,
//!   webhook deliveries, stale projects;
//! - instance-wide counts for the metrics, which never name an organization.
//!
//! # Concepts
//!
//! - An **organization** ([`organizations`]) owns **projects** ([`projects`]); users belong to
//!   organizations through **memberships** ([`memberships`]) that carry a role.
//! - CI uploads a CycloneDX SBOM with an **upload token** ([`tokens`]); the upload replaces the
//!   project's **components** ([`inventory`]) and their **dependency graph**
//!   ([`dependencies`]), which tells which direct dependency of the project pulls in a
//!   vulnerable component.
//! - A **run** ([`evaluation`]) matches components against a
//!   [`VulnerabilitySource`](nanobom_osv::VulnerabilitySource) and opens, fixes and reopens
//!   **findings** ([`findings`]); members can ignore findings, with a reason and an optional
//!   expiry.
//! - Findings are prioritized with exploitation signals ([`exploitation`]: CISA KEV and EPSS),
//!   projects whose SBOM stopped coming are flagged ([`staleness`]), and organizations are told
//!   about new findings through webhooks ([`notifications`]), whose deliveries are queued and
//!   retried ([`deliveries`]).
//!
//! The crate builds on [`nanobom_entity`] (the tables), `nanobom_migration` (the schema) and
//! [`nanobom_osv`] (the vulnerability source and severity scoring). The `app` crate calls it
//! from its server functions, the `server` crate from the upload API, the run worker and the
//! command line; they authenticate the caller and leave authorization to this crate.
//!
//! # Errors
//!
//! Every operation returns [`Result`]. [`Error::Invalid`] and [`Error::Conflict`] carry a
//! [`Problem`], a message meant for the user that renders in each interface language; other
//! variants are mapped to HTTP statuses by the server.
//!
//! # Where to start reading
//!
//! [`access`] for authorization, [`inventory::ingest`] for an upload, then
//! [`evaluation::Evaluator::run`] for what a run does to [`findings`]. [`database`] opens and
//! migrates the database; the `testing` module (behind the `testing` feature) gives tests a
//! fresh database and a fake vulnerability source.

pub mod access;
pub mod database;
pub mod deliveries;
pub mod dependencies;
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
