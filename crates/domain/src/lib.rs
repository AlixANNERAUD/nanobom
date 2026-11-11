//! Domain of nanobom: SBOM inventory, vulnerability matching against OSV, the finding lifecycle
//! and organizations.
//!
//! Every read and write of organization data goes through this crate; the `server` and `app`
//! crates do not query [`nanobom_entity`] tables themselves (the one exception is an
//! instance-wide metric in the server). That keeps one rule in one place: **isolation between
//! organizations**. Functions that read or change organization data take an [`access::Actor`]
//! and check its [`access::Role`] in the organization before touching anything (see [`access`]
//! for the role and permission table). Functions that only read take an [`access::Reader`]: an
//! actor, or a token of the read API, which reads as a viewer of what it reaches. A resource of an
//! organization the actor does not belong to is reported as [`Error::NotFound`], never
//! [`Error::Forbidden`], so its existence does not leak.
//!
//! Functions without an actor fall in three groups:
//!
//! - the caller is authenticated by other means: an upload token ([`tokens::authenticate`],
//!   then [`inventory::ingest`] and [`vex::import`], which also check its scope), a password or an
//!   identity provider at sign-in ([`users`], [`memberships::synchronize`]), or the operator on
//!   the command line (the `*_from_command_line` functions of [`tokens`]);
//! - background work of the server over the whole instance: runs ([`evaluation::Evaluator`],
//!   which trusts its caller to have checked [`evaluation::authorize`]), exploitation data,
//!   webhook and email deliveries, stale projects;
//! - instance-wide counts for the metrics, which never name an organization.
//!
//! # Concepts
//!
//! - An **organization** ([`organizations`]) owns **projects** ([`projects`]); users belong to
//!   organizations through **memberships** ([`memberships`]) that carry a role. A project's
//!   components and findings belong to one of its **versions** ([`versions`]); a project that
//!   never names one has a single, unnamed version.
//! - CI uploads a CycloneDX or SPDX SBOM with an **upload token** ([`tokens`]); the upload
//!   replaces the **components** of a project version ([`inventory`]) and their **dependency
//!   graph** ([`dependencies`]), which tells which direct dependency of the project pulls in a
//!   vulnerable component.
//! - A **run** ([`evaluation`]) matches components against a
//!   [`VulnerabilitySource`](nanobom_osv::VulnerabilitySource) and opens, fixes and reopens
//!   **findings** ([`findings`]); members can ignore findings, with a reason and an optional
//!   expiry.
//! - Findings are prioritized with exploitation signals ([`exploitation`]: CISA KEV and EPSS),
//!   projects whose SBOM stopped coming are flagged ([`staleness`]), and organizations are told
//!   about new findings through webhooks ([`notifications`]) and email ([`email`]), whose
//!   deliveries are queued and retried ([`deliveries`]); webhooks can post to Slack and
//!   Microsoft Teams ([`chat`]) instead of sending JSON.
//! - An organization's **license policy** ([`licenses`]) allows, warns about or forbids the
//!   licenses of its components; violations are computed when read.
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

// Every embedded locale must translate every message (strict): a missing key fails the build
// instead of showing English to French readers, so no fallback chain is ever consulted.
// `Problem` and emails translate per call (`locale = ...`), the global locale stays unset.
embedded_i18n::i18n!(
    "locales",
    default_locale = "en",
    available_locales = ["en", "fr"],
    strict = true
);

pub mod access;
pub mod chat;
pub mod database;
pub mod deliveries;
pub mod dependencies;
pub mod email;
pub mod error;
pub mod evaluation;
pub mod exploitation;
pub mod findings;
pub mod inventory;
pub mod licenses;
pub mod memberships;
pub mod names;
pub mod notifications;
pub mod organizations;
pub mod passwords;
pub mod problem;
pub mod projects;
pub mod report;
pub mod staleness;
pub mod tokens;
pub mod users;
pub mod versions;
pub mod vex;

pub use error::{Error, Result};
pub use problem::{Field, Problem};
/// The URL type of addresses such as the instance's public URL, for crates that do not depend
/// on `reqwest` themselves.
pub use reqwest::Url;

#[cfg(any(test, feature = "testing"))]
pub mod testing;
