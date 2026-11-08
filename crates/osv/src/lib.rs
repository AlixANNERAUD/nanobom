//! OSV.dev support for nanobom: the record schema, severity scoring from CVSS vectors, and a
//! client for the batch query and vulnerability APIs behind the [`VulnerabilitySource`] trait.
//!
//! This crate knows nothing about the database or organizations. `nanobom-domain` drives it
//! during a run: it sends every package URL in scope to [`VulnerabilitySource::query`], fetches
//! the records it has not cached with [`VulnerabilitySource::vulnerability`], and stores each
//! record with the severity computed by [`assess`].
//!
//! Two design points matter to callers:
//!
//! - a query fails as a whole rather than answering partially, so "no vulnerabilities" always
//!   means OSV said so;
//! - records are parsed leniently ([`schema`]), so a new field or ecosystem upstream never
//!   breaks a run.
//!
//! Start with [`client`] for the network side and [`severity`] for how findings get their
//! severity. Tests use wiremock against [`OsvClient`], or the domain's in-memory source.

pub mod client;
pub mod schema;
pub mod severity;

pub use client::{OsvClient, SourceError, VulnerabilityReference, VulnerabilitySource};
pub use schema::Vulnerability;
pub use severity::{Assessment, Severity, assess};
