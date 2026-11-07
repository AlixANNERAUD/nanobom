//! OSV.dev support for nanobom: the record schema, severity scoring from CVSS vectors, and a
//! client for the batch query and vulnerability APIs behind the [`VulnerabilitySource`] trait.

pub mod client;
pub mod schema;
pub mod severity;

pub use client::{OsvClient, SourceError, VulnerabilityReference, VulnerabilitySource};
pub use schema::Vulnerability;
pub use severity::{Assessment, Severity, assess};
