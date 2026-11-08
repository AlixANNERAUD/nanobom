//! The parts of the OSV schema (<https://ossf.github.io/osv-schema/>) nanobom reads. Every field
//! that is optional in the schema is optional here, unknown fields are ignored and enumerations
//! are kept as strings, so new ecosystems or range types never break parsing.
//!
//! Records round-trip through serde: the domain caches them as JSON in the database, so a field
//! dropped here is lost from the cache too. Optional fields are skipped when empty to keep that
//! JSON small.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// An OSV record: one advisory, from one database, possibly affecting several packages.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub modified: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<DateTime<Utc>>,
    /// Set when the advisory was retracted; nanobom then stops matching it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn: Option<DateTime<Utc>>,
    /// Identifiers of the same issue in other databases (a GHSA's CVE, for example).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// Identifiers of different but related issues; not merged with this one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Record-level severities; see [`crate::severity::assess`] for how they are combined.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub severity: Vec<SeverityScore>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected: Vec<Affected>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<Reference>,
    /// Free-form data of the source database; GitHub advisories put a qualitative `severity`
    /// here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_specific: Option<Value>,
}

/// A severity given as a vector: `CVSS_V2`, `CVSS_V3`, `CVSS_V4`, `Ubuntu`…
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityScore {
    #[serde(rename = "type")]
    pub kind: String,
    /// Despite the name, a vector string such as `CVSS:3.1/AV:N/…`, not a number.
    pub score: String,
}

/// A package the record affects, with the versions or ranges concerned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Affected {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<Package>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub severity: Vec<SeverityScore>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<Range>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem_specific: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_specific: Option<Value>,
}

/// An affected package, named in its ecosystem (`crates.io`, `npm`, `PyPI`…).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    #[serde(default)]
    pub ecosystem: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
}

/// A range of affected versions, as a list of events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    /// `SEMVER`, `ECOSYSTEM` or `GIT`; for `GIT`, events are commit hashes in [`Range::repo`].
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<Event>,
}

/// One event of a range; exactly one field is set.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Event {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introduced: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_affected: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<String>,
}

/// A link about the record: advisory, fix, report…
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reference {
    #[serde(rename = "type", default)]
    pub kind: String,
    pub url: String,
}

impl Vulnerability {
    /// The versions that fix this vulnerability, deduplicated and sorted as strings (not as
    /// versions). With a package name, only the ranges of that package count, compared
    /// case-insensitively. Git ranges, whose events are commits, are left out.
    pub fn fixed_versions(&self, package_name: Option<&str>) -> Vec<String> {
        let mut versions: Vec<String> = self
            .affected
            .iter()
            .filter(|affected| match (package_name, &affected.package) {
                (Some(name), Some(package)) => package.name.eq_ignore_ascii_case(name),
                (Some(_), None) => false,
                (None, _) => true,
            })
            .flat_map(|affected| &affected.ranges)
            .filter(|range| range.kind != "GIT")
            .flat_map(|range| &range.events)
            .filter_map(|event| event.fixed.clone())
            .collect();
        versions.sort();
        versions.dedup();
        versions
    }
}
