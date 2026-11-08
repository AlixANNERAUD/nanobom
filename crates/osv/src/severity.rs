//! Severity of a vulnerability, computed from the CVSS vectors OSV gives.
//!
//! Supported vectors: CVSS 2.0, 3.0, 3.1 and 4.0. When a record has several, the most recent CVSS
//! version wins. Records without a usable vector fall back to the qualitative severity some
//! databases provide (`database_specific.severity`, as GitHub advisories do), then to unknown.
//!
//! The severity is computed once per record when it is cached, and a finding takes the highest
//! severity among the aliases that matched it. Non-CVSS vectors (`Ubuntu`…) are ignored.

use std::{fmt, str::FromStr};

use cvss::Cvss;
use serde::{Deserialize, Serialize};

use crate::schema::{SeverityScore, Vulnerability};

/// CVSS versions whose vectors are scored.
pub const SUPPORTED_CVSS_VERSIONS: [&str; 4] = ["2.0", "3.0", "3.1", "4.0"];

/// The qualitative severity of a vulnerability, ordered from [`Severity::Unknown`] (lowest) to
/// [`Severity::Critical`], following the CVSS rating scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// No usable vector or rating. Ranked lowest so thresholds such as "high and above" leave
    /// it out; filters can still ask for it explicitly.
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// From the most to the least severe.
    pub const DESCENDING: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Unknown,
    ];

    /// The lower-case name stored in the database and used in URLs and webhooks; parsed back
    /// with [`str::parse`].
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Unknown => "unknown",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// The qualitative rating of a CVSS base score. A score of 0.0 ("none") counts as low.
    pub fn from_score(score: f64) -> Self {
        match score {
            score if score >= 9.0 => Severity::Critical,
            score if score >= 7.0 => Severity::High,
            score if score >= 4.0 => Severity::Medium,
            score if score >= 0.0 => Severity::Low,
            _ => Severity::Unknown,
        }
    }

    /// Parses the qualitative ratings databases use (`CRITICAL`, `HIGH`, `MODERATE`…).
    pub fn from_label(label: &str) -> Self {
        match label.trim().to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" | "important" => Severity::High,
            "medium" | "moderate" => Severity::Medium,
            "low" | "negligible" | "none" => Severity::Low,
            _ => Severity::Unknown,
        }
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "unknown" => Ok(Severity::Unknown),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            other => Err(format!("unknown severity {other:?}")),
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A scored CVSS vector.
#[derive(Debug, Clone, PartialEq)]
pub struct CvssScore {
    /// `2.0`, `3.0`, `3.1` or `4.0`.
    pub version: &'static str,
    pub vector: String,
    pub score: f64,
}

/// The severity of a record and the CVSS score it comes from, if any.
#[derive(Debug, Clone, PartialEq)]
pub struct Assessment {
    pub severity: Severity,
    /// The vector the severity was derived from; `None` when it came from a qualitative rating
    /// or is unknown.
    pub cvss: Option<CvssScore>,
}

fn score(entry: &SeverityScore) -> Option<CvssScore> {
    let vector = entry.score.trim();
    let (version, score) = match entry.kind.as_str() {
        "CVSS_V2" => {
            let vector = vector.strip_prefix("CVSS:2.0/").unwrap_or(vector);
            (
                "2.0",
                cvss::v2::Vector::from_str(vector).ok()?.score().value(),
            )
        }
        "CVSS_V3" | "CVSS_V4" => match Cvss::from_str(vector).ok()? {
            Cvss::CvssV30(parsed) => ("3.0", parsed.score().value()),
            Cvss::CvssV31(parsed) => ("3.1", parsed.score().value()),
            Cvss::CvssV40(parsed) => ("4.0", parsed.score().value()),
            _ => return None,
        },
        _ => return None,
    };
    score.is_finite().then(|| CvssScore {
        version,
        vector: vector.to_owned(),
        score,
    })
}

/// Assesses a record: the most recent CVSS version among its vectors (top level first, then
/// per affected package), then its qualitative rating. Between vectors of the same version,
/// the highest score wins. Unparsable vectors are skipped, never an error.
pub fn assess(vulnerability: &Vulnerability) -> Assessment {
    let best = |entries: &mut dyn Iterator<Item = &SeverityScore>| {
        entries.filter_map(score).max_by(|left, right| {
            left.version
                .cmp(right.version)
                .then(left.score.total_cmp(&right.score))
        })
    };
    let cvss = best(&mut vulnerability.severity.iter()).or_else(|| {
        best(
            &mut vulnerability
                .affected
                .iter()
                .flat_map(|affected| &affected.severity),
        )
    });
    if let Some(cvss) = cvss {
        return Assessment {
            severity: Severity::from_score(cvss.score),
            cvss: Some(cvss),
        };
    }
    let label = vulnerability
        .database_specific
        .as_ref()
        .and_then(|value| value.get("severity"))
        .and_then(|value| value.as_str())
        .or_else(|| {
            vulnerability.affected.iter().find_map(|affected| {
                [&affected.database_specific, &affected.ecosystem_specific]
                    .into_iter()
                    .flatten()
                    .find_map(|value| value.get("severity").and_then(|value| value.as_str()))
            })
        });
    Assessment {
        severity: label.map_or(Severity::Unknown, Severity::from_label),
        cvss: None,
    }
}
