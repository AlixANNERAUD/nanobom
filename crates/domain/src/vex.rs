//! VEX (Vulnerability Exploitability eXchange): telling others which vulnerabilities affect a
//! project, and learning from others which do not, in the CycloneDX format.
//!
//! # Export
//!
//! [`export`] describes every finding of a project as a CycloneDX 1.6 vulnerability with an
//! impact analysis:
//!
//! | Finding | `analysis.state` | `analysis.justification` | `analysis.detail` |
//! | --- | --- | --- | --- |
//! | open | `in_triage` | | |
//! | ignored with a justification | `not_affected` | the justification | the reason |
//! | ignored as a false positive | `false_positive` | | the reason |
//! | ignored without a justification | `in_triage` | | the reason |
//! | fixed | `resolved` | | |
//!
//! The document of a public page ([`crate::public_pages::vex`]) leaves out `analysis.detail`
//! and the organization, which only members may read.
//!
//! An ignore without a justification is often an accepted risk rather than a proof that the
//! product is not affected, so it is never exported as `not_affected`: the document claims no
//! more than members recorded. Open findings are `in_triage` even when known exploited, since
//! exploitation elsewhere says nothing about this product's exposure.
//!
//! Each vulnerability's `affects` names the component by a `bom-ref` equal to its package URL,
//! and the components are listed in the document itself, so the references resolve without the
//! SBOM.
//!
//! # Import
//!
//! [`import`] applies the statements of a CycloneDX document (a standalone VEX, or the
//! `vulnerabilities` of an uploaded SBOM, see [`crate::inventory::ParsedSbom::vex`]) to a
//! project's findings. A statement whose state is `not_affected` or `false_positive` ignores the
//! open findings it matches, with its justification and its detail as the reason; other states
//! change nothing and are reported as informational. Importing the same document twice changes
//! nothing the second time.
//!
//! A statement matches a finding when one of its identifiers (its `id` and the `id`s of its
//! `references`) equals the finding's vulnerability or one of its aliases, ignoring case, and
//! one of its `affects` resolves to the finding's package URL, ignoring qualifiers and subpath.
//! An `affects[].ref` resolves through the `bom-ref` of a component of the same document, or is
//! itself a package URL; a BOM-Link (`urn:cdx:…#ref`) is read the same way from its fragment.
//! A package URL without a version matches nothing, so a statement cannot silence every
//! version of a package.

use std::{
    collections::{BTreeSet, HashMap},
    str::FromStr,
};

use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use cyclonedx_bom::{models::component::Component, prelude::Bom};
use nanobom_entity::{
    finding_events, findings, organizations, project_versions, projects, upload_tokens,
};
use packageurl::PackageUrl;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, TransactionSession,
    TransactionTrait,
};
use serde::{Deserialize, Serialize};

use crate::{
    access::Reader,
    error::{Error, Result},
    exploitation::{QUERY_CHUNK, vulnerability_facts},
    findings::{Finding, IgnoredBy, Justification, MAXIMUM_REASON_LENGTH, Status},
    inventory,
};

/// The CycloneDX version of exported documents.
pub const SPECIFICATION_VERSION: &str = "1.6";

/// At most this many statements are listed in an import's outcome; all are counted.
const MAXIMUM_LISTED_STATEMENTS: usize = 500;

/// A CycloneDX VEX document, as exported. Field names follow the CycloneDX JSON schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    pub bom_format: String,
    pub spec_version: String,
    pub serial_number: String,
    pub version: u32,
    pub metadata: Metadata,
    pub components: Vec<DocumentComponent>,
    pub vulnerabilities: Vec<DocumentVulnerability>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metadata {
    pub timestamp: String,
    pub tools: Tools,
    /// The project.
    pub component: DocumentComponent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tools {
    pub components: Vec<DocumentComponent>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    #[serde(rename = "bom-ref", skip_serializing_if = "Option::is_none")]
    pub bom_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentVulnerability {
    pub id: String,
    pub source: Source,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub references: Vec<Reference>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub ratings: Vec<Rating>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    pub updated: String,
    pub analysis: Analysis,
    pub affects: Vec<Affects>,
}

/// Where a vulnerability identifier is published.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reference {
    pub id: String,
    pub source: Source,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rating {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Analysis {
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub first_issued: String,
    pub last_updated: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Affects {
    #[serde(rename = "ref")]
    pub reference: String,
}

fn timestamp(value: DateTime<FixedOffset>) -> String {
    value
        .with_timezone(&Utc)
        .to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// The database that publishes an identifier, by its prefix; OSV for the others, since nanobom
/// learned every identifier from it.
fn source(id: &str) -> Source {
    let prefix = id.split('-').next().unwrap_or_default();
    if prefix.eq_ignore_ascii_case("CVE") {
        Source {
            name: "NVD".to_owned(),
            url: format!("https://nvd.nist.gov/vuln/detail/{id}"),
        }
    } else if prefix.eq_ignore_ascii_case("GHSA") {
        Source {
            name: "GitHub Advisories".to_owned(),
            url: format!("https://github.com/advisories/{id}"),
        }
    } else {
        Source {
            name: "OSV".to_owned(),
            url: format!("https://osv.dev/vulnerability/{id}"),
        }
    }
}

/// The CycloneDX scoring method of a CVSS version stored by nanobom.
fn score_method(version: &str) -> Option<&'static str> {
    match version {
        "2.0" => Some("CVSSv2"),
        "3.0" => Some("CVSSv3"),
        "3.1" => Some("CVSSv31"),
        "4.0" => Some("CVSSv4"),
        _ => None,
    }
}

/// The impact analysis of a finding, per the table of the module documentation.
fn analysis(finding: &Finding) -> (String, Option<String>, Option<String>) {
    match finding.status {
        Status::Open => ("in_triage".to_owned(), None, None),
        Status::Fixed => ("resolved".to_owned(), None, None),
        Status::Ignored => {
            let detail = finding.ignore_reason.clone();
            match finding.ignore_justification {
                Some(Justification::FalsePositive) => ("false_positive".to_owned(), None, detail),
                Some(justification) => (
                    "not_affected".to_owned(),
                    Some(justification.as_str().to_owned()),
                    detail,
                ),
                None => ("in_triage".to_owned(), None, detail),
            }
        }
    }
}

fn component(purl: &str) -> DocumentComponent {
    match PackageUrl::from_str(purl) {
        Ok(parsed) => DocumentComponent {
            component_type: "library".to_owned(),
            bom_ref: Some(purl.to_owned()),
            group: parsed.namespace().map(str::to_owned),
            name: parsed.name().to_owned(),
            version: parsed.version().map(str::to_owned),
            purl: Some(purl.to_owned()),
        },
        Err(_) => DocumentComponent {
            component_type: "library".to_owned(),
            bom_ref: Some(purl.to_owned()),
            group: None,
            name: purl.to_owned(),
            version: None,
            purl: None,
        },
    }
}

/// The findings of a project version (`None`: the latest) as a CycloneDX VEX document, whose
/// metadata component carries the version name, unless it is the unnamed version. Requires
/// [`crate::access::Permission::View`] in the organization; a missing organization, project or
/// version, or one outside a token's reach, is [`Error::NotFound`].
pub async fn export(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    organization_slug: &str,
    project_slug: &str,
    version: Option<&str>,
) -> Result<Document> {
    let reader = reader.into();
    let organization = crate::organizations::find(database, reader, organization_slug).await?;
    let project = crate::projects::find(database, reader, organization.id, project_slug).await?;
    let version = crate::versions::select(database, project.id, version).await?;
    version_document(
        database,
        project,
        &version,
        Audience::Members {
            organization_slug: &organization.slug,
        },
    )
    .await
}

/// Who a document is for, which decides what it may say beyond the findings themselves.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Audience<'a> {
    /// Readers of the project: the document names the organization, and `analysis.detail`
    /// carries the reason of each ignore.
    Members { organization_slug: &'a str },
    /// Anyone holding a public page's key ([`crate::public_pages`]): no organization and no
    /// `analysis.detail`, since reasons are internal notes that may name people or systems.
    Public,
}

/// The VEX document of a version of a project, **without authorization**: [`export`] checks
/// the reader first, and a public page's key stands for its authorization.
pub(crate) async fn version_document(
    database: &impl ConnectionTrait,
    project: projects::Model,
    version: &project_versions::Model,
    audience: Audience<'_>,
) -> Result<Document> {
    let findings = crate::findings::version_findings(
        database,
        project.clone(),
        version,
        &crate::findings::Filter::default(),
    )
    .await?;
    document(database, audience, project, &version.name, findings).await
}

/// The organization and project an upload token names, if the token covers them.
async fn token_project(
    database: &impl ConnectionTrait,
    token: &upload_tokens::Model,
    organization_slug: &str,
    project_slug: &str,
) -> Result<(organizations::Model, projects::Model)> {
    let organization = organizations::Entity::find()
        .filter(organizations::Column::Slug.eq(organization_slug.trim().to_ascii_lowercase()))
        .one(database)
        .await?
        .filter(|organization| organization.id == token.organization_id)
        .ok_or(Error::NotFound)?;
    let project = crate::projects::find_model(database, organization.id, project_slug)
        .await?
        .filter(|project| token.project_id.is_none_or(|allowed| allowed == project.id))
        .ok_or(Error::NotFound)?;
    Ok((organization, project))
}

async fn document(
    database: &impl ConnectionTrait,
    audience: Audience<'_>,
    project: projects::Model,
    version: &str,
    mut findings: Vec<Finding>,
) -> Result<Document> {
    // A stable order, so two exports of the same state differ only in their header.
    findings.sort_by(|left, right| {
        (&left.vulnerability_id, &left.purl).cmp(&(&right.vulnerability_id, &right.purl))
    });
    let last_events = last_event_times(database, findings.iter().map(|finding| finding.id)).await?;
    let records = vulnerability_records(
        database,
        findings
            .iter()
            .map(|finding| finding.vulnerability_id.as_str()),
    )
    .await?;
    let components: BTreeSet<&str> = findings
        .iter()
        .map(|finding| finding.purl.as_str())
        .collect();
    let vulnerabilities = findings
        .iter()
        .map(|finding| {
            let record = records.get(&finding.vulnerability_id);
            let last_updated = last_events
                .get(&finding.id)
                .copied()
                .unwrap_or(finding.last_seen_at);
            let (state, justification, detail) = analysis(finding);
            let detail = match audience {
                Audience::Members { .. } => detail,
                Audience::Public => None,
            };
            let rating = Rating {
                score: finding.cvss_score,
                severity: finding.severity.as_str().to_owned(),
                method: record
                    .and_then(|record| record.cvss_version.as_deref())
                    .and_then(score_method)
                    .map(str::to_owned),
                vector: record.and_then(|record| record.cvss_vector.clone()),
            };
            DocumentVulnerability {
                id: finding.vulnerability_id.clone(),
                source: source(&finding.vulnerability_id),
                references: finding
                    .aliases
                    .iter()
                    .filter(|alias| **alias != finding.vulnerability_id)
                    .map(|alias| Reference {
                        id: alias.clone(),
                        source: source(alias),
                    })
                    .collect(),
                ratings: vec![rating],
                description: finding.summary.clone(),
                published: record.and_then(|record| record.published.map(timestamp)),
                updated: timestamp(record.map_or(finding.last_seen_at, |record| record.modified)),
                analysis: Analysis {
                    state,
                    justification,
                    detail,
                    first_issued: timestamp(finding.first_seen_at),
                    last_updated: timestamp(last_updated),
                },
                affects: vec![Affects {
                    reference: finding.purl.clone(),
                }],
            }
        })
        .collect();
    Ok(Document {
        bom_format: "CycloneDX".to_owned(),
        spec_version: SPECIFICATION_VERSION.to_owned(),
        serial_number: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        version: 1,
        metadata: Metadata {
            timestamp: timestamp(Utc::now().fixed_offset()),
            tools: Tools {
                components: vec![DocumentComponent {
                    component_type: "application".to_owned(),
                    bom_ref: None,
                    group: None,
                    name: "nanobom".to_owned(),
                    // Not to the public: it would tell anyone which instances run a release
                    // with a known flaw.
                    version: match audience {
                        Audience::Members { .. } => Some(env!("CARGO_PKG_VERSION").to_owned()),
                        Audience::Public => None,
                    },
                    purl: None,
                }],
            },
            component: DocumentComponent {
                component_type: "application".to_owned(),
                bom_ref: match audience {
                    Audience::Members { organization_slug } => {
                        Some(format!("{organization_slug}/{}", project.slug))
                    }
                    Audience::Public => None,
                },
                group: None,
                name: project.name,
                version: (!version.is_empty()).then(|| version.to_owned()),
                purl: None,
            },
        },
        components: components.into_iter().map(component).collect(),
        vulnerabilities,
    })
}

/// The time of the latest event of each finding.
async fn last_event_times(
    database: &impl ConnectionTrait,
    finding_ids: impl Iterator<Item = i64>,
) -> Result<HashMap<i64, DateTime<FixedOffset>>> {
    let finding_ids: Vec<i64> = finding_ids.collect();
    let mut times = HashMap::new();
    for chunk in finding_ids.chunks(QUERY_CHUNK) {
        for event in finding_events::Entity::find()
            .filter(finding_events::Column::FindingId.is_in(chunk.iter().copied()))
            .order_by_asc(finding_events::Column::Id)
            .all(database)
            .await?
        {
            let latest = times.entry(event.finding_id).or_insert(event.created_at);
            *latest = (*latest).max(event.created_at);
        }
    }
    Ok(times)
}

/// The dates and CVSS vector of vulnerabilities; the OSV record itself is not loaded.
struct RecordFacts {
    published: Option<DateTime<FixedOffset>>,
    modified: DateTime<FixedOffset>,
    cvss_version: Option<String>,
    cvss_vector: Option<String>,
}

/// `id`, `published`, `modified`, `cvss_version` and `cvss_vector` of a vulnerability.
type RecordRow = (
    String,
    Option<DateTime<FixedOffset>>,
    DateTime<FixedOffset>,
    Option<String>,
    Option<String>,
);

async fn vulnerability_records<'a>(
    database: &impl ConnectionTrait,
    identifiers: impl Iterator<Item = &'a str>,
) -> Result<HashMap<String, RecordFacts>> {
    use nanobom_entity::vulnerabilities;
    use sea_orm::QuerySelect;
    let identifiers: Vec<&str> = identifiers.collect::<BTreeSet<_>>().into_iter().collect();
    let mut records = HashMap::new();
    for chunk in identifiers.chunks(QUERY_CHUNK) {
        let rows: Vec<RecordRow> = vulnerabilities::Entity::find()
            .select_only()
            .columns([
                vulnerabilities::Column::Id,
                vulnerabilities::Column::Published,
                vulnerabilities::Column::Modified,
                vulnerabilities::Column::CvssVersion,
                vulnerabilities::Column::CvssVector,
            ])
            .filter(vulnerabilities::Column::Id.is_in(chunk.iter().copied()))
            .into_tuple()
            .all(database)
            .await?;
        for (id, published, modified, cvss_version, cvss_vector) in rows {
            records.insert(
                id,
                RecordFacts {
                    published,
                    modified,
                    cvss_version,
                    cvss_vector,
                },
            );
        }
    }
    Ok(records)
}

/// The impact analysis state of a statement, as CycloneDX names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Resolved,
    ResolvedWithPedigree,
    Exploitable,
    InTriage,
    FalsePositive,
    NotAffected,
}

impl State {
    pub fn as_str(&self) -> &'static str {
        match self {
            State::Resolved => "resolved",
            State::ResolvedWithPedigree => "resolved_with_pedigree",
            State::Exploitable => "exploitable",
            State::InTriage => "in_triage",
            State::FalsePositive => "false_positive",
            State::NotAffected => "not_affected",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "resolved" => State::Resolved,
            "resolved_with_pedigree" => State::ResolvedWithPedigree,
            "exploitable" => State::Exploitable,
            "in_triage" => State::InTriage,
            "false_positive" => State::FalsePositive,
            "not_affected" => State::NotAffected,
            _ => return None,
        })
    }
}

/// A component an `affects[].ref` points to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The reference as written in the document.
    pub reference: String,
    /// The package URL it resolves to, if any.
    pub purl: Option<String>,
}

/// One analysed vulnerability of a CycloneDX document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// The vulnerability's `id`, then the `id`s of its `references`.
    pub identifiers: Vec<String>,
    pub state: State,
    pub justification: Option<Justification>,
    pub detail: Option<String>,
    pub targets: Vec<Target>,
}

/// Parses a standalone CycloneDX VEX document (JSON, specification 1.4 or later, since earlier
/// versions have no `vulnerabilities`). Errors are [`Error::Invalid`] with a problem for CI.
pub fn parse(document: &[u8]) -> Result<Vec<Statement>> {
    let bom = inventory::read_vex(document)?;
    Ok(statements(&bom))
}

/// The analysed vulnerabilities of a CycloneDX document. Entries without an `analysis.state`
/// (what scanners list) or with a state outside the specification are left out.
pub(crate) fn statements(bom: &Bom) -> Vec<Statement> {
    let Some(vulnerabilities) = &bom.vulnerabilities else {
        return Vec::new();
    };
    let mut references = HashMap::new();
    if let Some(component) = bom
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.component.as_ref())
    {
        collect_references(std::slice::from_ref(component), &mut references);
    }
    if let Some(components) = &bom.components {
        collect_references(&components.0, &mut references);
    }
    vulnerabilities
        .0
        .iter()
        .filter_map(|vulnerability| {
            let analysis = vulnerability.vulnerability_analysis.as_ref()?;
            let state = State::parse(&analysis.state.as_ref()?.to_string())?;
            let identifiers = vulnerability
                .id
                .iter()
                .map(ToString::to_string)
                .chain(
                    vulnerability
                        .vulnerability_references
                        .iter()
                        .flat_map(|references| &references.0)
                        .map(|reference| reference.id.to_string()),
                )
                .map(|id| id.trim().to_owned())
                .filter(|id| !id.is_empty())
                .collect();
            let justification = match state {
                State::FalsePositive => Some(Justification::FalsePositive),
                _ => analysis
                    .justification
                    .as_ref()
                    .and_then(|value| Justification::parse(&value.to_string()).ok())
                    .filter(|value| *value != Justification::FalsePositive),
            };
            let targets = vulnerability
                .vulnerability_targets
                .iter()
                .flat_map(|targets| &targets.0)
                .map(|target| Target {
                    reference: target.bom_ref.clone(),
                    purl: resolve(&target.bom_ref, &references),
                })
                .collect();
            Some(Statement {
                identifiers,
                state,
                justification,
                detail: analysis
                    .detail
                    .as_deref()
                    .map(str::trim)
                    .filter(|detail| !detail.is_empty())
                    .map(str::to_owned),
                targets,
            })
        })
        .collect()
}

/// `bom-ref` to package URL, for every component of a document, nested ones included.
fn collect_references(components: &[Component], references: &mut HashMap<String, String>) {
    for component in components {
        if let (Some(reference), Some(purl)) = (&component.bom_ref, &component.purl) {
            references
                .entry(reference.clone())
                .or_insert_with(|| purl.to_string());
        }
        if let Some(children) = &component.components {
            collect_references(&children.0, references);
        }
    }
}

/// The package URL an `affects[].ref` points to: a component of the document, or the reference
/// itself when it is a package URL. A BOM-Link (`urn:cdx:serial/version#ref`) points to an
/// element of another document, read the same way from its percent-encoded fragment.
fn resolve(reference: &str, references: &HashMap<String, String>) -> Option<String> {
    let reference = match reference.strip_prefix("urn:cdx:") {
        Some(link) => percent_decode(link.split_once('#')?.1)?,
        None => reference.to_owned(),
    };
    references.get(&reference).cloned().or_else(|| {
        reference
            .starts_with("pkg:")
            .then(|| PackageUrl::from_str(&reference).ok())
            .flatten()
            .map(|purl| purl.to_string())
    })
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = std::str::from_utf8(bytes.get(index + 1..index + 3)?).ok()?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

/// A package URL without qualifiers and subpath, the part findings are matched on. `None` when
/// it does not parse.
fn match_key(purl: &str) -> Option<(String, bool)> {
    let mut parsed = PackageUrl::from_str(purl).ok()?;
    let versioned = parsed.version().is_some();
    parsed.clear_qualifiers().without_subpath();
    Some((parsed.to_string(), versioned))
}

/// What an import did with one target of one statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatementResult {
    /// Open findings were ignored.
    Ignored,
    /// The matching findings were already ignored: nothing changed.
    AlreadyIgnored,
    /// No open or ignored finding matches.
    NoMatchingFinding,
    /// The state does not ignore findings (`resolved`, `exploitable`, `in_triage`…).
    Informational,
    /// The reference names neither a component of the document nor a package URL.
    UnresolvedReference,
    /// The package URL has no version, so it would match every version of the package.
    NoVersion,
    /// The statement names no component (`affects` is empty).
    NoTarget,
}

/// One target of one statement, and what the import did with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatementOutcome {
    /// The statement's vulnerability identifier.
    pub vulnerability: String,
    /// The `affects[].ref`, as written.
    pub component: Option<String>,
    pub state: State,
    pub result: StatementResult,
    /// The findings the statement matched (ignored now or before).
    pub findings: Vec<i64>,
}

/// What an import did, returned to CI.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportOutcome {
    /// Statements read, with an analysis state.
    pub statements: usize,
    /// Findings this import ignored.
    pub ignored: usize,
    /// Findings the statements cover that were already ignored.
    pub already_ignored: usize,
    /// Statement targets that changed nothing (informational, unmatched or unresolved).
    pub skipped: usize,
    /// The first statement targets (at most 500) with what was done.
    pub results: Vec<StatementOutcome>,
}

/// Imports VEX statements into a project version (`None`: the latest) with an upload token: the
/// project must be in the token's organization, and be the token's project when it has one;
/// any other project, or a missing version, is [`Error::NotFound`]. A read token
/// ([`crate::tokens::Scope::Read`]) is [`Error::Forbidden`]. The ignores are recorded as made
/// by the token. Runs in one transaction.
pub async fn import(
    database: &(impl ConnectionTrait + TransactionTrait),
    token: &upload_tokens::Model,
    organization_slug: &str,
    project_slug: &str,
    version: Option<&str>,
    statements: &[Statement],
) -> Result<ImportOutcome> {
    let (_, project) = token_project(database, token, organization_slug, project_slug).await?;
    apply(database, token, project.id, version, statements).await
}

/// Like [`import`], for a project already checked against the token and the version it just
/// uploaded to (an upload that carried statements).
pub async fn import_into_project(
    database: &(impl ConnectionTrait + TransactionTrait),
    token: &upload_tokens::Model,
    project_id: i64,
    version: &str,
    statements: &[Statement],
) -> Result<ImportOutcome> {
    projects::Entity::find_by_id(project_id)
        .one(database)
        .await?
        .filter(|project| {
            project.organization_id == token.organization_id
                && token.project_id.is_none_or(|allowed| allowed == project.id)
        })
        .ok_or(Error::NotFound)?;
    apply(database, token, project_id, Some(version), statements).await
}

/// The reason recorded for an ignore imported from a statement: its detail, or a sentence
/// naming the state and justification. Details longer than a reason may be are cut.
fn reason(statement: &Statement) -> String {
    match &statement.detail {
        Some(detail) => detail.chars().take(MAXIMUM_REASON_LENGTH).collect(),
        None => match statement.justification {
            Some(Justification::FalsePositive) | None => {
                format!("VEX statement: {}", statement.state.as_str())
            }
            Some(justification) => format!(
                "VEX statement: {} ({})",
                statement.state.as_str(),
                justification.as_str()
            ),
        },
    }
}

async fn apply(
    database: &(impl ConnectionTrait + TransactionTrait),
    token: &upload_tokens::Model,
    project_id: i64,
    version: Option<&str>,
    statements: &[Statement],
) -> Result<ImportOutcome> {
    crate::tokens::require_upload_scope(token)?;
    let transaction = crate::database::begin_write(database).await?;
    let version = crate::versions::select(&transaction, project_id, version).await?;
    let candidates = findings::Entity::find()
        .filter(findings::Column::VersionId.eq(version.id))
        .filter(findings::Column::Status.ne(Status::Fixed.as_str()))
        .order_by_asc(findings::Column::Id)
        .all(&transaction)
        .await?;
    let facts = vulnerability_facts(
        &transaction,
        candidates
            .iter()
            .map(|finding| finding.vulnerability_id.as_str()),
    )
    .await?;
    // Findings by package URL without qualifiers, each with its identifiers in lower case.
    let mut by_component: HashMap<String, Vec<(findings::Model, BTreeSet<String>)>> =
        HashMap::new();
    for finding in candidates {
        let Some((key, _)) = match_key(&finding.purl) else {
            continue;
        };
        let identifiers = std::iter::once(finding.vulnerability_id.as_str())
            .chain(
                facts
                    .get(&finding.vulnerability_id)
                    .into_iter()
                    .flat_map(|facts| facts.aliases.iter().map(String::as_str)),
            )
            .map(str::to_ascii_lowercase)
            .collect();
        by_component
            .entry(key)
            .or_default()
            .push((finding, identifiers));
    }

    let mut outcome = ImportOutcome {
        statements: statements.len(),
        ..ImportOutcome::default()
    };
    fn record(outcome: &mut ImportOutcome, result: StatementOutcome) {
        if matches!(
            result.result,
            StatementResult::Informational
                | StatementResult::NoMatchingFinding
                | StatementResult::UnresolvedReference
                | StatementResult::NoVersion
                | StatementResult::NoTarget
        ) {
            outcome.skipped += 1;
        }
        if outcome.results.len() < MAXIMUM_LISTED_STATEMENTS {
            outcome.results.push(result);
        }
    }
    for statement in statements {
        let vulnerability = statement.identifiers.first().cloned().unwrap_or_default();
        let ignores = matches!(statement.state, State::NotAffected | State::FalsePositive);
        let outcome_for =
            |component: Option<&Target>, result: StatementResult, findings: Vec<i64>| {
                StatementOutcome {
                    vulnerability: vulnerability.clone(),
                    component: component.map(|target| target.reference.clone()),
                    state: statement.state.clone(),
                    result,
                    findings,
                }
            };
        if statement.targets.is_empty() {
            let result = if ignores {
                StatementResult::NoTarget
            } else {
                StatementResult::Informational
            };
            record(&mut outcome, outcome_for(None, result, Vec::new()));
            continue;
        }
        let identifiers: BTreeSet<String> = statement
            .identifiers
            .iter()
            .map(|id| id.to_ascii_lowercase())
            .collect();
        for target in &statement.targets {
            if !ignores {
                record(
                    &mut outcome,
                    outcome_for(Some(target), StatementResult::Informational, Vec::new()),
                );
                continue;
            }
            let Some((key, versioned)) = target.purl.as_deref().and_then(match_key) else {
                record(
                    &mut outcome,
                    outcome_for(
                        Some(target),
                        StatementResult::UnresolvedReference,
                        Vec::new(),
                    ),
                );
                continue;
            };
            if !versioned {
                record(
                    &mut outcome,
                    outcome_for(Some(target), StatementResult::NoVersion, Vec::new()),
                );
                continue;
            }
            let mut matched = Vec::new();
            let mut ignored_now = 0;
            for (finding, finding_identifiers) in by_component.get_mut(&key).into_iter().flatten() {
                if finding_identifiers.is_disjoint(&identifiers) {
                    continue;
                }
                matched.push(finding.id);
                if Status::parse(&finding.status) == Status::Open {
                    crate::findings::mark_ignored(
                        &transaction,
                        finding.clone(),
                        IgnoredBy::UploadToken(token.id),
                        &reason(statement),
                        statement.justification,
                        None,
                    )
                    .await?;
                    // Later statements about the same finding see it ignored.
                    finding.status = Status::Ignored.as_str().to_owned();
                    ignored_now += 1;
                } else {
                    outcome.already_ignored += 1;
                }
            }
            outcome.ignored += ignored_now;
            let result = if matched.is_empty() {
                StatementResult::NoMatchingFinding
            } else if ignored_now > 0 {
                StatementResult::Ignored
            } else {
                StatementResult::AlreadyIgnored
            };
            record(&mut outcome, outcome_for(Some(target), result, matched));
        }
    }
    transaction.commit().await?;
    if outcome.ignored > 0 {
        tracing::info!(
            project = project_id,
            ignored = outcome.ignored,
            "VEX statements imported"
        );
    }
    Ok(outcome)
}
