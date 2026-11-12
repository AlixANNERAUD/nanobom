//! The component inventory: parsing CycloneDX and SPDX SBOMs and replacing the components of
//! a project version ([`crate::versions`]) with each new upload, keeping the upload history.
//!
//! An upload is a full snapshot: [`ingest`] deletes the version's components and inserts the
//! new ones in one transaction, so a version's components are always those of exactly one SBOM.
//! An upload names its version, or goes to the unnamed one; the first upload naming a version
//! creates it, with the open and ignored findings of the latest version ([`crate::versions`]).
//! Findings are not touched here; the next run ([`crate::evaluation`]) compares them with the
//! new components.
//!
//! Components are identified by their package URL (purl), the only identifier OSV can match.
//! Components without a valid purl, or whose purl gives a version requirement (`^1.2`) rather
//! than a version, are counted and reported back to CI as skipped; files and the operating
//! system entry are ignored altogether. Two components with the same purl are stored once.
//!
//! The SBOM's dependency graph is kept with the components, between the components stored: see
//! [`crate::dependencies`] for what is derived from it and how incomplete graphs are handled.
//!
//! Each component keeps its license as one SPDX license expression string, read from the
//! CycloneDX `licenses` (several entries are joined with `AND`, the conservative reading for a
//! policy) or the SPDX `licenseConcluded` and `licenseDeclared` ([`spdx`]), and bounded by
//! [`MAXIMUM_LICENSE_LENGTH`]. Expressions are only trimmed, not parsed or validated: free-text
//! license names are kept as written, and whoever evaluates them must expect strings that are
//! not valid SPDX.
//!
//! [`list_components`] reads a version's components back a page at a time, for the interface.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    str::FromStr,
};

use chrono::Utc;
use cyclonedx_bom::{
    models::{
        bom::SpecVersion,
        component::{Classification, Component},
        dependency::Dependency,
        license::{LicenseChoice, LicenseIdentifier, Licenses},
    },
    prelude::Bom,
};
use nanobom_entity::{
    component_dependencies, components, organizations, project_versions, projects, sbom_uploads,
    upload_tokens,
};
use packageurl::PackageUrl;
use sea_orm::{
    ActiveModelTrait,
    ActiveValue::Set,
    ColumnTrait, ConnectionTrait, EntityTrait, ExprTrait, QueryFilter, QueryOrder, QuerySelect,
    TransactionSession, TransactionTrait,
    sea_query::{Expr, Func, LikeExpr},
};
use serde::{Deserialize, Serialize};
use serde_json::error::Category;

use self::header::{Context, Header, Text};
use crate::{
    access::{Permission, Reader},
    error::{Error, Result},
    problem::{Field, Problem},
};

mod header;
mod listing;
pub mod spdx;

pub use listing::{
    COMPONENTS_PER_PAGE, ComponentFilter, ComponentPage, ComponentQuery, DependencyKind,
    ListedComponent, MAXIMUM_COMPONENTS_PER_PAGE, list_components,
};

/// CycloneDX specification versions accepted at upload.
pub const SUPPORTED_SPECIFICATION_VERSIONS: [&str; 5] = ["1.3", "1.4", "1.5", "1.6", "1.7"];

/// SPDX versions accepted at upload, as the documents' `spdxVersion` spells them: the JSON
/// serialization of SPDX 2.2 and 2.3, which share the fields nanobom reads.
pub const SUPPORTED_SPDX_VERSIONS: [&str; 2] = ["SPDX-2.2", "SPDX-2.3"];

/// CycloneDX specification versions accepted for a standalone VEX document: `vulnerabilities`
/// appeared in 1.4.
pub const SUPPORTED_VEX_VERSIONS: [&str; 4] = ["1.4", "1.5", "1.6", "1.7"];

/// At most this many skipped components are listed in an upload's response; all are counted.
const MAXIMUM_LISTED_SKIPPED_COMPONENTS: usize = 100;

/// A component's license longer than this many characters is dropped (stored as unknown), so
/// an SBOM cannot bloat the database with license texts pasted as names. It is dropped rather
/// than cut: a truncated expression would name other licenses than the SBOM does.
pub const MAXIMUM_LICENSE_LENGTH: usize = 1000;

/// A component of an SBOM, identified by its package URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryComponent {
    /// The package URL in canonical form, qualifiers included.
    pub purl: String,
    /// The package URL sent to OSV: without qualifiers or subpath.
    pub query_purl: String,
    /// The package URL type: `cargo`, `npm`, `pypi`, `deb`…
    pub ecosystem: String,
    /// The package name, with its namespace when it has one (`@scope/name`, `group/name`).
    pub name: String,
    /// The purl's version; components without one are kept but never matched.
    pub version: Option<String>,
    /// The license, as an SPDX license expression (possibly with free-text names), at most
    /// [`MAXIMUM_LICENSE_LENGTH`] characters; `None` when the SBOM does not give one.
    pub license: Option<String>,
}

/// A component that cannot be tracked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedComponent {
    pub name: String,
    pub version: Option<String>,
    /// Why, in English: no package URL, or why it did not parse.
    pub reason: String,
}

/// The parts of an SBOM nanobom keeps.
#[derive(Debug, Clone)]
pub struct ParsedSbom {
    /// The CycloneDX specification version (`1.6`), or the SPDX version prefixed as SPDX
    /// documents spell it (`SPDX-2.3`).
    pub specification_version: String,
    /// The CycloneDX serial number, or the SPDX document namespace.
    pub serial_number: Option<String>,
    pub components: Vec<InventoryComponent>,
    /// Components without a usable package URL, which cannot be matched against OSV.
    pub skipped_count: usize,
    /// The first skipped components, for the upload's response.
    pub skipped: Vec<SkippedComponent>,
    /// The edges of the SBOM's dependency graph between the components kept, sorted and
    /// without duplicates. Edges to or from a component that is not kept are dropped.
    pub dependencies: Vec<DependencyEdge>,
    /// Whether edges that could lead through a dropped component were lost, whatever the
    /// format: a component without a usable package URL that the graph reaches and leaves, or
    /// an identifier (`bom-ref`, SPDXID) given to components with different package URLs. Paths
    /// derived from the graph may then be missing.
    pub dependencies_partial: bool,
    /// The analysed vulnerabilities of a CycloneDX SBOM's `vulnerabilities`, which the upload
    /// imports like a VEX document ([`crate::vex`]); always empty for SPDX.
    pub vex: Vec<crate::vex::Statement>,
}

/// An edge of an SBOM's dependency graph, between package URLs in canonical form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DependencyEdge {
    /// The component that depends on `child`; `None` for the project itself (the CycloneDX
    /// `metadata.component`, the package an SPDX document describes).
    pub parent: Option<String>,
    pub child: String,
}

/// Parses a CycloneDX or SPDX JSON document, telling them apart by their content
/// (`bomFormat` or `spdxVersion`), never by a header. A document with both a
/// `"bomFormat": "CycloneDX"` and an `spdxVersion` is read as CycloneDX.
///
/// Errors are [`Error::Invalid`] with a problem that tells CI what is wrong: not JSON (with a
/// specific message for XML, SPDX tag-value and SPDX RDF), neither CycloneDX nor SPDX (with a
/// specific message for SPDX 3, recognized by its JSON-LD `@context`), a specification version
/// outside [`SUPPORTED_SPECIFICATION_VERSIONS`] or [`SUPPORTED_SPDX_VERSIONS`], or a document
/// that does not follow it. Values of the document echoed in a message are cut to 200
/// characters.
///
/// CycloneDX documents are deserialized once, straight into the model of their specification
/// version, to keep memory use low on large SBOMs; nested components are flattened. The
/// dependency graph is read from `dependencies`, whose references are the `bom-ref` of
/// components; a reference to `metadata.component` is the project. A reference carried by
/// components with different package URLs is ambiguous: no edge goes through it. See [`spdx`]
/// for SPDX.
pub fn parse(document: &[u8]) -> Result<ParsedSbom> {
    let header: Header = match serde_json::from_slice(document) {
        Ok(header) => header,
        // Valid JSON, but not an object.
        Err(error) if error.classify() == Category::Data => {
            return Err(Error::invalid(Problem::UnknownSbomFormat));
        }
        Err(error) => return Err(Error::invalid(not_json(document, &error))),
    };
    if matches!(&header.format, Some(Text::Text(format)) if format == "CycloneDX") {
        return match header.specification_version {
            Some(Text::Text(version)) => parse_cyclonedx(document, version),
            Some(Text::Other) => Err(Error::invalid(Problem::InvalidCycloneDx {
                detail: "specVersion must be a string".to_owned(),
            })),
            None => parse_cyclonedx(document, String::new()),
        };
    }
    match header.spdx_version {
        Some(Text::Text(version)) => return spdx::parse(document, version),
        Some(Text::Other) => {
            return Err(Error::invalid(Problem::InvalidSpdx {
                detail: "spdxVersion must be a string".to_owned(),
            }));
        }
        None => {}
    }
    match header.context {
        Some(Context {
            version: Some(version),
            ..
        }) => Err(Error::invalid(Problem::UnsupportedSpdxVersion { version })),
        // JSON-LD naming the SPDX 2 vocabulary: an RDF serialization.
        Some(Context {
            names_spdx: true, ..
        }) => Err(Error::invalid(Problem::SpdxRdf)),
        _ => Err(Error::invalid(Problem::UnknownSbomFormat)),
    }
}

/// Why a document is not JSON, naming the formats CI most likely sent by mistake. Only XML and
/// Turtle naming the SPDX vocabulary are SPDX RDF: broken JSON may name it too.
fn not_json(document: &[u8], error: &serde_json::Error) -> Problem {
    let tag_value = document
        .split(|byte| *byte == b'\n')
        .any(|line| line.trim_ascii_start().starts_with(b"SPDXVersion:"));
    let text = document
        .strip_prefix(b"\xEF\xBB\xBF")
        .unwrap_or(document)
        .trim_ascii_start();
    let names_spdx = contains(document, b"spdx.org/rdf");
    if tag_value {
        Problem::SpdxTagValue
    } else if text.starts_with(b"<") {
        if names_spdx {
            Problem::SpdxRdf
        } else {
            Problem::SbomXml
        }
    } else if names_spdx && is_turtle(text) {
        Problem::SpdxRdf
    } else {
        Problem::SbomNotJson {
            detail: capped(&error.to_string()),
        }
    }
}

/// Whether a document starts like Turtle: comments, then a prefix or base declaration
/// (`@prefix`, or `PREFIX` in the SPARQL style).
fn is_turtle(document: &[u8]) -> bool {
    document
        .split(|byte| *byte == b'\n')
        .map(<[u8]>::trim_ascii)
        .find(|line| !line.is_empty() && !line.starts_with(b"#"))
        .is_some_and(|line| {
            ["@prefix", "@base", "prefix ", "base "]
                .iter()
                .any(|start| {
                    line.get(..start.len())
                        .is_some_and(|head| head.eq_ignore_ascii_case(start.as_bytes()))
                })
        })
}

/// Error messages echo values of the document; this many characters of each are kept.
const MAXIMUM_ECHOED_LENGTH: usize = 200;

/// `text` cut to [`MAXIMUM_ECHOED_LENGTH`] characters, with an ellipsis when it was longer, to
/// echo in an error message.
fn capped(text: &str) -> String {
    match text.char_indices().nth(MAXIMUM_ECHOED_LENGTH) {
        Some((end, _)) => format!("{}\u{2026}", &text[..end]),
        None => text.to_owned(),
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn parse_cyclonedx(document: &[u8], specification_version: String) -> Result<ParsedSbom> {
    if !SUPPORTED_SPECIFICATION_VERSIONS.contains(&specification_version.as_str()) {
        return Err(Error::invalid(Problem::UnsupportedSpecificationVersion {
            version: specification_version,
        }));
    }
    let version = SpecVersion::from_str(&specification_version).map_err(|_| {
        Error::invalid(Problem::UnsupportedSpecificationVersion {
            version: specification_version.clone(),
        })
    })?;
    let bom = Bom::parse_from_json_with_version(document, version).map_err(|error| {
        Error::invalid(Problem::InvalidCycloneDx {
            detail: capped(&error.to_string()),
        })
    })?;

    let mut collector = Collector::default();
    let mut references = References::default();
    if let Some(components) = &bom.components {
        collect(&components.0, &mut collector, &mut references);
    }
    references.forget_ambiguous();
    let project = bom
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.component.as_ref())
        .and_then(|component| component.bom_ref.as_ref())
        .map(String::as_str);
    let (dependencies, dependencies_partial) = match &bom.dependencies {
        Some(dependencies) => dependency_edges(&dependencies.0, project, &references),
        None => (Vec::new(), false),
    };
    let mut parsed = collector.finish(
        specification_version,
        bom.serial_number.as_ref().map(ToString::to_string),
        dependencies,
        dependencies_partial,
    );
    parsed.vex = crate::vex::statements(&bom);
    Ok(parsed)
}

/// Reads a standalone CycloneDX VEX document (JSON, a version of [`SUPPORTED_VEX_VERSIONS`]),
/// deserialized straight into the model of its specification version like an SBOM. Errors are
/// [`Error::Invalid`] with a VEX problem: not JSON, not CycloneDX, an unsupported version, or a
/// document that does not follow it.
pub(crate) fn read_vex(document: &[u8]) -> Result<Bom> {
    let header: Header = match serde_json::from_slice(document) {
        Ok(header) => header,
        // Valid JSON, but not an object.
        Err(error) if error.classify() == Category::Data => {
            return Err(Error::invalid(Problem::VexNotCycloneDx));
        }
        Err(error) => {
            return Err(Error::invalid(Problem::VexNotJson {
                detail: capped(&error.to_string()),
            }));
        }
    };
    if !matches!(&header.format, Some(Text::Text(format)) if format == "CycloneDX") {
        return Err(Error::invalid(Problem::VexNotCycloneDx));
    }
    let version = match header.specification_version {
        Some(Text::Text(version)) => version,
        _ => String::new(),
    };
    let unsupported = |version: String| Error::invalid(Problem::UnsupportedVexVersion { version });
    if !SUPPORTED_VEX_VERSIONS.contains(&version.as_str()) {
        return Err(unsupported(version));
    }
    let parsed = SpecVersion::from_str(&version).map_err(|_| unsupported(version.clone()))?;
    Bom::parse_from_json_with_version(document, parsed).map_err(|error| {
        Error::invalid(Problem::InvalidVex {
            detail: capped(&error.to_string()),
        })
    })
}

/// How the `bom-ref`s of an SBOM resolve to the components kept.
#[derive(Debug, Default)]
struct References {
    /// `bom-ref` to package URL, for the components kept.
    resolved: HashMap<String, String>,
    /// `bom-ref`s of components that are not kept for lack of a usable package URL.
    unstored: HashSet<String>,
    /// `bom-ref`s given to several components with different package URLs (or to one kept and
    /// one not kept). An edge naming one cannot be attributed to a component, and mapping it to
    /// whichever came last would make up a link.
    ambiguous: HashSet<String>,
}

impl References {
    fn keep(&mut self, reference: &str, purl: &str) {
        if self.unstored.contains(reference)
            || self
                .resolved
                .get(reference)
                .is_some_and(|known| known != purl)
        {
            self.ambiguous.insert(reference.to_owned());
        }
        self.resolved
            .entry(reference.to_owned())
            .or_insert_with(|| purl.to_owned());
    }

    fn skip(&mut self, reference: &str) {
        if self.resolved.contains_key(reference) {
            self.ambiguous.insert(reference.to_owned());
        }
        self.unstored.insert(reference.to_owned());
    }

    /// Run once every component was seen: ambiguous references resolve to nothing.
    fn forget_ambiguous(&mut self) {
        self.resolved
            .retain(|reference, _| !self.ambiguous.contains(reference));
    }
}

/// The edges between known components, `references` telling which `bom-ref` is which kept
/// component and `project` being the `bom-ref` of the project, and whether links were lost
/// through components that are not kept (see [`ParsedSbom::dependencies_partial`]).
fn dependency_edges(
    dependencies: &[Dependency],
    project: Option<&str>,
    references: &References,
) -> (Vec<DependencyEdge>, bool) {
    let mut edges = BTreeSet::new();
    for dependency in dependencies {
        let parent = if Some(dependency.dependency_ref.as_str()) == project {
            None
        } else {
            match references.resolved.get(&dependency.dependency_ref) {
                Some(purl) => Some(purl.clone()),
                None => continue,
            }
        };
        for child in &dependency.dependencies {
            if Some(child.as_str()) == project {
                continue;
            }
            let Some(child) = references.resolved.get(child) else {
                continue;
            };
            // Two references can share a package URL, and a package can list itself.
            if parent.as_ref() != Some(child) {
                edges.insert(DependencyEdge {
                    parent: parent.clone(),
                    child: child.clone(),
                });
            }
        }
    }
    let reached: HashSet<&str> = dependencies
        .iter()
        .flat_map(|dependency| dependency.dependencies.iter().map(String::as_str))
        .collect();
    // A dropped component only breaks a path if the graph both enters and leaves it; an
    // ambiguous reference loses every edge that names it.
    let partial = reached
        .iter()
        .any(|reference| references.ambiguous.contains(*reference))
        || dependencies.iter().any(|dependency| {
            let reference = dependency.dependency_ref.as_str();
            let leaves = !dependency.dependencies.is_empty();
            (leaves && references.ambiguous.contains(reference))
                || (leaves
                    && references.unstored.contains(reference)
                    && reached.contains(reference))
        });
    (edges.into_iter().collect(), partial)
}

/// The license of a CycloneDX component, from its `licenses`: each entry gives an expression,
/// an SPDX license identifier (`license.id`) or a free-text name (`license.name`).
///
/// One entry gives its value. Several are joined with `AND`, sorted and without duplicates so
/// that the stored value does not change with the order a generator writes them in; compound
/// expressions are put in parentheses. CycloneDX does not say whether several entries are
/// alternatives or all apply, and `AND` is the conservative reading for a license policy: a
/// component is only as acceptable as the most restrictive of its licenses.
///
/// `None` without entries, or when the result exceeds [`MAXIMUM_LICENSE_LENGTH`].
fn cyclonedx_license(licenses: Option<&Licenses>) -> Option<String> {
    let mut terms = BTreeSet::new();
    let mut length = 0;
    for choice in &licenses?.0 {
        let term = match choice {
            LicenseChoice::Expression(expression) => expression.to_string(),
            LicenseChoice::License(license) => match &license.license_identifier {
                LicenseIdentifier::SpdxId(identifier) => identifier.to_string(),
                // Some generators write an expression here too.
                LicenseIdentifier::Name(name) => name.to_string(),
            },
        };
        let term = term.trim();
        if term.is_empty() || terms.contains(term) {
            continue;
        }
        // Checked as entries come, so a component with countless entries stops early.
        length += term.chars().count();
        if length > MAXIMUM_LICENSE_LENGTH {
            return None;
        }
        terms.insert(term.to_owned());
    }
    let license = match terms.len() {
        0 => return None,
        1 => terms.pop_first()?,
        _ => terms
            .into_iter()
            .map(|term| {
                // `AND` binds tighter than `OR` and `WITH` terms read fine either way, so any
                // term with a space is put in parentheses.
                if term.contains(char::is_whitespace) {
                    format!("({term})")
                } else {
                    term
                }
            })
            .collect::<Vec<_>>()
            .join(" AND "),
    };
    bounded_license(&license)
}

/// `license` trimmed, or `None` when it is empty or longer than [`MAXIMUM_LICENSE_LENGTH`]
/// characters.
fn bounded_license(license: &str) -> Option<String> {
    let license = license.trim();
    (!license.is_empty() && license.chars().count() <= MAXIMUM_LICENSE_LENGTH)
        .then(|| license.to_owned())
}

fn collect(components: &[Component], collector: &mut Collector, references: &mut References) {
    for component in components {
        // Files and the operating system describe what was scanned; they are not packages.
        let is_package = !matches!(
            component.component_type,
            Classification::File | Classification::OperatingSystem
        );
        if is_package {
            let purl = component.purl.as_ref().map(ToString::to_string);
            let version = component.version.as_ref().map(ToString::to_string);
            let license = cyclonedx_license(component.licenses.as_ref());
            let kept = collector.add(&component.name, version, purl.as_deref(), license);
            if let Some(reference) = &component.bom_ref {
                match kept {
                    Some(purl) => references.keep(reference, &purl),
                    None => references.skip(reference),
                }
            }
        }
        if let Some(children) = &component.components {
            collect(&children.0, collector, references);
        }
    }
}

/// The components of an SBOM being parsed, whatever its format.
#[derive(Default)]
struct Collector {
    by_purl: BTreeMap<String, InventoryComponent>,
    skipped_count: usize,
    skipped: Vec<SkippedComponent>,
}

impl Collector {
    /// Adds a package, returning its package URL in canonical form when it can be tracked and
    /// recording why otherwise. When several packages share a package URL, the first one's
    /// license is kept.
    fn add(
        &mut self,
        name: &str,
        version: Option<String>,
        purl: Option<&str>,
        license: Option<String>,
    ) -> Option<String> {
        match inventory_component(purl) {
            Ok(mut inventory) => {
                inventory.license = license;
                let purl = inventory.purl.clone();
                self.by_purl.entry(purl.clone()).or_insert(inventory);
                Some(purl)
            }
            Err(reason) => {
                self.skipped_count += 1;
                if self.skipped.len() < MAXIMUM_LISTED_SKIPPED_COMPONENTS {
                    self.skipped.push(SkippedComponent {
                        name: name.to_owned(),
                        version,
                        reason,
                    });
                }
                None
            }
        }
    }

    fn finish(
        self,
        specification_version: String,
        serial_number: Option<String>,
        dependencies: Vec<DependencyEdge>,
        dependencies_partial: bool,
    ) -> ParsedSbom {
        ParsedSbom {
            specification_version,
            serial_number,
            components: self.by_purl.into_values().collect(),
            skipped_count: self.skipped_count,
            skipped: self.skipped,
            dependencies,
            dependencies_partial,
            vex: Vec::new(),
        }
    }
}

fn inventory_component(purl: Option<&str>) -> std::result::Result<InventoryComponent, String> {
    let purl = purl.ok_or_else(|| "no package URL".to_owned())?;
    let mut parsed = PackageUrl::from_str(purl)
        .map_err(|error| format!("invalid package URL {purl:?}: {error}"))?;
    if let Some(version) = parsed.version() {
        // `=1.6.0` (or `==1.6.0`) allows one version, which OSV can match.
        let exact = version.trim_start_matches('=');
        if exact.is_empty() || is_version_requirement(exact) {
            return Err(format!(
                "version requirement {version:?} instead of a resolved version"
            ));
        }
        if exact.len() != version.len() {
            let exact = exact.to_owned();
            parsed
                .with_version(exact)
                .map_err(|error| format!("invalid package URL {purl:?}: {error}"))?;
        }
    }
    let mut query = parsed.clone();
    query.clear_qualifiers().without_subpath();
    let name = match parsed.namespace() {
        Some(namespace) => format!("{namespace}/{}", parsed.name()),
        None => parsed.name().to_owned(),
    };
    Ok(InventoryComponent {
        purl: parsed.to_string(),
        query_purl: query.to_string(),
        ecosystem: parsed.ty().to_owned(),
        name,
        version: parsed.version().map(str::to_owned),
        license: None,
    })
}

/// Whether a purl version is a requirement on versions rather than one version. GitHub's
/// dependency graph export gives the manifest's requirement (`^6.1.2`, `2.*.*`, `1.x`) for
/// packages no lock file pins, and OSV matches such a string against the wrong releases. A
/// `~` is only a requirement at the start: Debian versions contain one (`1.0~rc1-2`). Real
/// versions use `!` (`1!2.0`, a Python epoch), `:` (`1:2.3`, a Debian epoch) and `+`
/// (`v1.2.3+incompatible`, Go), so those are not requirements.
fn is_version_requirement(version: &str) -> bool {
    version.starts_with(['^', '~', '>', '<', '!', '['])
        || version.contains(['*', ' ', ',', '|', '>', '<'])
        || version
            .split('.')
            .any(|segment| segment.eq_ignore_ascii_case("x"))
}

/// Where an upload comes from and which version it describes, as given by CI. Both labels are
/// free text kept for display: at most 300 characters without control characters; blank values
/// are dropped.
#[derive(Debug, Clone, Default)]
pub struct UploadSource {
    pub source_commit: Option<String>,
    pub image_tag: Option<String>,
    /// The project version, checked by [`crate::versions::validate_name`]; `None` for the
    /// unnamed version. Never read from the SBOM.
    pub version: Option<String>,
    /// `Some(true)` makes the version the latest; `Some(false)` keeps a version this upload
    /// creates from becoming the latest. `None`: a created version becomes the latest, an
    /// existing one keeps its flag.
    pub latest: Option<bool>,
}

/// The result of an upload, returned to CI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadOutcome {
    /// The organization slug, normalized.
    pub organization: String,
    /// The project slug, normalized.
    pub project: String,
    pub project_id: i64,
    /// Whether this upload created the project (organization-wide tokens only).
    pub project_created: bool,
    /// The project version the upload went to; empty for the unnamed version.
    pub version: String,
    /// Whether this upload created the version.
    pub version_created: bool,
    /// The identifier of the version, for the caller's next steps.
    #[serde(skip)]
    pub version_id: i64,
    pub upload_id: i64,
    /// Components stored, after removing duplicates.
    pub component_count: usize,
    /// Components skipped for lack of a usable package URL.
    pub components_without_purl: usize,
    /// The first skipped components (at most 100), with the reason.
    pub skipped: Vec<SkippedComponent>,
}

fn optional_label(field: Field, value: Option<String>) -> Result<Option<String>> {
    match value.map(|value| value.trim().to_owned()) {
        Some(value) if value.is_empty() => Ok(None),
        Some(value) if value.chars().count() > 300 || value.chars().any(char::is_control) => {
            Err(Error::invalid(Problem::InvalidLabel(field)))
        }
        other => Ok(other),
    }
}

/// Replaces the components of a project with those of an SBOM uploaded with `token`, creating
/// the project first when the token is organization-wide.
///
/// The token, already authenticated by [`crate::tokens::authenticate`], is the only
/// authorization:
///
/// - an organization other than the token's is [`Error::NotFound`], like a missing one;
/// - a read token ([`crate::tokens::Scope::Read`]) is [`Error::Forbidden`] in its own
///   organization: it neither uploads nor creates projects;
/// - a project-scoped token may upload to its own project only: another existing project is
///   [`Error::Forbidden`], a missing one [`Error::NotFound`] (it cannot create projects);
/// - an organization-wide token may upload to any project of its organization and creates
///   missing ones, with the slug as name.
///
/// No run is started; the caller decides whether to evaluate the project now.
pub async fn ingest(
    database: &(impl ConnectionTrait + TransactionTrait),
    token: &upload_tokens::Model,
    organization_slug: &str,
    project_slug: &str,
    sbom: ParsedSbom,
    source: UploadSource,
) -> Result<UploadOutcome> {
    let organization = organizations::Entity::find()
        .filter(organizations::Column::Slug.eq(organization_slug.trim().to_ascii_lowercase()))
        .one(database)
        .await?
        .filter(|organization| organization.id == token.organization_id)
        .ok_or(Error::NotFound)?;
    store(
        database,
        token,
        organization,
        project_slug,
        sbom,
        source,
        true,
    )
    .await
}

/// Like [`ingest`], into the token's own organization, for clients that do not name one (the
/// Dependency-Track API). With `create_missing` false, a missing project is
/// [`Error::NotFound`] even for an organization-wide token.
pub async fn ingest_into_token_organization(
    database: &(impl ConnectionTrait + TransactionTrait),
    token: &upload_tokens::Model,
    project_slug: &str,
    sbom: ParsedSbom,
    source: UploadSource,
    create_missing: bool,
) -> Result<UploadOutcome> {
    let organization = organizations::Entity::find_by_id(token.organization_id)
        .one(database)
        .await?
        .ok_or(Error::NotFound)?;
    store(
        database,
        token,
        organization,
        project_slug,
        sbom,
        source,
        create_missing,
    )
    .await
}

/// The common part of [`ingest`] and [`ingest_into_token_organization`], once the
/// organization is known to be the token's.
async fn store(
    database: &(impl ConnectionTrait + TransactionTrait),
    token: &upload_tokens::Model,
    organization: organizations::Model,
    project_slug: &str,
    sbom: ParsedSbom,
    source: UploadSource,
    create_missing: bool,
) -> Result<UploadOutcome> {
    crate::tokens::require_upload_scope(token)?;
    let source_commit = optional_label(Field::SourceCommit, source.source_commit)?;
    let image_tag = optional_label(Field::ImageTag, source.image_tag)?;
    let version_name = match source.version.as_deref() {
        Some(name) => crate::versions::validate_name(name)?,
        None => crate::versions::UNNAMED.to_owned(),
    };
    let transaction = crate::database::begin_write(database).await?;
    let existing = crate::projects::find_model(&transaction, organization.id, project_slug).await?;
    let (project, project_created) = match (existing, token.project_id) {
        (Some(project), None) => (project, false),
        (Some(project), Some(allowed)) if project.id == allowed => (project, false),
        (Some(_), Some(_)) => return Err(Error::Forbidden),
        (None, None) if create_missing => (
            crate::projects::insert(
                &transaction,
                organization.id,
                project_slug,
                None,
                &version_name,
                None,
            )
            .await?,
            true,
        ),
        (None, _) => return Err(Error::NotFound),
    };

    let now = Utc::now().fixed_offset();
    // First, to take the project row's write lock: on PostgreSQL it holds back other uploads to
    // the project until this one commits, so that two of them never both create a version past
    // the cap or both move the latest flag. The project's own time is that of its last upload
    // to any version: staleness is per project.
    let mut updated: projects::ActiveModel = project.clone().into();
    updated.last_upload_at = Set(Some(now));
    updated.update(&transaction).await?;
    let prepared = crate::versions::prepare_upload(
        &transaction,
        project.id,
        &version_name,
        source.latest,
        now,
    )
    .await?;
    if let Some(source_version) = &prepared.inherits_from {
        crate::versions::inherit(
            &transaction,
            source_version,
            &prepared.version,
            token.id,
            now,
        )
        .await?;
    }
    let version_created = project_created || prepared.created;
    let version = prepared.version;
    // Before the components, which the edges reference.
    component_dependencies::Entity::delete_many()
        .filter(component_dependencies::Column::VersionId.eq(version.id))
        .exec(&transaction)
        .await?;
    components::Entity::delete_many()
        .filter(components::Column::VersionId.eq(version.id))
        .exec(&transaction)
        .await?;
    let component_count = sbom.components.len();
    let dependencies_partial = sbom.dependencies_partial;
    let rows: Vec<components::ActiveModel> = sbom
        .components
        .into_iter()
        .map(|component| components::ActiveModel {
            project_id: Set(project.id),
            version_id: Set(Some(version.id)),
            purl: Set(component.purl),
            query_purl: Set(component.query_purl),
            ecosystem: Set(component.ecosystem),
            name: Set(component.name),
            version: Set(component.version),
            license: Set(component.license),
            ..Default::default()
        })
        .collect();
    // Bounded batches stay under the bind parameter limits of every database.
    for batch in rows.chunks(500) {
        components::Entity::insert_many(batch.to_vec())
            .exec(&transaction)
            .await?;
    }
    store_dependencies(&transaction, project.id, version.id, &sbom.dependencies).await?;
    let upload = sbom_uploads::ActiveModel {
        project_id: Set(project.id),
        version_id: Set(Some(version.id)),
        upload_token_id: Set(Some(token.id)),
        uploaded_at: Set(now),
        specification_version: Set(sbom.specification_version),
        serial_number: Set(sbom.serial_number),
        source_commit: Set(source_commit),
        image_tag: Set(image_tag),
        component_count: Set(i64::try_from(component_count).unwrap_or(i64::MAX)),
        components_without_purl: Set(i64::try_from(sbom.skipped_count).unwrap_or(i64::MAX)),
        ..Default::default()
    }
    .insert(&transaction)
    .await?;
    let version =
        crate::versions::record_upload(&transaction, version, now, dependencies_partial).await?;
    transaction.commit().await?;

    tracing::info!(
        organization = %organization.slug,
        project = %project.slug,
        version = %version.name,
        components = component_count,
        without_purl = sbom.skipped_count,
        "SBOM uploaded"
    );
    Ok(UploadOutcome {
        organization: organization.slug,
        project: project.slug,
        project_id: project.id,
        project_created,
        version: version.name,
        version_created,
        version_id: version.id,
        upload_id: upload.id,
        component_count,
        components_without_purl: sbom.skipped_count,
        skipped: sbom.skipped,
    })
}

/// Stores the dependency graph of a version whose components were just inserted.
async fn store_dependencies(
    database: &impl ConnectionTrait,
    project_id: i64,
    version_id: i64,
    dependencies: &[DependencyEdge],
) -> Result<()> {
    if dependencies.is_empty() {
        return Ok(());
    }
    // Multi-row inserts do not return every identifier on all databases: read them back.
    let identifiers: HashMap<String, i64> = components::Entity::find()
        .filter(components::Column::VersionId.eq(version_id))
        .all(database)
        .await?
        .into_iter()
        .map(|component| (component.purl, component.id))
        .collect();
    let rows: Vec<component_dependencies::ActiveModel> = dependencies
        .iter()
        .filter_map(|edge| {
            let child = *identifiers.get(&edge.child)?;
            let parent = match &edge.parent {
                Some(purl) => Some(*identifiers.get(purl)?),
                None => None,
            };
            Some(component_dependencies::ActiveModel {
                project_id: Set(project_id),
                version_id: Set(Some(version_id)),
                parent_component_id: Set(parent),
                child_component_id: Set(child),
                ..Default::default()
            })
        })
        .collect();
    for batch in rows.chunks(1000) {
        component_dependencies::Entity::insert_many(batch.to_vec())
            .exec(database)
            .await?;
    }
    Ok(())
}

/// The upload history of a project, every version included, newest first. Requires
/// [`Permission::View`].
pub async fn uploads(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    project_id: i64,
) -> Result<Vec<sbom_uploads::Model>> {
    crate::projects::authorize(database, reader, project_id, Permission::View).await?;
    Ok(sbom_uploads::Entity::find()
        .filter(sbom_uploads::Column::ProjectId.eq(project_id))
        .order_by_desc(sbom_uploads::Column::UploadedAt)
        .order_by_desc(sbom_uploads::Column::Id)
        .all(database)
        .await?)
}

/// The current components of a project's latest version, sorted by package URL. Requires
/// [`Permission::View`].
pub async fn components(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    project_id: i64,
) -> Result<Vec<components::Model>> {
    components_in_version(database, reader, project_id, None).await
}

/// Like [`components()`], for the version named `version` (`None`: the latest); a missing version
/// is [`Error::NotFound`].
pub async fn components_in_version(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    project_id: i64,
    version: Option<&str>,
) -> Result<Vec<components::Model>> {
    let version = crate::versions::find(database, reader, project_id, version).await?;
    Ok(components::Entity::find()
        .filter(components::Column::VersionId.eq(version.id))
        .order_by_asc(components::Column::Purl)
        .all(database)
        .await?)
}

/// A component found by a search.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentMatch {
    pub organization_slug: String,
    pub project_slug: String,
    /// The project version the component is in; empty for the unnamed version. A package
    /// present in several versions of a project is one match per version.
    pub project_version: String,
    /// Whether that version is active; inactive versions are searched only on request.
    pub project_version_active: bool,
    pub purl: String,
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
    pub license: Option<String>,
}

/// At most this many components are returned by a search.
pub const MAXIMUM_SEARCH_RESULTS: usize = 200;

/// The outcome of [`search_results`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResults {
    /// At most [`MAXIMUM_SEARCH_RESULTS`] components.
    pub matches: Vec<ComponentMatch>,
    /// More components matched than `matches` holds.
    pub truncated: bool,
}

/// Finds components by name across the active versions of the projects the reader can see (one
/// match per version holding the package, see [`search_versions`] for inactive ones):
/// `openssl` matches
/// names containing it, `openssl 3.` (or `openssl@3.`) also requires the version to start with
/// `3.`. Names and versions match case-insensitively; `%` and `_` are taken literally.
/// Results are sorted by name then version and capped at [`MAXIMUM_SEARCH_RESULTS`]; an empty
/// name returns nothing rather than every component. [`search_results`] also says whether the
/// cap cut the list.
pub async fn search(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    query: &str,
) -> Result<Vec<ComponentMatch>> {
    Ok(search_results(database, reader, query).await?.matches)
}

/// [`search`], and whether more components matched than were returned.
pub async fn search_results(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    query: &str,
) -> Result<SearchResults> {
    search_by_license(database, reader, query, "").await
}

/// [`search_results`], also requiring the license to contain `license` (case-insensitively,
/// `%` and `_` taken literally) when it is not blank: `GPL` finds `GPL-3.0-only` and
/// `MIT OR GPL-2.0-or-later`. Either `query` or `license` may be blank, not both; a blank
/// `query` matches every name.
pub async fn search_by_license(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    query: &str,
    license: &str,
) -> Result<SearchResults> {
    search_versions(database, reader, query, license, false).await
}

/// [`search_by_license`], across inactive versions too when `include_inactive` is true.
pub async fn search_versions(
    database: &impl ConnectionTrait,
    reader: impl Into<Reader>,
    query: &str,
    license: &str,
    include_inactive: bool,
) -> Result<SearchResults> {
    let reader = reader.into();
    let query = query.trim();
    let license = license.trim();
    let (name, version) = match query.split_once(['@', ' ']) {
        Some((name, version)) => (name.trim(), Some(version.trim())),
        None => (query, None),
    };
    if name.is_empty() && license.is_empty() {
        return Ok(SearchResults {
            matches: Vec::new(),
            truncated: false,
        });
    }
    let organizations: std::collections::HashMap<i64, String> =
        crate::organizations::list(database, reader)
            .await?
            .into_iter()
            .map(|organization| (organization.id, organization.slug))
            .collect();
    let projects: std::collections::HashMap<i64, (String, String)> = projects::Entity::find()
        .filter(projects::Column::OrganizationId.is_in(organizations.keys().copied()))
        .all(database)
        .await?
        .into_iter()
        .filter(|project| reader.reaches_project(project.id))
        .map(|project| {
            let organization = organizations[&project.organization_id].clone();
            (project.id, (organization, project.slug))
        })
        .collect();
    // Names and versions keep their case in package URLs (Maven, Go, `1.0-RC1`), and `LIKE` is
    // case-sensitive on PostgreSQL (and on SQLite for non-ASCII letters), so both sides are
    // compared in lower case.
    let mut select = components::Entity::find()
        .filter(components::Column::ProjectId.is_in(projects.keys().copied()));
    if !include_inactive {
        select =
            select.filter(components::Column::VersionId.in_subquery(crate::versions::active_ids()));
    }
    if !name.is_empty() {
        select = select.filter(contains_text(components::Column::Name, name));
    }
    if !license.is_empty() {
        select = select.filter(contains_text(components::Column::License, license));
    }
    if let Some(version) = version.filter(|version| !version.is_empty()) {
        select = select.filter(
            Expr::expr(Func::lower(Expr::col(components::Column::Version))).like(
                LikeExpr::new(format!("{}%", escape_like(&version.to_lowercase()))).escape('\\'),
            ),
        );
    }
    let models = select
        .order_by_asc(components::Column::Name)
        .order_by_asc(components::Column::Version)
        // The identifier breaks ties, or which rows the limit keeps would be arbitrary.
        .order_by_asc(components::Column::Id)
        // One more than returned, to know whether the cap cut the list.
        .limit(MAXIMUM_SEARCH_RESULTS as u64 + 1)
        .all(database)
        .await?;
    let truncated = models.len() > MAXIMUM_SEARCH_RESULTS;
    let models: Vec<components::Model> = models.into_iter().take(MAXIMUM_SEARCH_RESULTS).collect();
    let versions: HashMap<i64, project_versions::Model> = project_versions::Entity::find()
        .filter(
            project_versions::Column::Id
                .is_in(models.iter().filter_map(|component| component.version_id)),
        )
        .all(database)
        .await?
        .into_iter()
        .map(|version| (version.id, version))
        .collect();
    let matches = models
        .into_iter()
        .map(|component| {
            let (organization_slug, project_slug) = projects[&component.project_id].clone();
            let version = component.version_id.and_then(|id| versions.get(&id));
            ComponentMatch {
                organization_slug,
                project_slug,
                project_version: version
                    .map(|version| version.name.clone())
                    .unwrap_or_default(),
                project_version_active: version.is_some_and(|version| version.active),
                purl: component.purl,
                ecosystem: component.ecosystem,
                name: component.name,
                version: component.version,
                license: component.license,
            }
        })
        .collect();
    Ok(SearchResults { matches, truncated })
}

/// `column` contains `text`, both in lower case: see [`search_results`].
fn contains_text(column: components::Column, text: &str) -> Expr {
    Expr::expr(Func::lower(Expr::col(column)))
        .like(LikeExpr::new(format!("%{}%", escape_like(&text.to_lowercase()))).escape('\\'))
}

/// Escapes the wildcards of a `LIKE` pattern, so `_` in a package name matches itself.
pub(crate) fn escape_like(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '%' | '_' | '\\') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}
