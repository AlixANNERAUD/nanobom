//! SPDX 2.2 and 2.3 JSON documents, mapped onto the same inventory as CycloneDX.
//!
//! The model below holds only the fields nanobom reads, and ignores the others: generators
//! disagree on the rest of the schema (checksums, files, license details), and a strict model
//! would refuse documents for fields that do not matter here. For the same reason a `null` or
//! missing field counts as absent, even where the specification requires it; a relationship
//! missing one of its ends is ignored. No maintained crate parses SPDX leniently, and none
//! parses SPDX 3.
//!
//! - **Components** are the packages with a package URL: an `externalRefs` entry of type `purl`
//!   in the `PACKAGE-MANAGER` category (`PACKAGE_MANAGER` in SPDX 2.2, or no category); the
//!   first one when a package has several. Packages without one are skipped and counted, like CycloneDX
//!   components without a purl. Files are not packages, and neither are packages whose
//!   purpose is `FILE` or `OPERATING-SYSTEM`.
//! - **Licenses** come from `licenseConcluded`, or `licenseDeclared` when the former is
//!   missing, `NOASSERTION` or `NONE`. Either is already an SPDX license expression and is kept
//!   as written, `LicenseRef-` identifiers included; `NOASSERTION` and `NONE` alone mean no
//!   license is known. A value that is not a string is ignored, like a missing one.
//! - **The project** is what the document describes (`DESCRIBES` relationships from the
//!   document, `documentDescribes` in SPDX 2.2): a directory, an image or a repository. It is
//!   not a component, like the CycloneDX `metadata.component`.
//! - **Dependencies** come from `DEPENDS_ON` and `DEPENDENCY_OF` (and its `BUILD_`, `DEV_`,
//!   `OPTIONAL_`, `PROVIDED_`, `RUNTIME_` and `TEST_` variants), and from `CONTAINS` between
//!   two packages (an archive bundling a library). A `CONTAINS` from the project is not an
//!   edge: a scanned directory or image contains every package, direct dependency or not
//!   (Syft lists them all that way). An `SPDXID` given to several packages that do not map to
//!   the same package URL is ambiguous: no edge goes through it.
//!
//! GitHub's dependency graph export makes the repository depend on every package of a lock
//! file it does not read as a graph (all crates of a `Cargo.lock`), which would show every
//! transitive package as a direct dependency. A repository can hold such a flat list next to
//! a graphed lock file of the same ecosystem, so an edge from the project to a package is kept
//! only when that package is itself linked to another package. A direct dependency that
//! depends on nothing and that nothing else depends on is then left out: its path is missing
//! rather than made up (see [`crate::dependencies`]).

use std::collections::{BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Deserializer};

use super::{
    Collector, DependencyEdge, ParsedSbom, SUPPORTED_SPDX_VERSIONS, bounded_license, capped,
};
use crate::{
    error::{Error, Result},
    problem::Problem,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Document {
    #[serde(rename = "SPDXID")]
    spdx_id: Option<String>,
    document_namespace: Option<String>,
    /// Deprecated in SPDX 2.3 in favour of `DESCRIBES` relationships, still written by some
    /// generators.
    #[serde(default, deserialize_with = "nullable")]
    document_describes: Vec<String>,
    #[serde(default, deserialize_with = "nullable")]
    packages: Vec<Package>,
    #[serde(default, deserialize_with = "nullable")]
    relationships: Vec<Relationship>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Package {
    #[serde(rename = "SPDXID")]
    spdx_id: Option<String>,
    #[serde(default, deserialize_with = "nullable")]
    name: String,
    version_info: Option<String>,
    primary_package_purpose: Option<String>,
    #[serde(default, deserialize_with = "nullable")]
    external_refs: Vec<ExternalReference>,
    #[serde(default, deserialize_with = "lenient_text")]
    license_concluded: Option<String>,
    #[serde(default, deserialize_with = "lenient_text")]
    license_declared: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExternalReference {
    reference_category: Option<String>,
    reference_type: Option<String>,
    reference_locator: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Relationship {
    spdx_element_id: Option<String>,
    relationship_type: Option<String>,
    related_spdx_element: Option<String>,
}

/// Reads `null` as the default value, like a missing field.
fn nullable<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// Reads a string, and any other JSON value as absent.
fn lenient_text<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(
        match Option::<serde_json::Value>::deserialize(deserializer)? {
            Some(serde_json::Value::String(text)) => Some(text),
            _ => None,
        },
    )
}

/// The license of a package (see the [module](self)), within the bounds of
/// [`super::MAXIMUM_LICENSE_LENGTH`].
fn license(package: &Package) -> Option<String> {
    fn known(value: Option<&str>) -> Option<&str> {
        value.map(str::trim).filter(|value| {
            !value.is_empty()
                && !value.eq_ignore_ascii_case("NOASSERTION")
                && !value.eq_ignore_ascii_case("NONE")
        })
    }
    known(package.license_concluded.as_deref())
        .or_else(|| known(package.license_declared.as_deref()))
        .and_then(bounded_license)
}

/// Parses an SPDX JSON document whose `spdxVersion` is `version`.
pub(super) fn parse(document: &[u8], version: String) -> Result<ParsedSbom> {
    if !SUPPORTED_SPDX_VERSIONS.contains(&version.as_str()) {
        return Err(Error::invalid(Problem::UnsupportedSpdxVersion { version }));
    }
    let document: Document = serde_json::from_slice(document).map_err(|error| {
        Error::invalid(Problem::InvalidSpdx {
            detail: capped(&error.to_string()),
        })
    })?;

    let projects = described(&document);
    let mut collector = Collector::default();
    let mut references = References::default();
    for package in &document.packages {
        let id = package.spdx_id.as_deref();
        if id.is_some_and(|id| projects.contains(id)) {
            continue;
        }
        let is_package = !matches!(
            package.primary_package_purpose.as_deref(),
            Some("FILE" | "OPERATING-SYSTEM")
        );
        if !is_package {
            if let Some(id) = id {
                references.discard(id, false);
            }
            continue;
        }
        let purl = package
            .external_refs
            .iter()
            .find(|reference| {
                matches!(
                    reference.reference_category.as_deref(),
                    None | Some("PACKAGE-MANAGER" | "PACKAGE_MANAGER")
                ) && reference.reference_type.as_deref() == Some("purl")
            })
            .and_then(|reference| reference.reference_locator.as_deref());
        let kept = collector.add(
            &package.name,
            package.version_info.clone(),
            purl,
            license(package),
        );
        match (id, kept) {
            (Some(id), Some(purl)) => references.keep(id, purl),
            (Some(id), None) => references.discard(id, true),
            (None, _) => {}
        }
    }
    references.forget_ambiguous();
    let (dependencies, partial) = dependency_edges(&document.relationships, &projects, &references);
    Ok(collector.finish(version, document.document_namespace, dependencies, partial))
}

/// The SPDX identifiers of what the document describes: the project.
fn described(document: &Document) -> HashSet<&str> {
    let document_id = document.spdx_id.as_deref().unwrap_or("SPDXRef-DOCUMENT");
    let mut described: HashSet<&str> = document
        .document_describes
        .iter()
        .map(String::as_str)
        .collect();
    for relationship in &document.relationships {
        let (Some(from), Some(kind), Some(to)) = (
            relationship.spdx_element_id.as_deref(),
            relationship.relationship_type.as_deref(),
            relationship.related_spdx_element.as_deref(),
        ) else {
            continue;
        };
        match kind {
            "DESCRIBES" if from == document_id => {
                described.insert(to);
            }
            "DESCRIBED_BY" if to == document_id => {
                described.insert(from);
            }
            _ => {}
        }
    }
    described
}

/// How the `SPDXID`s of a document resolve to the components kept.
#[derive(Default)]
struct References<'a> {
    /// `SPDXID` to package URL, for the packages kept.
    resolved: HashMap<&'a str, String>,
    /// `SPDXID`s of packages without a usable package URL.
    skipped: HashSet<&'a str>,
    /// `SPDXID`s of packages not kept, skipped or not packages at all (files, the operating
    /// system).
    dropped: HashSet<&'a str>,
    /// `SPDXID`s given to several packages with different package URLs, or to one kept and
    /// one not: an edge naming one cannot be attributed to a component, and attributing it to
    /// either would make up a link.
    ambiguous: HashSet<&'a str>,
}

impl<'a> References<'a> {
    fn keep(&mut self, id: &'a str, purl: String) {
        if self.dropped.contains(id) || self.resolved.get(id).is_some_and(|known| *known != purl) {
            self.ambiguous.insert(id);
        }
        self.resolved.entry(id).or_insert(purl);
    }

    fn discard(&mut self, id: &'a str, skipped: bool) {
        if self.resolved.contains_key(id) {
            self.ambiguous.insert(id);
        }
        self.dropped.insert(id);
        if skipped {
            self.skipped.insert(id);
        }
    }

    /// Run once every package was seen: ambiguous identifiers resolve to nothing.
    fn forget_ambiguous(&mut self) {
        let ambiguous = &self.ambiguous;
        self.resolved.retain(|id, _| !ambiguous.contains(id));
    }
}

/// The edges between kept components, and whether links were lost through packages that are
/// not kept (see [`ParsedSbom::dependencies_partial`]).
fn dependency_edges(
    relationships: &[Relationship],
    projects: &HashSet<&str>,
    references: &References,
) -> (Vec<DependencyEdge>, bool) {
    let mut edges = BTreeSet::new();
    // The identifiers relationships lead to and from, to tell whether a path went through a
    // package that is not kept.
    let mut entered = HashSet::new();
    let mut left = HashSet::new();
    for relationship in relationships {
        let (Some(from), Some(kind), Some(to)) = (
            relationship.spdx_element_id.as_deref(),
            relationship.relationship_type.as_deref(),
            relationship.related_spdx_element.as_deref(),
        ) else {
            continue;
        };
        let (parent, child, containment) = match kind {
            "DEPENDS_ON" => (from, to, false),
            "CONTAINS" => (from, to, true),
            "CONTAINED_BY" => (to, from, true),
            kind if kind == "DEPENDENCY_OF" || kind.ends_with("_DEPENDENCY_OF") => {
                (to, from, false)
            }
            _ => continue,
        };
        if projects.contains(child) {
            continue;
        }
        left.insert(parent);
        entered.insert(child);
        if containment && projects.contains(parent) {
            continue;
        }
        let Some(child) = references.resolved.get(child) else {
            continue;
        };
        let parent = if projects.contains(parent) {
            None
        } else {
            match references.resolved.get(parent) {
                Some(purl) => Some(purl.clone()),
                None => continue,
            }
        };
        // Two packages can share a package URL, and a package can list itself.
        if parent.as_ref() != Some(child) {
            edges.insert(DependencyEdge {
                parent,
                child: child.clone(),
            });
        }
    }

    // Edges from the project are kept only to packages linked to another package, so that a
    // flat list of every package of a lock file does not make them all direct dependencies.
    let linked: HashSet<&str> = edges
        .iter()
        .filter_map(|edge| Some([edge.parent.as_deref()?, edge.child.as_str()]))
        .flatten()
        .collect();
    let edges = edges
        .iter()
        .filter(|edge| edge.parent.is_some() || linked.contains(edge.child.as_str()))
        .cloned()
        .collect();

    let partial = entered
        .iter()
        .chain(&left)
        .any(|id| references.ambiguous.contains(id))
        || references
            .skipped
            .iter()
            .any(|id| entered.contains(id) && left.contains(id));
    (edges, partial)
}
