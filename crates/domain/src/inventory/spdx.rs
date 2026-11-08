//! SPDX 2.2 and 2.3 JSON documents, mapped onto the same inventory as CycloneDX.
//!
//! The model below holds only the fields nanobom reads, and ignores the others: generators
//! disagree on the rest of the schema (licenses, checksums, files), and a strict model would
//! refuse documents for fields that do not matter here. No maintained crate parses SPDX
//! leniently, and none parses SPDX 3.
//!
//! - **Components** are the packages with a package URL: an `externalRefs` entry of type `purl`
//!   in the `PACKAGE-MANAGER` category (`PACKAGE_MANAGER` in SPDX 2.2). Packages without one
//!   are skipped and counted, like CycloneDX components without a purl. Files are not
//!   packages, and neither are packages whose purpose is `FILE` or `OPERATING-SYSTEM`.
//! - **The project** is what the document describes (`DESCRIBES` relationships from the
//!   document, `documentDescribes` in SPDX 2.2): a directory, an image or a repository. It is
//!   not a component, like the CycloneDX `metadata.component`.
//! - **Dependencies** come from `DEPENDS_ON` and `DEPENDENCY_OF` (and its `BUILD_`, `DEV_`,
//!   `OPTIONAL_`, `PROVIDED_`, `RUNTIME_` and `TEST_` variants), and from `CONTAINS` between
//!   two packages (an archive bundling a library). A `CONTAINS` from the project is not an
//!   edge: a scanned directory or image contains every package, direct dependency or not
//!   (Syft lists them all that way).
//!
//! GitHub's dependency graph export makes the repository depend on every package of an
//! ecosystem whose lock file it does not read as a graph (all crates of a `Cargo.lock`), which
//! would show every transitive package as a direct dependency. So edges from the project to
//! the packages of an ecosystem are kept only when the document has edges between packages of
//! that ecosystem; otherwise paths are missing rather than wrong (see
//! [`crate::dependencies`]).

use std::collections::{BTreeSet, HashMap, HashSet};

use serde::Deserialize;

use super::{Collector, DependencyEdge, ParsedSbom, SUPPORTED_SPDX_VERSIONS};
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
    #[serde(default)]
    document_describes: Vec<String>,
    #[serde(default)]
    packages: Vec<Package>,
    #[serde(default)]
    relationships: Vec<Relationship>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Package {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    #[serde(default)]
    name: String,
    version_info: Option<String>,
    primary_package_purpose: Option<String>,
    #[serde(default)]
    external_refs: Vec<ExternalReference>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExternalReference {
    reference_category: String,
    reference_type: String,
    reference_locator: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Relationship {
    spdx_element_id: String,
    relationship_type: String,
    related_spdx_element: String,
}

/// Parses an SPDX JSON document whose `spdxVersion` is `version`.
pub(super) fn parse(document: &[u8], version: String) -> Result<ParsedSbom> {
    if !SUPPORTED_SPDX_VERSIONS.contains(&version.as_str()) {
        return Err(Error::invalid(Problem::UnsupportedSpdxVersion { version }));
    }
    let document: Document = serde_json::from_slice(document).map_err(|error| {
        Error::invalid(Problem::InvalidSpdx {
            detail: error.to_string(),
        })
    })?;

    let projects = described(&document);
    let mut collector = Collector::default();
    // Each kept package's SPDX identifier, mapped to its package URL in canonical form.
    let mut references: HashMap<&str, String> = HashMap::new();
    for package in &document.packages {
        let is_package = !matches!(
            package.primary_package_purpose.as_deref(),
            Some("FILE" | "OPERATING-SYSTEM")
        );
        if projects.contains(package.spdx_id.as_str()) || !is_package {
            continue;
        }
        let purl = package
            .external_refs
            .iter()
            .find(|reference| {
                matches!(
                    reference.reference_category.as_str(),
                    "PACKAGE-MANAGER" | "PACKAGE_MANAGER"
                ) && reference.reference_type == "purl"
            })
            .map(|reference| reference.reference_locator.as_str());
        if let Some(purl) = collector.add(&package.name, package.version_info.clone(), purl) {
            references.insert(&package.spdx_id, purl);
        }
    }
    let dependencies =
        dependency_edges(&document.relationships, &projects, &references, &collector);
    Ok(collector.finish(version, document.document_namespace, dependencies, false))
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
        match relationship.relationship_type.as_str() {
            "DESCRIBES" if relationship.spdx_element_id == document_id => {
                described.insert(&relationship.related_spdx_element);
            }
            "DESCRIBED_BY" if relationship.related_spdx_element == document_id => {
                described.insert(&relationship.spdx_element_id);
            }
            _ => {}
        }
    }
    described
}

fn dependency_edges(
    relationships: &[Relationship],
    projects: &HashSet<&str>,
    references: &HashMap<&str, String>,
    collector: &Collector,
) -> Vec<DependencyEdge> {
    let mut edges = BTreeSet::new();
    for relationship in relationships {
        let (from, to) = (
            relationship.spdx_element_id.as_str(),
            relationship.related_spdx_element.as_str(),
        );
        let (parent, child, containment) = match relationship.relationship_type.as_str() {
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
        let Some(child) = references.get(child) else {
            continue;
        };
        let parent = if projects.contains(parent) {
            if containment {
                continue;
            }
            None
        } else {
            match references.get(parent) {
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

    let graphed: HashSet<&str> = edges
        .iter()
        .filter(|edge| edge.parent.is_some())
        .filter_map(|edge| collector.ecosystem(&edge.child))
        .collect();
    edges
        .into_iter()
        .filter(|edge| {
            edge.parent.is_some()
                || collector
                    .ecosystem(&edge.child)
                    .is_some_and(|ecosystem| graphed.contains(ecosystem))
        })
        .collect()
}

/// The SPDX version of an SPDX 3 document, from its JSON-LD context
/// (`https://spdx.org/rdf/3.0.1/spdx-context.jsonld` is `SPDX-3.0.1`), or `None` when the
/// context is not SPDX's.
pub(super) fn version_3(context: &serde_json::Value) -> Option<String> {
    let urls: Vec<&str> = match context {
        serde_json::Value::String(url) => vec![url.as_str()],
        serde_json::Value::Array(values) => values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect(),
        _ => Vec::new(),
    };
    urls.into_iter().find_map(|url| {
        let version = url.split_once("spdx.org/rdf/")?.1.split('/').next()?;
        Some(format!("SPDX-{version}"))
    })
}
