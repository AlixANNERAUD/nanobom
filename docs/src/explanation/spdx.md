# SPDX documents

nanobom was built around CycloneDX, and reads SPDX by mapping it onto the same inventory: the
same components, identified by the same package URLs, matched against OSV the same way. What a
project shows does not depend on the format, except for the dependency graph, which SPDX
generators describe less consistently. The exact mapping is in the
[upload API reference](../reference/upload-api.md#spdx); this page explains its choices and what
is lost.

## Packages and the project

An SPDX document lists `packages`, and says which of them it is about with a `DESCRIBES`
relationship. nanobom keeps the packages that have a package URL, like CycloneDX components, and
treats the described package as the project, like the CycloneDX `metadata.component`. A
package without a package URL is skipped and reported to CI the same way in both formats. A
package with several package URLs (several `purl` references) gets the first one: CycloneDX
gives a component one package URL, and the others usually name the same package in another
ecosystem's terms.

Generators also disagree on which fields they fill. nanobom reads a `null` or missing field as
absent rather than refusing the document, even for fields SPDX requires: a package without a
name is still matched by its package URL, a relationship missing one of its ends is ignored.

Two packages with the same `SPDXID` break the document's own rules. If they have the same
package URL, nothing is lost; otherwise a relationship naming that identifier cannot be traced
to one of them, so it is ignored rather than attributed to either, and the graph is marked
incomplete.

Generators do not describe the same thing. Syft and Trivy describe what they scanned (a
directory or an image), GitHub describes the repository. None of these is a package of an
ecosystem OSV covers, so leaving the described package out loses nothing; but a package of your
own (`pkg:cargo/your-crate@0.1.0`, found in the scanned lock file) stays a component, as it does
in their CycloneDX output.

SPDX `files` and `snippets` are ignored: OSV matches packages, not files.

## Dependency graph

A CycloneDX document names the project's direct dependencies in one place: the `dependencies`
entry of `metadata.component`. SPDX expresses dependencies with relationships (`DEPENDS_ON`,
`DEPENDENCY_OF` and its variants, `CONTAINS`), and generators use them differently:

- **Syft** writes `DEPENDENCY_OF` between packages when the lock file gives them, and makes the
  scanned directory or image `CONTAINS` every package, direct dependency or not. Containment is
  therefore not read as a dependency of the project: it would make every package direct.
  `CONTAINS` between two packages (an archive bundling a library) is read as a dependency.
- **Trivy** hangs the direct dependencies from an entry for the lock file, which has no package
  URL. nanobom does not bridge edges through packages it does not store, so the project's direct
  dependencies are not known, as with Trivy's CycloneDX output.
- **GitHub's dependency graph export** makes the repository `DEPENDS_ON` its dependencies. For
  `package-lock.json` these are the direct dependencies, development ones included, with
  `DEPENDS_ON` between packages below them. For `Cargo.lock` the repository depends on every
  crate, transitive ones included, with no edge between crates.

The last case would show every crate as a direct dependency, and a repository can hold such a
flat list next to a graphed lock file of the same ecosystem (two npm projects in one
repository, for example). Nothing in the document tells the two apart, so nanobom keeps an
edge from the project to a package only when that package is also linked to another package,
as a dependency or a dependent. A flat list is then ignored: the path is missing rather than
wrong, the rule of [Dependency paths](dependency-paths.md#limits). The price is a direct
dependency that depends on nothing and that no other package depends on, such as a small
utility library: it gets no path, even from a complete graph. A project whose only
dependencies are such packages gets no path at all.

In practice, **introduced via** is shown less often for SPDX uploads than for CycloneDX ones from
the ecosystem's own generator. If you rely on it, prefer a CycloneDX generator that describes the
project (cargo-cyclonedx, cyclonedx-npm).

## Versions and serializations

- **SPDX 2.2 and 2.3 JSON** share the fields nanobom reads; SPDX 2.2 spells the purl category
  `PACKAGE_MANAGER` and may name the project in `documentDescribes`, both accepted.
- **Tag-value and RDF** are other serializations of the same model. Every generator that writes
  them also writes JSON, so nanobom refuses them with a message saying so rather than carrying
  three parsers.
- **SPDX 3.0** is a different model (a JSON-LD graph of elements), and no maintained Rust library
  reads it. It is refused with a message naming the supported versions; generators still default
  to SPDX 2.3.

## What else is lost

Nothing nanobom uses for CycloneDX is missing from SPDX, with two differences besides the graph:

- **Version requirements.** GitHub's export gives the manifest's requirement (`^6.1.2`) for
  packages no lock file pins. A requirement is not a version: OSV would match it against the
  wrong releases, so such packages are skipped and reported in `skipped`. The same rule applies
  to CycloneDX documents, where generators rarely write requirements.
- **Serial number.** SPDX has none; the document namespace, a URI unique to each document, is
  recorded in its place.
