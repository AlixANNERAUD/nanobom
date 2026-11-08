# Dependency paths

A finding names the vulnerable component, which is often deep in the dependency tree: `lodash
4.17.20`, required by a template engine, required by the web framework the project uses. The
project's manifest names the web framework, not lodash, so that is what a developer upgrades.
When the SBOM describes its dependency graph, nanobom shows that link: the finding was
**introduced via** the web framework.

## Where the graph comes from

A CycloneDX document describes the project itself in `metadata.component`, and its dependency
graph in `dependencies`: one entry per component, by `bom-ref`, listing the components it
depends on directly.

```json
{
  "metadata": { "component": { "name": "shop", "bom-ref": "shop" } },
  "components": [
    { "name": "web-framework", "bom-ref": "framework", "purl": "pkg:npm/web-framework@2.1.0" },
    { "name": "template-engine", "bom-ref": "engine", "purl": "pkg:npm/template-engine@0.9.0" },
    { "name": "lodash", "bom-ref": "lodash", "purl": "pkg:npm/lodash@4.17.20" }
  ],
  "dependencies": [
    { "ref": "shop", "dependsOn": ["framework"] },
    { "ref": "framework", "dependsOn": ["engine"] },
    { "ref": "engine", "dependsOn": ["lodash"] }
  ]
}
```

An SPDX document gives the same information as relationships between packages (`DEPENDS_ON`,
`DEPENDENCY_OF`), the project being the package the document describes; generators fill them
less consistently (see [SPDX documents](spdx.md#dependency-graph)).

The components the project's own entry lists are its **direct dependencies**. Each upload stores
the graph between the components it keeps, and replaces the previous graph along with the
components: like the components, the graph is always the latest SBOM's.

## How paths are chosen

For a vulnerable component, nanobom finds every direct dependency that leads to it and, for each,
the shortest path from it to the component. They are shown shortest first:

- on the finding's page, under **Introduced via**: `web-framework 2.1.0 → template-engine 0.9.0 →
  lodash 4.17.20`. A component that is itself a direct dependency is a path of its own, marked
  *direct dependency*. At most 5 paths are shown; the others are counted.
- on the project page, in the **Introduced via** column: the direct dependencies, the first two
  by name (with their versions only when several versions of one lead to the component) and how
  many more, or *direct* when the component is one itself;
- in [webhooks](../reference/webhooks.md#findingsnew) and in the
  [evaluation returned to CI](../reference/upload-api.md#the-evaluation-object), as
  `introduced_via`: the names of the direct dependencies.

When several paths of the same length lead from a direct dependency, one of them is shown. Paths
longer than 32 components are not followed. The graph may have cycles; they do not change the
result.

A component that is a direct dependency and is also required by other direct dependencies lists
them all: they may keep requiring the vulnerable version after you upgrade your own.

## Limits

A path may be missing, and with several copies of a package it may combine them, but every link
in it is in the SBOM: nanobom shows no path rather than a guess.

- **No graph, or no project in it.** Without any dependency of the project itself, nothing is
  derived, and the finding's page says the SBOM does not tell which components the project
  depends on directly. nanobom does not take the components nothing depends on for the direct
  dependencies: in an environment, a package the project requires directly is often required by
  another one too, and the guess would hide it.
- **Components that are not stored.** The graph is kept between the components nanobom stores,
  those with a package URL. An edge to or from a component without one, or a file, is dropped
  rather than bridged, so a path never skips a component: a component reached only through one
  is not linked to the project. When the graph enters and leaves such a component, the finding's
  page adds that some links could not be followed, and other paths may exist.
- **References shared by several packages.** A `bom-ref` is meant to be unique. When two
  components with different package URLs carry the same one, nanobom cannot tell which one an
  edge means, so it drops every edge that names it, and says so like above.
- **Copies of a package.** Paths are between packages, identified by package URL, not between
  installed copies of them. Components with the same package URL are stored once, with the
  edges of all their copies: if two nested copies of `foo 1.0.0` in an npm tree resolve `dep` to
  different versions, `foo 1.0.0` leads to both, and a path through `foo 1.0.0` may combine the
  link of one copy with a link into the other. Each link exists in the SBOM, but the whole path
  may not match one installation.
- **Gone components.** A finding whose component is no longer in the latest SBOM has no path,
  and its page does not show the card.

Generators fill the graph unevenly. With the versions nanobom is tested with:

| Generator | Graph | Paths |
| --- | --- | --- |
| cargo-cyclonedx 0.5.9 | complete, from the crate | yes |
| cyclonedx-npm 6.0.1 | complete, from the package | yes |
| cyclonedx-py 8.0.1, `environment` | between installed packages; no `metadata.component` | no |
| Syft 1.57.0, on an image | between packages; the image is in `metadata.component`, but nothing links it to them | no |
| Syft 1.33.0, SPDX, on an image or a lock file | between packages; the image or directory only contains them | no |
| Trivy 0.76.2, SPDX, on a lock file | through the lock file's entry, which has no package URL | no |
| GitHub dependency graph export (SPDX), `Cargo.lock` | the repository depends on every crate, none on another | no |

Whether your generator links the project to its dependencies shows in its output: the entry of
`dependencies` whose `ref` is the `bom-ref` of `metadata.component` in CycloneDX, the
`DEPENDS_ON` relationships of the described package in SPDX.

A path says how a package gets installed, not that its vulnerable code is called: that is still
what triage decides ([Triage findings](../how-to/triage.md)). The graph is the one the generator
resolved, with the same options: development dependencies left out of the SBOM are left out of
the paths.
