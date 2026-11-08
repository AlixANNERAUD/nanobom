# Generate an SBOM

nanobom reads CycloneDX JSON (specification versions 1.3 to 1.7) and SPDX JSON (SPDX 2.2 and
2.3), and matches each component by its package URL (`pkg:npm/lodash@4.17.20`). Whatever the
generator, make sure it writes one of these formats in JSON and gives components a package URL
with a version. How nanobom reads the document is described in the
[upload API reference](../reference/upload-api.md#the-document).

Prefer CycloneDX when the generator offers both: its dependency graph names the project's direct
dependencies more reliably, so findings show what to upgrade more often (see
[SPDX documents](../explanation/spdx.md)).

## Choose a generator

Prefer the generator of your ecosystem when you build from source: it reads the lock file or the
resolved dependency tree, so versions are exact and development dependencies can be left out.
Use [Syft](https://github.com/anchore/syft) for container images, binaries, and anything else.

| Ecosystem | Command | Notes |
| --- | --- | --- |
| Rust | `cargo cyclonedx --format json --override-filename sbom` | [cargo-cyclonedx](https://github.com/CycloneDX/cyclonedx-rust-cargo); one file per crate of a workspace (see below) |
| npm | `npx @cyclonedx/cyclonedx-npm --omit dev --output-file sbom.json` | [cyclonedx-npm](https://github.com/CycloneDX/cyclonedx-node-npm); run after `npm ci` |
| Yarn (berry) | `yarn cyclonedx --output-file sbom.json` | [yarn-plugin-cyclonedx](https://github.com/CycloneDX/cyclonedx-node-yarn) |
| Python | `cyclonedx-py environment --output-file sbom.json` | [cyclonedx-py](https://github.com/CycloneDX/cyclonedx-python); run inside the project's virtual environment |
| Maven | `mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom` | writes `target/bom.json` |
| Gradle | the `org.cyclonedx.bom` plugin, task `cyclonedxBom` | writes to `build/reports/` |
| Go | `cyclonedx-gomod app -json -output sbom.json` | [cyclonedx-gomod](https://github.com/CycloneDX/cyclonedx-gomod) |
| Container images, binaries, anything | `syft <image or directory> -o cyclonedx-json=sbom.json` | [Syft](https://github.com/anchore/syft) |

## Generate SPDX

When a tool or policy requires SPDX, ask for SPDX **JSON**, version 2.2 or 2.3. Tag-value
(`.spdx`), RDF and SPDX 3.0 are refused.

| Generator | Command | Notes |
| --- | --- | --- |
| Syft | `syft <image or directory> -o spdx-json=sbom.spdx.json` | SPDX 2.3; `-o spdx-json@2.2=…` for 2.2. Not `-o spdx`, which is tag-value |
| Trivy | `trivy image --format spdx-json --output sbom.spdx.json <image>`, or `trivy fs` on a directory | Not `--format spdx`, which is tag-value |
| GitHub dependency graph | **Insights → Dependency graph → Export SBOM**, or `gh api repos/OWNER/REPO/dependency-graph/sbom --jq .sbom > sbom.spdx.json` | SPDX 2.3, from the manifests and lock files GitHub reads (see below) |

GitHub's export describes the default branch as GitHub last analyzed it, not your build. For a
package no lock file pins, it gives the manifest's version requirement (`^6.1.2`, `2.*.*`)
instead of a version: nanobom skips such packages and reports them in `skipped`, since a
requirement cannot be matched. Commit lock files to get versions. The `--jq .sbom` unwraps the
document from the API's response.

## Rust

`cargo cyclonedx` writes an SBOM next to each `Cargo.toml` of a workspace. For a binary, upload
the SBOM of the binary's crate: it includes its dependencies, workspace crates among them. With
`--override-filename sbom` each file is named `sbom.json` in its crate's directory.

Feature flags change the dependency tree; `--all-features` covers everything that might be built,
at the cost of possibly listing crates your build does not use. Syft scanning the
`Cargo.lock` (`syft dir:. -o cyclonedx-json=sbom.json`) gives one SBOM for the whole workspace,
including development dependencies.

## npm and pnpm

`cyclonedx-npm` reads the installed tree (`node_modules`), so install first with `npm ci`.
`--omit dev` leaves development dependencies out, which is usually what you ship. For pnpm, Syft
on the checkout reads `pnpm-lock.yaml`.

## Python

`cyclonedx-py environment` lists what is installed in the current environment: run it in the
project's virtual environment after installing the project, not in a shared one, or it will list
unrelated packages (including itself). Other sources:

- `cyclonedx-py requirements requirements.txt`: only pinned requirements (`==`) have a version;
  unpinned ones cannot be matched;
- `cyclonedx-py poetry` and `cyclonedx-py pipenv` read the lock files.

## Container images

Syft lists the operating system packages (`pkg:deb/…`, `pkg:apk/…`, `pkg:rpm/…`) and the
language packages it finds in the image:

```sh
syft ghcr.io/acme/web:1.4.0 -o cyclonedx-json=sbom.json
```

Scan the image you push, not the build context: base image packages are part of what you ship.
Pass the tag with `image_tag` at upload so the history says which image each SBOM describes.
Distribution packages are matched when OSV covers the distribution.

## Check an SBOM before uploading

For CycloneDX:

```sh
jq '{format: .bomFormat, version: .specVersion,
     components: (.components | length),
     without_purl: ([.components[] | select(.purl == null)] | length)}' sbom.json
```

`format` must be `CycloneDX` and `version` between `1.3` and `1.7`. Most generators can emit an
older or newer specification with an option (Syft: `-o cyclonedx-json@1.6=sbom.json`).
`without_purl` counts the components nanobom will not be able to check.

For SPDX:

```sh
jq '{version: .spdxVersion,
     packages: (.packages | length),
     without_purl: ([.packages[] | select(all(.externalRefs[]?; .referenceType != "purl"))]
                    | length)}' sbom.spdx.json
```

`version` must be `SPDX-2.2` or `SPDX-2.3`. `without_purl` includes the package the document
describes (the scanned directory or image), which is the project and not a component.
