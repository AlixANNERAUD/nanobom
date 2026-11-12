# Components of a version

The components page lists what the latest SBOM of a project version holds, vulnerable or not:
to check that an SBOM arrived complete, read a component's license, or confirm that a dependency
is there. The steps are in
[Check what nanobom received](../how-to/generate-sbom.md#check-what-nanobom-received).

## Address

The **Components** tab of the project page opens
`/organizations/{organization}/projects/{project}/components`, for the version the page shows.
Any member of the organization can open it, as for the project page; another organization's
project, or an unknown version, is a 404.

| Query parameter | Meaning | Default |
| --- | --- | --- |
| `version` | The name of a [project version](../explanation/concepts.md#versions); an empty `version=` names the unnamed version | The latest version |
| `name` | Only components whose name contains this text, namespace included, ignoring case (`%` and `_` match themselves) | Every name |
| `show` | `open`: components with at least one open finding (ignored and fixed ones do not count). `unlicensed`: components whose SBOM entry gives no license | Every component |
| `page` | The page, from 1 | 1 |

The filter form and the page links keep the version and the filters; filtering goes back to the
first page.

## What it shows

Above the table: the number of components of the version, the components of its latest upload
that had no package URL (not stored, so not listed, see
[Components without package URL](../how-to/troubleshoot.md#components-without-package-url)), and
how many components match the filters when there are any.

| Column | Content |
| --- | --- |
| Component | The name, with its namespace (`org.apache.logging.log4j/log4j-core`), and the package URL |
| Version | The package URL's version |
| Ecosystem | The package URL type: `npm`, `cargo`, `maven`… |
| License | The license expression of the SBOM, or **None declared** |
| Open findings | The severity of the worst open finding and their number, linking to the finding when there is one, to the version's findings otherwise; **None** without open findings |
| Dependency | **Direct** when the SBOM lists it among the project's own dependencies, **Transitive** otherwise, **Not known** when the SBOM does not say which components the project depends on directly (see [Dependency paths](../explanation/dependency-paths.md)) |

Components with open findings come first, the most severe first, then every component by name
and version. A page holds 100 components; asking for a page past the last shows the last.

When some links of the SBOM's dependency graph could not be followed (components without a
package URL, or a reference shared by several packages), the page says so: a direct dependency
whose link was lost shows as **Transitive**.

The [read API](read-api.md)'s `/components` returns the same components as JSON, by package URL,
without these filters.
