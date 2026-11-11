# Vulnerability report

The vulnerability report describes one version of a project for readers who do not use nanobom:
customers, auditors, regulators. It is a page of the interface, made to be printed or saved as
PDF, and the same content as an HTML document from the API, for archiving. The steps are in
[Share a vulnerability report](../how-to/share-report.md).

## In the interface

The **Report** button of the project page opens
`/organizations/{organization}/projects/{project}/report`, for the version the page shows
(`?version=…`, the latest version without it). Any member of the organization can open it, as
for the project page. The page is in the language of the interface; printing leaves out the
header, the breadcrumb and the printing hint, and always uses light colors.

## Endpoint

```text
GET /api/organizations/{organization}/projects/{project}/report
```

| | |
| --- | --- |
| Authentication | A [token](upload-api.md#tokens) of either scope, in `Authorization: Bearer nanobom_…` or `X-Api-Key`, or the session of a signed-in member, as on the [read API](read-api.md#authentication) |
| `version` | The name of a [project version](../explanation/concepts.md#versions) (`?version=2.4`; an empty `version=` names the unnamed version). Without it, the latest version |
| `Accept-Language` | The language of the report, English or French; English when absent or not offered |

A token reaches its organization's projects, or its own project for a project token.

| Status | When |
| --- | --- |
| `200` | The report, `Content-Type: text/html; charset=utf-8`: a complete HTML document with the interface's stylesheet inlined, so a saved copy shows the same without the server |
| `401` | No token or session, or an invalid token |
| `404` | Unknown organization, project or version, or one the token does not reach |
| `422` | An invalid query string, such as `version` given twice |

Errors are JSON, `{"error": "…"}`, in English. Like every [read API](read-api.md#caching)
response, the report is `Cache-Control: private, no-cache` and varies on `Cookie`,
`Authorization` and `X-Api-Key`. It is not described in the OpenAPI document, which covers the
JSON endpoints.

## Content

The page and the document hold the same sections, in this order. Dates are in UTC.

| Section | Content |
| --- | --- |
| Title | Organization, project and version (or "Unnamed version"), the time of generation, the nanobom version and the host of `NANOBOM_PUBLIC_URL` |
| Warnings | When the project received no SBOM for longer than `NANOBOM_STALE_AFTER_DAYS` (as on the project page), and when the version is inactive, so no longer checked |
| Scope and provenance | The latest upload of the version (time, SBOM format, source commit and image tag when given), the components checked, the components of that SBOM without a package URL (not checked), the end of the last successful run covering the project, and the last reads of the CISA KEV catalog and of FIRST EPSS scores |
| Summary | A sentence on open findings of high or critical severity, the open findings by severity, how many are known exploited, the ignored findings, and the findings fixed in the last 90 days |
| Open vulnerabilities | Each open finding, in the order of the project page (known exploited first, then by severity and EPSS): identifier and aliases, component and version, severity and CVSS score, known exploited, EPSS percentile, direct or transitive dependency (and through which direct dependencies), fixed versions per the OSV record, first seen |
| Assessed as not affecting the product | Each ignored finding with its justification ("None (accepted risk)" without one), its reason, when it was ignored and by which member or upload token, and its expiry. The address of the [VEX export](vex-api.md) of the same version follows, for machine-readable use |
| Licenses | With a [license policy](license-policy.md), the components it forbids or warns about; without one, the components by license expression, the 10 most common, then the others together and those without a license |
| Method | What nanobom checks and what it does not, and that the report reflects the time of generation |

Lists are bounded so that a large project gives a report of reasonable size: at most 500 open
findings, 500 ignored findings and 200 license violations, each followed by how many more the
project page lists. The counts of the summary always cover every finding.

The report shows nothing a viewer of the project cannot see: who ignored a finding is the
username the finding page shows.
