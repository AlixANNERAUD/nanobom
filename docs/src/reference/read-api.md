# Read API

The read API returns what nanobom knows as JSON: organizations, projects, findings, components
and runs. It changes nothing. Scripts, dashboards and other tools use it instead of the
interface. An example is in [Export findings to a spreadsheet](../how-to/export-findings.md);
which token to give a tool is explained in [Tokens and scopes](../explanation/tokens.md).

The API is described in OpenAPI 3.1 at `/api/openapi.json` on every instance, without
authentication. Load it in an OpenAPI viewer or a client generator.

## Endpoints

Every endpoint is a `GET`.

| Path | Returns | Paginated |
| --- | --- | --- |
| `/api/organizations` | The organizations the caller sees, by name | |
| `/api/organizations/{organization}/projects` | The organization's projects, by slug, with their open findings by severity | |
| `/api/organizations/{organization}/projects/{project}/findings` | The project's findings, filtered, in the project page's order | ✓ |
| `/api/organizations/{organization}/projects/{project}/components` | The project's components from its latest SBOM, by package URL | ✓ |
| `/api/organizations/{organization}/runs` | The latest runs that covered the organization, newest first | |
| `/api/findings/{finding}` | One finding with its vulnerability, history and dependency paths | |
| `/api/components?q={name}` | Components by name across the projects the caller sees | |
| `/api/openapi.json` | The OpenAPI description | |

Slugs are case-insensitive. A project's findings as a CycloneDX VEX document come from the
[VEX API](vex-api.md), with the same authentication.

## Authentication

| Caller | Sends | Reads |
| --- | --- | --- |
| A token of either [scope](upload-api.md#tokens), `read` or `upload` | `Authorization: Bearer nanobom_…`, or `X-Api-Key: nanobom_…` as on the [Dependency-Track API](upload-api.md#dependency-track-api) | Its organization, as a viewer; a project token, its project only |
| A signed-in user | The session cookie of the interface | What the interface shows them: every organization they belong to, with their role |

When a request carries `Authorization` or `X-Api-Key`, the token decides, even if it is invalid
and a session cookie comes along: the request is then `401`.

A **project token** sees, of its organization:

- the project in `/projects`, and only that project's findings and components;
- in a finding's `affected_components`, no other project;
- in `/runs`, whole-instance runs and the runs of its project, not the runs of the whole
  organization (their counts cover the other projects).

Anything out of the caller's reach answers `404`, exactly like something that does not exist.

## Pagination

Findings and components are paginated with `limit` and `offset`:

| Parameter | Default | |
| --- | --- | --- |
| `limit` | `100` | Items per page, from 1 to 500 |
| `offset` | `0` | Items to skip |

A page is an object:

```json
{"items": [], "total": 42, "limit": 100, "offset": 0}
```

`total` counts the whole list. Fetch pages until `offset + limit` reaches `total`. The list is
computed at each request: a run between two requests can move findings from one page to the
next.

Lists that are not paginated are `{"items": […]}`. `/runs` takes a `limit` from 1 to 100,
20 by default. `/api/components` returns at most 200 components.

## Findings

```text
GET /api/organizations/{organization}/projects/{project}/findings?status=open&severity=critical,high
```

| Parameter | Values | Default |
| --- | --- | --- |
| `status` | `all`, or a comma-separated list of `open`, `ignored`, `fixed` | `open,ignored`, as on the project page |
| `severity` | A comma-separated list of `critical`, `high`, `medium`, `low`, `unknown` | Any |
| `exploited` | `true`: only findings with a CVE in the CISA KEV catalog | `false` |
| `ecosystem` | The package URL type: `npm`, `cargo`, `pypi`… | Any |

The order is the project page's: known exploited first, then by severity, EPSS score, CVSS
score, component name and vulnerability ([Prioritization](../explanation/prioritization.md)).

A finding:

```json
{
  "id": 17,
  "project": "web",
  "vulnerability_id": "GHSA-35jh-r3h4-6jhm",
  "aliases": ["CVE-2021-23337"],
  "summary": "Command Injection in lodash",
  "component": {
    "purl": "pkg:npm/lodash@4.17.20",
    "name": "lodash",
    "version": "4.17.20",
    "ecosystem": "npm"
  },
  "severity": "high",
  "cvss_score": 7.2,
  "status": "ignored",
  "exploitation": {
    "known_exploited": true,
    "kev_date_added": "2021-11-03",
    "kev_due_date": null,
    "kev_ransomware": false,
    "epss_score": 0.5,
    "epss_percentile": 0.9,
    "epss_date": "2024-01-01"
  },
  "introduced_via": [
    {"purl": "pkg:npm/express@4.17.1", "name": "express", "version": "4.17.1"}
  ],
  "first_seen_at": "2026-11-08T03:00:12Z",
  "last_seen_at": "2026-11-08T03:00:12Z",
  "fixed_at": null,
  "ignore": {
    "reason": "template() is never called",
    "justification": "code_not_reachable",
    "expires_at": null
  },
  "url": "https://nanobom.example.com/findings/17"
}
```

| Field | |
| --- | --- |
| `severity` | The highest among the vulnerability's aliases at the latest run that reported it |
| `exploitation` | Aggregated over the finding's CVEs; empty values when nothing is known, which is not the same as "not exploited" for a finding without a CVE |
| `introduced_via` | The project's direct dependencies that lead to the component; empty when the SBOM's dependency graph does not say ([Dependency paths](../explanation/dependency-paths.md)) |
| `ignore` | Set while the finding is ignored, `null` otherwise. `justification` is one of the [VEX justifications](vex-api.md#mapping-of-findings) or `false_positive` |
| `url` | The finding's page in the interface, built from `NANOBOM_PUBLIC_URL` |

## One finding

`GET /api/findings/{finding}` takes the `id` of a finding. It returns every field of a finding
in a list, plus:

| Field | |
| --- | --- |
| `organization` | The organization's slug |
| `details` | The advisory's description, in Markdown |
| `published`, `modified` | The advisory's dates |
| `cvss_version`, `cvss_vector` | The CVSS vector the score comes from |
| `fixed_versions` | Versions of the package that fix the vulnerability, per the OSV record |
| `references` | The advisory's links: `{"type": "ADVISORY", "url": "…"}` |
| `ignored_by`, `ignored_by_token` | The member, or the token of a VEX import, that ignored the finding, while it is ignored |
| `events` | The history, oldest first: `kind` (`opened`, `fixed`, `reopened`, `ignored`, `restored`, `ignore_expired`), `created_at`, `user` or `token`, `reason`, `justification`, `run_id` |
| `dependency_paths` | `{"paths": [[…]], "more": 0, "partial": false}`, each path from a direct dependency to the component; `null` when the SBOM does not say which components are direct dependencies |
| `affected_components` | The same vulnerability in other projects the caller sees: `finding_id`, `organization`, `project`, `purl`, `status` |

## Projects, components, runs and search

A project:

| Field | |
| --- | --- |
| `slug`, `name` | |
| `last_upload_at` | The latest upload; `null` before the first |
| `stale` | No SBOM for longer than `NANOBOM_STALE_AFTER_DAYS` |
| `open` | Open findings by severity: `critical`, `high`, `medium`, `low`, `unknown` |
| `ignored` | Ignored findings |
| `known_exploited` | Open findings with a CVE in the CISA KEV catalog |
| `url` | The project's page in the interface |

A component is `purl`, `name`, `version` and `ecosystem`. A search result adds `organization`
and `project`. `q` is a name, matched anywhere in the component's name, optionally followed by a
space or `@` and a version prefix (`openssl 3.`, `lodash@4.17`), both ignoring case.

A run is `id`, `trigger` (`scheduled`, `manual`, `upload`), `scope` (`all`, `organization`,
`project`), `status` (`running`, `succeeded`, `failed`), `started_at`, `finished_at`, `error`,
`new_findings` and `fixed_findings`. The error of a whole-instance run is shown to instance
administrators only; others read `the run could not complete`.

An organization is `slug`, `name` and `role`: the caller's role, `viewer` for tokens.

## Caching

Every `200` carries a weak `ETag`. Send it back in `If-None-Match` and the answer is
`304 Not Modified`, without a body, while the data is unchanged. The response is still computed:
this saves bandwidth, not server work.

## Status codes and errors

Errors are English JSON, `{"error": "…"}`, as on the upload API.

| Status | When | `error` |
| --- | --- | --- |
| `304` | `If-None-Match` matches | |
| `401` | No token and no session, or a token that is unknown or revoked. The response has a `WWW-Authenticate: Bearer` header | `sign in, or send a token in the Authorization header (Bearer) or in X-Api-Key` |
| `404` | Missing, or out of the caller's reach | `not found` |
| `422` | An invalid query parameter | For example `limit must be a number from 1 to 500`, `severity must be a comma-separated list of critical, high, medium, low and unknown`, `q, the name to search for, is required` |
| `500` | A database error | `internal error` |

## Stability

The paths have no version number, like those of the upload API; `/api/v1/…` belongs to the
[Dependency-Track API](upload-api.md#dependency-track-api). Changes to the read API are
additive: new endpoints, new query parameters, new fields in responses, new values in
documented enumerations only when the release notes say so. Clients must ignore fields they do
not know. Removing or renaming a field or an endpoint, or changing its meaning, is a breaking
change: it is marked as such in the [release notes](https://github.com/AlixANNERAUD/nanobom/releases),
and from version 1.0 on happens only in a major release.
