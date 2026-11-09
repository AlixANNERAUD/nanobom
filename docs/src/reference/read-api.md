# Read API

The read API returns what nanobom knows as JSON: organizations, projects, findings, components,
runs and license policies. It changes nothing. Scripts, dashboards and other tools use it instead of the
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
| `/api/organizations/{organization}/projects/{project}/versions` | The project's [versions](#versions), newest first | |
| `/api/organizations/{organization}/projects/{project}/findings` | The findings of a project version, filtered, in the project page's order | ✓ |
| `/api/organizations/{organization}/projects/{project}/components` | The components of a project version from its latest SBOM, by package URL | ✓ |
| `/api/organizations/{organization}/runs` | The latest runs that covered the organization, newest first | |
| `/api/findings/{finding}` | One finding with its vulnerability, history and dependency paths | |
| `/api/components?q={name}&license={license}` | Components by name, license or both across the active versions of the projects the caller sees | |
| `/api/organizations/{organization}/license-policy` | The organization's [license policy](license-policy.md) | |
| `/api/organizations/{organization}/projects/{project}/license-violations` | The components of a project version whose license the policy forbids or warns about, forbidden first | ✓ |
| `/api/openapi.json` | The OpenAPI description | |

Slugs are case-insensitive. A project's findings as a CycloneDX VEX document come from the
[VEX API](vex-api.md), with the same authentication.

## Versions

Findings, components and license violations belong to one [version](../explanation/concepts.md#versions)
of a project. Their endpoints take `version`, the version's name (case-sensitive); without it,
they return the **latest** version. An empty `version=` names the unnamed version, the one
uploads without a version go to. An unknown version is `404`, like an unknown project.

```text
GET /api/organizations/{organization}/projects/{project}/findings?version=2.4
```

`/versions` lists them, newest first, [inactive](versions.md#states) ones included:

```json
{
  "items": [
    {
      "name": "2.4",
      "latest": true,
      "active": true,
      "created_at": "2026-11-09T08:12:40Z",
      "last_upload_at": "2026-11-09T08:12:40Z",
      "open": {"critical": 0, "high": 1, "medium": 2, "low": 0, "unknown": 0}
    },
    {
      "name": "",
      "latest": false,
      "active": true,
      "created_at": "2026-10-02T14:03:11Z",
      "last_upload_at": "2026-11-08T03:00:12Z",
      "open": {"critical": 0, "high": 1, "medium": 3, "low": 1, "unknown": 0}
    }
  ]
}
```

| Field | |
| --- | --- |
| `name` | The version name; `""` for the unnamed version |
| `latest` | Whether it is the latest version, the one read when a request names none; exactly one version of a project is |
| `active` | Whether runs evaluate it; an inactive version is not counted, searched or notified, and stays readable ([states](versions.md#states)) |
| `last_upload_at` | The version's latest upload; `null` before the first |
| `open` | The version's open findings by severity |

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

Findings, components and license violations are paginated with `limit` and `offset`:

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
20 by default, and has no `offset`: it is refused with `422` rather than ignored.

`/api/components` returns at most 200 components, by name then version, and adds
`"truncated": true` when more matched: make the search narrower (a longer name, or a version
prefix such as `lodash@4.17`).

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
| `version` | A [version](#versions) name | The latest version |

The order is the project page's: known exploited first, then by severity, EPSS score, CVSS
score, component name and vulnerability ([Prioritization](../explanation/prioritization.md)).

A finding:

```json
{
  "id": 17,
  "project": "web",
  "version": "2.4",
  "vulnerability_id": "GHSA-35jh-r3h4-6jhm",
  "aliases": ["CVE-2021-23337"],
  "summary": "Command Injection in lodash",
  "component": {
    "purl": "pkg:npm/lodash@4.17.20",
    "name": "lodash",
    "version": "4.17.20",
    "ecosystem": "npm",
    "license": "MIT"
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
| `version` | The project version the finding belongs to; `""` for the unnamed version |
| `component.license` | The component's license in the latest SBOM; `null` when it is not in it any more ([components](#projects-components-runs-and-search)) |
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
| `events` | The history, oldest first: `kind` (`opened`, `fixed`, `reopened`, `ignored`, `restored`, `ignore_expired`, `inherited`), `created_at`, `user` or `token`, `reason`, `justification`, `run_id`. An `inherited` event starts the history of a finding copied into a new version: its `reason` is the name of the version it was copied from (`""` for the unnamed version), and `token` the token of the upload that created the version |
| `dependency_paths` | `{"paths": [[…]], "more": 0, "partial": false}`, each path from a direct dependency to the component; `null` when the SBOM does not say which components are direct dependencies |
| `affected_components` | The same vulnerability in the active versions of the projects the caller sees, other findings of the finding's own project included: `finding_id`, `organization`, `project`, `version` (the project version, `""` for the unnamed one), `purl`, `status` |
| `versions` | Every version of the finding's project, newest first, inactive ones included, with where it stands with the vulnerability or any of its aliases: `name`, `latest`, `active`, `current` (the finding's own version), `status` and `finding_id`. `status` is `open` when one of the version's findings for the vulnerability is open, else `ignored` when one is ignored, else `fixed`; `not_affected` when the version never had one, with a `null` `finding_id`. `finding_id` is the finding that decides the status, the one of the same component when there is one |

## Projects, components, runs and search

A project:

| Field | |
| --- | --- |
| `slug`, `name` | |
| `last_upload_at` | The latest upload; `null` before the first |
| `stale` | No SBOM for longer than `NANOBOM_STALE_AFTER_DAYS` |
| `open` | Open issues by severity: `critical`, `high`, `medium`, `low`, `unknown` |
| `ignored` | Ignored issues |
| `known_exploited` | Open issues with a CVE in the CISA KEV catalog |

The counts cover the project's active versions, by **issue**: a vulnerability of a package
counts once, at its highest severity, however many versions (or versions of the package) have
it. An issue is open when it is open in any version, ignored when it is ignored in every version
that has it open or ignored. Each version's own counts are in [`/versions`](#versions).
| `url` | The project's page in the interface |

A component is `purl`, `name`, `version` (of the package), `ecosystem` and `license`. `license` is an SPDX
license expression as the SBOM gave it, possibly with free-text license names (`MIT`,
`Apache-2.0 OR MIT`, `LicenseRef-Acme`); it is `null` when the SBOM gives none, and for
components uploaded before nanobom read licenses until their project's next upload
([how licenses are read](upload-api.md#the-document)). A search result adds `organization`,
`project`, `project_version` (`""` for the unnamed version) and `project_version_active`: a
package in several versions of a project is one result per version.

A search takes `q`, `license` or both, and refuses a request with neither (`422`):

- `q` is a name, matched anywhere in the component's name, optionally followed by a space or
  `@` and a version prefix (`openssl 3.`, `lodash@4.17`), both ignoring case;
- `license` is matched anywhere in the component's license, ignoring case: `GPL` finds
  `GPL-3.0-only` and `MIT OR LGPL-2.1-or-later`. Components without a license never match;
- `inactive=true` also searches [inactive versions](versions.md#states), left out by default
  (`true` or `false`, anything else is `422`).

A run is `id`, `trigger` (`scheduled`, `manual`, `upload`), `scope` (`all`, `organization`,
`project`), `status` (`running`, `succeeded`, `failed`), `started_at`, `finished_at`, `error`,
`new_findings` and `fixed_findings`. A whole-instance run covers every organization, so its
`error` and its counts are shown to instance administrators only: others read
`the run could not complete`, and `null` counts.

An organization is `slug`, `name` and `role`: the caller's role, `viewer` for tokens.

## License policy and violations

The policy is changed in the interface only ([Enforce a license policy](../how-to/license-policy.md));
the API reads it:

```json
{
  "active": true,
  "unlisted": "forbid",
  "unknown": "warn",
  "rules": [
    {"license": "Apache-2.0", "action": "allow"},
    {"license": "MIT", "action": "allow"}
  ]
}
```

| Field | |
| --- | --- |
| `active` | Whether the policy can report anything: a rule or a default other than `allow`. An organization that never set a policy is `false`, with `allow` everywhere |
| `unlisted` | The action (`allow`, `warn`, `forbid`) for licenses no rule lists |
| `unknown` | The action for components whose license is missing or is not a valid SPDX expression |
| `rules` | `license` (canonical SPDX identifier or `LicenseRef-…`) and `action`, by identifier |

A page of violations adds `active`, `forbidden` and `warned` (the number of components with
each verdict across the project version; `total` is their sum) to the usual page fields. Each item is
`component` (as above), `verdict` (`forbid` or `warn`) and `licenses`, the identifiers that
lead to the verdict, empty when the action for unknown licenses alone gives it. Items are forbidden components first,
then warned ones, each by name then package URL. Violations are computed at each request from
the current policy and the version's latest SBOM ([how](license-policy.md#evaluation)); without an active
policy the list is empty and `active` is `false`.

## Caching

Every `200` carries a weak `ETag`. Send it back in `If-None-Match` and the answer is
`304 Not Modified`, without a body, while the data is unchanged. The comparison is the weak one
of [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110#section-13.1.2): the `W/` prefix is
ignored on either side, and a list of tags matches when one of them does. The response is still
computed: this saves bandwidth, not server work.

The same URL answers differently for each caller, so every response of the read API (errors and
`304` included, and the [VEX export](vex-api.md)) carries `Cache-Control: private, no-cache`
and `Vary: Cookie, Authorization, X-Api-Key`. Shared caches and proxies must not store it;
the caller's own cache may, after revalidating.

## Status codes and errors

Errors are English JSON, `{"error": "…"}`, as on the upload API.

| Status | When | `error` |
| --- | --- | --- |
| `304` | `If-None-Match` matches | |
| `401` | No token and no session, or a token that is unknown or revoked. The response has a `WWW-Authenticate: Bearer` header | `sign in, or send a token in the Authorization header (Bearer) or in X-Api-Key` |
| `400` | A path segment that is not valid percent-encoded UTF-8 | A description of the problem |
| `404` | Missing (a project version included), or out of the caller's reach | `not found` |
| `422` | An invalid query parameter | For example `limit must be a number from 1 to 500`, `severity must be a comma-separated list of critical, high, medium, low and unknown`, `q, the name to search for, is required`, `offset is not supported on runs: use limit, up to 100` |
| `500` | A database error | `internal error` |

## Stability

The paths have no version number, like those of the upload API; `/api/v1/…` belongs to the
[Dependency-Track API](upload-api.md#dependency-track-api). Changes to the read API are
additive: new endpoints, new query parameters, new fields in responses, new values in
documented enumerations only when the release notes say so. Clients must ignore fields they do
not know. Removing or renaming a field or an endpoint, or changing its meaning, is a breaking
change: it is marked as such in the [release notes](https://github.com/AlixANNERAUD/nanobom/releases),
and from version 1.0 on happens only in a major release.
