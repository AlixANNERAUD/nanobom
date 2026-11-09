# Upload API

## Request

```text
PUT /api/organizations/{organization}/projects/{project}/sbom
Authorization: Bearer nanobom_…
```

The body is the CycloneDX or SPDX JSON document, as is; the `Content-Type` header is not
checked, and a multipart form is not read. One request replaces the project's components with
those of the document and records the upload in the project's history. The project is created
if it does not exist and the token allows it.

Organization and project slugs are case-insensitive (`Web` and `web` are the same project). A new
project's slug must be 1 to 64 characters among lower-case letters, digits, `.`, `_` and `-`,
starting with a letter or a digit.

The body may be at most `NANOBOM_MAXIMUM_SBOM_SIZE` MiB (16 by default).

## Tokens

Tokens are random 256-bit values prefixed with `nanobom_`. nanobom stores only their SHA-256
digest: a token is shown once, at creation, and cannot be recovered, only revoked and replaced.
Tokens authenticate on the upload API, the [VEX API](vex-api.md) and the
[read API](read-api.md), never on the interface.

A token has a reach, its organization or one project, and a scope:

| Reach | Created with | May |
| --- | --- | --- |
| **Organization token** | project **Whole organization** in **Settings → API tokens**, or `nanobom token create` without `--project` | reach any project of its organization; with the upload scope, create projects by uploading to a new slug |
| **Project token** | a project chosen, or `--project web` | reach that project only; it never creates one, so it can only be created once the project exists |

| Scope | Created with | May |
| --- | --- | --- |
| **`upload`** (default) | scope **Upload and read**, or `--scope upload` | upload SBOMs, import VEX documents, and read |
| **`read`** | scope **Read only**, or `--scope read` | read only, through the [read API](read-api.md) and the VEX export; uploads and VEX imports answer `403` |

Tokens are created and revoked by the organization's admins
([roles](accounts.md#organization-roles)) in **Settings → API tokens**, which shows each
token's project, scope and last use, or with [`nanobom token`](command-line.md#nanobom-token).
Which token to give to what is discussed in [Tokens and scopes](../explanation/tokens.md).

## The document

nanobom reads two formats, told apart by the document's content, never by a header:

| Format | Recognized by | Versions | Recorded as |
| --- | --- | --- | --- |
| **CycloneDX JSON** | `"bomFormat": "CycloneDX"` | `specVersion` 1.3 to 1.7 | `1.6` |
| **SPDX JSON** | `spdxVersion` | `SPDX-2.2` and `SPDX-2.3` | `SPDX-2.3` |

A document with both `"bomFormat": "CycloneDX"` and an `spdxVersion` is read as CycloneDX.
Anything else is refused with a `422` and a message naming what was sent: XML (CycloneDX XML),
SPDX tag-value, SPDX RDF (RDF/XML, Turtle, or JSON-LD with the SPDX 2 vocabulary), SPDX 3.0
JSON-LD (recognized by its `@context`), older or newer versions of either format
([error messages](#error-messages)). The recorded version is shown in the project's upload
history.

In both formats:

- Components are identified by their package URL (purl), such as `pkg:npm/lodash@4.17.20`.
  Components with the same package URL are merged.
- A component without a package URL, or with an invalid one, is skipped: it is reported in the
  response (`components_without_purl`, `skipped`) and flagged on the project page, but cannot be
  checked. So is a component whose package URL gives a version requirement rather than a
  version (`pkg:npm/ava@%5E6.1.2`, that is `^6.1.2`; `2.*.*`): its `reason` is
  `version requirement "^6.1.2" instead of a resolved version`.
- A component whose package URL has no version is kept in the inventory and in search results,
  but cannot be matched.
- Qualifiers and subpath of the package URL (`?arch=amd64&distro=debian-12`) are kept for display
  and dropped when querying OSV.
- The dependency graph is kept between the components stored. It is optional: without it, or
  without the project's own dependencies in it, findings show no path
  ([Dependency paths](../explanation/dependency-paths.md)).
- Each component's license is kept as one SPDX license expression (`MIT`,
  `Apache-2.0 OR MIT`), read as described below for each format. It is trimmed but neither
  parsed nor validated, so it may hold free-text license names. A license longer than 1000
  characters is dropped, and the component has no license, rather than cut into an expression
  that names other licenses. When several components share a package URL, the first one's
  license is kept. Licenses are replaced with the components at each upload; components
  uploaded before nanobom read licenses have none until their project's next upload.

### CycloneDX

- Only `components` count (nested components included). The `metadata.component`, which
  describes the project itself, is not a component.
- Components of type `file` and `operating-system` are skipped silently: they describe what was
  scanned, not packages.
- The graph comes from `dependencies`; the entry of `metadata.component` gives the project's
  direct dependencies.
- The serial number (`serialNumber`) is recorded with the upload.
- The license comes from the component's `licenses`. Each entry gives an `expression`, an SPDX
  license identifier (`license.id`) or a free-text name (`license.name`, kept as written). One
  entry gives the license. Several are joined with `AND`, sorted and without duplicates, with
  compound expressions in parentheses: an `MIT` identifier and a `GPL-2.0-only OR BSD-3-Clause`
  expression give `(GPL-2.0-only OR BSD-3-Clause) AND MIT`. CycloneDX does not say
  whether several entries are alternatives or all apply; `AND` is the conservative reading,
  since a component is then only as permissive as its most restrictive license. License
  `text`, `url` and `evidence.licenses` are not read.
- Entries of `vulnerabilities` with an `analysis.state` are VEX statements: they are imported
  into the project ([statements inside an SBOM](vex-api.md#statements-inside-an-sbom)). Entries
  without one, such as a scanner's results, are not read.

### SPDX

- Only `packages` count; `files` and `snippets` are ignored. A package's package URL is its
  first `externalRefs` entry of type `purl` in the `PACKAGE-MANAGER` category
  (`PACKAGE_MANAGER` in SPDX 2.2, or no category).
- A `null` or missing field counts as absent, even one SPDX requires: a package without a
  `name` is kept, a relationship missing one of its ends is ignored.
- The package the document describes (a `DESCRIBES` relationship from the document, or
  `documentDescribes`) is the project, not a component.
- Packages whose `primaryPackagePurpose` is `FILE` or `OPERATING-SYSTEM` are skipped silently.
- The graph comes from `relationships`:

  | Relationship | Edge |
  | --- | --- |
  | `A DEPENDS_ON B` | A depends on B |
  | `B DEPENDENCY_OF A`, and `BUILD_`, `DEV_`, `OPTIONAL_`, `PROVIDED_`, `RUNTIME_`, `TEST_DEPENDENCY_OF` | A depends on B |
  | `A CONTAINS B`, `B CONTAINED_BY A`, between two packages | A depends on B |
  | `CONTAINS` from the project | none: a scanned directory or image contains every package, direct dependency or not |
  | any other | none |

  Edges from the project are its direct dependencies, but only to packages that are also
  linked to another package (as a dependency or a dependent): a document whose project
  depends on every crate of a lock file, with no edge between crates, gives no direct
  dependency, and neither does a direct dependency that depends on nothing and that no other
  package depends on ([why](../explanation/spdx.md#dependency-graph)).
- An `SPDXID` given to several packages with different package URLs (or with and without
  one) is ambiguous: relationships naming it are ignored.
- The license is the package's `licenseConcluded`, or its `licenseDeclared` when
  `licenseConcluded` is missing, `NOASSERTION` or `NONE`. `NOASSERTION` or `NONE` in both means
  no license is known. Expressions are kept as written, `LicenseRef-` identifiers included. A
  license field that is not a string is ignored like a missing one.
- The document namespace (`documentNamespace`) is recorded with the upload as its serial
  number.

## Query parameters

| Parameter | Value | Effect |
| --- | --- | --- |
| `source_commit` | text, up to 300 characters | The commit the SBOM was built from, shown in the upload history |
| `image_tag` | text, up to 300 characters | The container image tag the SBOM describes, shown in the upload history |
| `wait` | `true` or `false` | Wait for the project's evaluation and return it |
| `fail_on` | `critical`, `high`, `medium`, `low`, `exploited` or `license`, or several separated by commas | Fail the upload when one of these thresholds is reached; implies `wait` |

All are optional. Empty `source_commit` and `image_tag` count as absent; control characters are
refused. Each `fail_on` value is trimmed and case-insensitive (`fail_on=high,license`); `wait`
accepts exactly `true` or `false`.

### `fail_on` thresholds

| `fail_on` | Fails (`409`) when an open finding is |
| --- | --- |
| `critical` | critical |
| `high` | high or critical |
| `medium` | medium, high or critical |
| `low` | low, medium, high or critical (anything but unknown) |
| `exploited` | known exploited, whatever its severity |
| `license` | not a finding: a component has a license the organization's [license policy](license-policy.md) forbids |

Ignored findings do not count. Findings of unknown severity (`open.unknown`) never reach a
severity threshold, not even `low`. `exploited` needs exploitation data: with
`NANOBOM_EXPLOITATION_DATA=false` it is refused with a `422`.

With several thresholds, the upload fails when any of them is reached, and `error` names each
one, separated by `; ` (`1 open finding at or above high; 3 components have forbidden
licenses`).

`license` counts only `forbid` verdicts: licenses the policy warns about never fail the upload,
and an organization without a policy always passes. Licenses come from the uploaded SBOM, not
from the run, so a run that fails or times out does not fail `fail_on=license` alone; with a
vulnerability threshold as well, it fails with `503` as before.

## Waiting for the evaluation

Without `wait` or `fail_on`, the request returns as soon as the SBOM is stored, and the project
is checked in the background (unless `NANOBOM_RUN_AFTER_UPLOAD` is `false`, in which case it waits
for the next scheduled run).

With `wait=true` or `fail_on`, the request returns once a run of the project that **started after
the upload** has finished, and the response gets an `evaluation` object. Runs execute one at a
time, so a waiting upload can queue behind a long scheduled run. The wait is bounded by
`NANOBOM_UPLOAD_WAIT_SECONDS` (300 by default); past it, the response says `timed_out` and the run
still completes in the background. Waiting runs the project even when `NANOBOM_RUN_AFTER_UPLOAD`
is `false`.

At most `NANOBOM_MAX_WAITING_UPLOADS` uploads (32 by default) wait at once. Another upload with
`wait` or `fail_on` is refused with a `503` and a `Retry-After` header before its body is parsed,
so nothing is stored and it can be sent again unchanged. The body is still received first, up to
`NANOBOM_MAXIMUM_SBOM_SIZE`. Uploads without `wait` or `fail_on` are
not limited.

The token is checked again when the wait ends. If it was revoked meanwhile, or deleted with its
project or organization, the upload answers `401` with no evaluation, as an invalid token would,
and VEX statements in the SBOM are not imported. The SBOM, accepted while the token was valid,
stays stored.

When exploitation data is on, the run refreshes the KEV and EPSS data of the CVEs it found before
the upload is answered, so `fail_on=exploited` sees a vulnerability first reported by this very
run. That refresh is bounded to 60 seconds. Webhooks are sent after waiting uploads are answered.

## Response

A successful upload returns `201 Created` when it created the project, `200 OK` otherwise:

```json
{
  "organization": "acme",
  "project": "web",
  "project_id": 3,
  "project_created": false,
  "upload_id": 58,
  "component_count": 212,
  "components_without_purl": 2,
  "skipped": [
    { "name": "internal-tool", "version": "1.2.0", "reason": "no package URL" },
    { "name": "vendored-lib", "version": null, "reason": "invalid package URL \"pkg:foo\": …" }
  ],
  "evaluation": {
    "status": "succeeded",
    "run_id": 42,
    "open": { "critical": 0, "high": 2, "medium": 5, "low": 1, "unknown": 0 },
    "known_exploited": 1,
    "findings": [
      {
        "vulnerability": "GHSA-35jh-r3h4-6jhm",
        "component": "pkg:npm/lodash@4.17.20",
        "severity": "high",
        "known_exploited": true,
        "introduced_via": ["web-framework"],
        "url": "https://nanobom.example.org/findings/17"
      }
    ],
    "licenses": {
      "forbidden": 1,
      "warned": 2,
      "violations": [
        {
          "component": "pkg:npm/left-pad@1.3.0",
          "name": "left-pad",
          "version": "1.3.0",
          "license": "MIT AND GPL-3.0-only",
          "verdict": "forbid",
          "licenses": ["GPL-3.0-only"]
        }
      ]
    }
  }
}
```

| Field | |
| --- | --- |
| `organization`, `project` | The slugs, normalized to lower case |
| `project_id`, `upload_id` | Identifiers in nanobom |
| `project_created` | Whether this upload created the project |
| `component_count` | Distinct components stored (by package URL) |
| `components_without_purl` | Components skipped for a missing or invalid package URL |
| `skipped` | The first 100 of them, with `name`, `version` and `reason` |
| `evaluation` | Only with `wait` or `fail_on`, see below |
| `vex` | Only when the SBOM carries VEX statements: what importing them did, as in the [VEX API](vex-api.md#response) |
| `error` | Only when the upload fails, as `{"error": "…"}` alone or next to the fields above |

### The `evaluation` object

| Field | |
| --- | --- |
| `status` | `succeeded`; `failed` when the run could not complete (OSV unreachable, for example); `timed_out` when it did not finish within `NANOBOM_UPLOAD_WAIT_SECONDS` |
| `run_id` | The run's identifier, `null` when timed out |
| `open` | The project's **open** findings by severity (`critical`, `high`, `medium`, `low`, `unknown`); ignored findings are not counted |
| `known_exploited` | How many open findings are known exploited |
| `findings` | The open findings, most severe first, known exploited first within a severity, then by EPSS score; at most 100, so a long list drops the least severe. Each has `vulnerability`, `component` (package URL), `severity`, `known_exploited`, `introduced_via` and `url` (the finding's page) |
| `findings[].introduced_via` | The names of the project's direct dependencies that lead to the component, sorted; the component's own name when it is one; empty when the SBOM's dependency graph does not say ([Dependency paths](../explanation/dependency-paths.md)) |
| `licenses` | Only when the organization has an active [license policy](license-policy.md), whatever `fail_on` says: `forbidden` and `warned`, the number of components with each verdict, and `violations`, the first 20 of them, forbidden first, then by name |
| `licenses.violations[]` | `component` (package URL), `name`, `version`, `license` (as read from the SBOM, `null` when it gave none), `verdict` (`forbid` or `warn`) and `licenses`, the identifiers that lead to the verdict (empty when the license is unknown) |

`open` and `findings` describe the project's findings as they are when the response is written.
After a `failed` or `timed_out` evaluation, they are the findings of the previous successful run,
not of this SBOM.

## Status codes

| Status | When | What to do |
| --- | --- | --- |
| `200` | The SBOM replaced the project's components | |
| `201` | The SBOM created the project | |
| `401` | No `Authorization: Bearer` header, or a token that is unknown or revoked, including one revoked while the upload waited | Check the secret in CI; the response has a `WWW-Authenticate: Bearer` header |
| `403` | A project token used for another existing project, or a read token | Use that project's slug, or an organization token; upload with a token of the upload scope |
| `404` | The organization does not exist or is not the token's; or a project token used for a project that does not exist | Check the organization slug in the URL; create the project first (with an organization token) |
| `409` | With `fail_on`: the evaluation succeeded and open findings reach a threshold, or, with `license`, a component has a forbidden license | Fix or triage the findings listed in `evaluation.findings`; replace the components listed in `evaluation.licenses.violations`, or change the policy |
| `413` | The body is larger than `NANOBOM_MAXIMUM_SBOM_SIZE` (16 MiB by default) | Raise the limit, or split the SBOM; this error's body is plain text, not JSON |
| `422` | Invalid parameter, invalid project slug, or invalid document (not JSON, neither CycloneDX nor SPDX, unsupported version) | Read `error` |
| `500` | A database error | See the server's logs |
| `503` | With a `fail_on` threshold other than `license`: the evaluation failed or timed out, so the findings are not up to date | Retry later; see [Troubleshoot](../how-to/troubleshoot.md#upload-answers-503) |
| `503` | With `wait` or `fail_on`: `NANOBOM_MAX_WAITING_UPLOADS` uploads are already waiting; the response has a `Retry-After` header (in seconds) | Send the upload again after `Retry-After`; nothing was stored |

The `409` and `503` responses still stored the SBOM, except a `503` for too many waiting uploads:
the inventory is up to date even when the gate fails. So did a `401` for a token revoked while
the upload waited. A `422` for a parameter is answered before anything is stored.

## Error messages

API messages are always in English, whatever the instance's users read: they end up in CI logs.
Values of the document they quote (a version, the part of the document a parse error names) are
cut to 200 characters, followed by `…`.

| Status | `error` |
| --- | --- |
| `401` | `a valid upload token is required in the Authorization header (Bearer)` |
| `403` | `this token does not allow uploads to this project` |
| `403` | `this token is read-only: uploads need a token with the upload scope` |
| `404` | `not found` |
| `422` | `wait must be true or false` |
| `422` | `fail_on must be critical, high, medium, low, exploited or license, or several of them separated by commas` |
| `422` | `fail_on=exploited needs exploitation data (NANOBOM_EXPLOITATION_DATA)`: exploitation data is off on this instance, so no finding could ever be known exploited and the gate would always pass |
| `422` | `the source commit must be at most 300 printable characters` (or `the image tag …`) |
| `422` | `the project slug must be 1 to 64 characters: letters, digits, '.', '_' or '-', starting with a letter or a digit` |
| `422` | `the SBOM is not valid JSON: …` |
| `422` | `XML SBOMs are not supported: generate the SBOM as CycloneDX JSON or SPDX JSON` |
| `422` | `SPDX tag-value documents are not supported: generate the SBOM as SPDX JSON (SPDX 2.2 or 2.3) or CycloneDX JSON` |
| `422` | `SPDX RDF documents are not supported: generate the SBOM as SPDX JSON (SPDX 2.2 or 2.3) or CycloneDX JSON` |
| `422` | `the SBOM must be a CycloneDX JSON document (bomFormat "CycloneDX") or an SPDX JSON document (spdxVersion "SPDX-2.3")` |
| `422` | `unsupported CycloneDX version "1.2"; supported versions are 1.3, 1.4, 1.5, 1.6, 1.7` |
| `422` | `unsupported SPDX version "SPDX-3.0.1"; supported versions are SPDX-2.2, SPDX-2.3, in JSON` |
| `422` | `invalid CycloneDX document: …` |
| `422` | `invalid SPDX document: …` |
| `503` | `the evaluation did not complete` |
| `503` | `too many uploads are waiting for their evaluation (at most 32, NANOBOM_MAX_WAITING_UPLOADS): nothing was stored, retry later` |

## Dependency-Track API

nanobom also answers the upload requests of Dependency-Track's API, for clients written for it
(see [Upload with Dependency-Track clients](../how-to/dependency-track-clients.md), and
[Dependency-Track compatibility](../explanation/dependency-track.md) for what the mapping
implies). The document, the [tokens](#tokens), the size limit and the run after the upload are
the same as above.

### Requests

```text
PUT  /api/v1/bom                 JSON body, the SBOM base64-encoded in "bom"
POST /api/v1/bom                 multipart/form-data, the SBOM in the "bom" part
GET  /api/v1/bom/token/{token}   processing status of an upload
GET  /api/v1/event/token/{token} same as above
X-Api-Key: nanobom_…
```

The upload token goes in `X-Api-Key`; `Authorization: Bearer nanobom_…` is accepted too. The
organization is the token's.

| Field | Value | Effect |
| --- | --- | --- |
| `projectName` | text | The project slug: trimmed and folded to lower case, then 1 to 64 characters among letters, digits, `.`, `_` and `-`, starting with a letter or a digit. Required |
| `projectVersion` | text, up to 300 characters | Recorded as the upload's image tag (`image_tag`) |
| `autoCreate` | `true` or `false` (default) | Create the project if it does not exist (organization tokens only). Without it, a missing project is a `404` |
| `bom` | base64 text (`PUT`), file or text part (`POST`) | The CycloneDX or SPDX JSON [document](#the-document). In `PUT`, line breaks in the base64 text are ignored. A UTF-8 byte order mark is removed. In `POST`, only the first `bom` part is read |
| `project` | UUID | Refused with a `400` when `projectName` is missing; ignored otherwise |
| `projectTags`, `parentUUID`, `parentName`, `parentVersion`, `isLatest`, `isActive` | | Accepted and ignored |

In `PUT`, the body is parsed as JSON whatever its `Content-Type`; `autoCreate` may be a boolean
or the string `"true"`. In `POST`, `autoCreate` is `true` when the field reads `true` in any case.

The decoded SBOM may be at most `NANOBOM_MAXIMUM_SBOM_SIZE` MiB, like a native upload. The `PUT`
body may be larger, for the base64 encoding (a third more) and for the line breaks of wrapped
base64 (about 5% more), plus 64 KiB for the other fields. Like Dependency-Track, nanobom
requires the base64 text to be padded (`=`).

### Response

A stored upload answers `200 OK`, whether or not it created the project:

```json
{ "token": "0b8f3c2e-5d1a-4c47-9e0b-3a6f1d2c4b5e" }
```

The processing status endpoints answer `200 OK` with:

```json
{ "processing": true }
```

`processing` is `true` from the upload until the run of the project it queued has finished,
including the refresh of exploitation data, or until `NANOBOM_UPLOAD_WAIT_SECONDS` have passed.
It is `false` for an unknown token: a finished one, one issued before the server restarted, one
of another organization, and every token when `NANOBOM_RUN_AFTER_UPLOAD` is `false`. Both
endpoints need a valid token in `X-Api-Key`.

### Status codes

Error bodies are plain text, as Dependency-Track's, except invalid documents, which are RFC 9457
problems (`Content-Type: application/problem+json`):

```json
{ "status": 400, "title": "The uploaded BOM is invalid", "detail": "the SBOM is not valid JSON: …" }
```

| Status | When | Body |
| --- | --- | --- |
| `200` | The SBOM replaced the project's components | `{"token": …}` |
| `400` | No `projectName` (`projectName is required`), a project given by UUID only (`nanobom cannot find projects by UUID: send projectName (the nanobom project slug) instead of project`), a `projectName` that cannot be a slug (`projectName "…" cannot be a nanobom project slug: …`), a `projectVersion` too long, a request that is not JSON (`invalid upload request: …`), `bom` not base64 (`The BOM must be Base64 encoded`), no SBOM (`No BOM file provided.`) | Plain text |
| `400` | An invalid document: any [document error](#error-messages) of the native API, XML and SPDX tag-value included | Problem |
| `401` | No `X-Api-Key`, or a token that is unknown or revoked | `a valid nanobom upload token is required in the X-Api-Key header` |
| `403` | A project token used for another existing project | `Access to the specified project is forbidden` |
| `403` | A read token | `This nanobom token is read-only: uploads need a token with the upload scope.` |
| `404` | A missing project without `autoCreate`, or with a project token | `The project could not be found.` |
| `409` | `autoCreate` and another upload created the same project first: send the upload again | `the project "…" already exists` |
| `413` | An SBOM larger than `NANOBOM_MAXIMUM_SBOM_SIZE` | Plain text |
| `500` | A database error | `internal error` |

The status endpoints answer `400` (`the token must be a UUID`) for a token that is not a UUID,
and `401` like uploads.
