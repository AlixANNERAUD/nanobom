# The upload API

```text
PUT /api/organizations/{organization}/projects/{project}/sbom
Authorization: Bearer nanobom_…
```

The body is the CycloneDX JSON document, as is; the `Content-Type` header is not checked. One
request replaces the project's components with those of the document and records the upload in
the project's history. The project is created if it does not exist and the token allows it.

Organization and project slugs are case-insensitive (`Web` and `web` are the same project). A new
project's slug must be 1 to 64 characters among lower-case letters, digits, `.`, `_` and `-`,
starting with a letter or a digit.

## Tokens

Upload tokens are random 256-bit values prefixed with `nanobom_`, so a leaked token is easy to
spot and search for. nanobom stores only their SHA-256 digest: a token is shown once, at
creation, and cannot be recovered, only revoked and replaced.

| Kind | Created with | May |
| --- | --- | --- |
| **Organization token** | scope **Whole organization** in the settings, or `nanobom token create` without `--project` | upload to any project of its organization, and create projects by uploading to a new slug |
| **Project token** | a project chosen as scope, or `--project web` | upload to that project only |

Prefer project tokens when a repository builds one project: a leaked token then reaches one
project, and a typo in the URL fails instead of creating a new project. A project token can only
be created once the project exists, so the first upload of a project needs an organization
token (or create it with an organization token, then switch).

Tokens are managed by the organization's admins (see [roles](../access/roles.md)) in
**Settings → Upload tokens**, which shows each token's scope and when it was last used, or from
the command line, with direct access to the database:

```sh
nanobom token create --organization acme --name "web CI" --project web
nanobom token list --organization acme
# 7	nanobom_3f9a1c	web CI	web	2026-11-08T03:12:44+00:00	active
nanobom token revoke --id 7
```

`token list` prints one tab-separated line per token, revoked ones included: identifier, first
characters, name, project (or `(organization)`), last use, state. `token create` prints the token
alone on standard output, so a script can capture it:
`TOKEN=$(nanobom token create --organization acme --name CI)`.

## Query parameters

| Parameter | Value | Effect |
| --- | --- | --- |
| `source_commit` | text, up to 300 characters | The commit the SBOM was built from, shown in the upload history |
| `image_tag` | text, up to 300 characters | The container image tag the SBOM describes, shown in the upload history |
| `wait` | `true` or `false` | Wait for the project's evaluation and return it |
| `fail_on` | `critical`, `high`, `medium`, `low` or `exploited` | Fail the upload when open findings reach this threshold; implies `wait` |

All are optional. Empty `source_commit` and `image_tag` count as absent; control characters are
refused. `fail_on` is trimmed and case-insensitive; `wait` accepts exactly `true` or `false`.

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

When exploitation data is on, the run refreshes the KEV and EPSS data of the CVEs it found before
the upload is answered, so `fail_on=exploited` sees a vulnerability first reported by this very
run. That refresh is bounded to 60 seconds.

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
        "url": "https://nanobom.example.org/findings/17"
      }
    ]
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
| `skipped` | The first 100 of them, with the reason |
| `evaluation` | Only with `wait` or `fail_on`, see below |
| `error` | Only when the upload fails, as `{"error": "…"}` alone or next to the fields above |

### The `evaluation` object

| Field | |
| --- | --- |
| `status` | `succeeded`; `failed` when the run could not complete (OSV unreachable, for example); `timed_out` when it did not finish within `NANOBOM_UPLOAD_WAIT_SECONDS` |
| `run_id` | The run's identifier, `null` when timed out |
| `open` | The project's **open** findings by severity; ignored findings are not counted |
| `known_exploited` | How many open findings are known exploited |
| `findings` | The open findings, known exploited first, then by severity and EPSS score; at most 100 |

`open` and `findings` describe the project's findings as they are when the response is written.
After a `failed` or `timed_out` evaluation, they are the findings of the previous successful run,
not of this SBOM.

## Status codes

| Status | When | What to do |
| --- | --- | --- |
| `200` | The SBOM replaced the project's components | |
| `201` | The SBOM created the project | |
| `401` | No `Authorization: Bearer` header, or a token that is unknown or revoked | Check the secret in CI; the response has a `WWW-Authenticate: Bearer` header |
| `403` | A project token used for another existing project | Use that project's slug, or an organization token |
| `404` | The organization does not exist or is not the token's; or a project token used for a project that does not exist | Check the organization slug in the URL; create the project first (with an organization token) |
| `409` | With `fail_on`: the evaluation succeeded and open findings reach the threshold | Fix or triage the findings listed in `evaluation.findings` |
| `413` | The body is larger than `NANOBOM_MAXIMUM_SBOM_SIZE` (16 MiB by default) | Raise the limit, or split the SBOM; this error's body is plain text, not JSON |
| `422` | Invalid parameter, invalid project slug, or invalid document (not JSON, not CycloneDX, unsupported version) | Read `error` |
| `500` | A database error | See the server's logs |
| `503` | With `fail_on`: the evaluation failed or timed out, so the findings are not up to date | Retry later; see [Troubleshooting](../troubleshooting.md#upload-answers-503) |

The `409` and `503` responses still stored the SBOM: the inventory is up to date even when the gate
fails. A `422` for a parameter is answered before anything is stored. The errors of `422` you can
meet:

- `wait must be true or false`
- `fail_on must be critical, high, medium, low or exploited`
- `fail_on=exploited needs exploitation data (NANOBOM_EXPLOITATION_DATA)`: exploitation data is
  off on this instance, so no finding could ever be known exploited and the gate would always
  pass
- `the source commit must be at most 300 printable characters` (or `the image tag …`)
- `the project slug must be 1 to 64 characters: letters, digits, '.', '_' or '-', starting with a letter or a digit`
- `the SBOM is not valid JSON: …`
- `the SBOM must be a CycloneDX JSON document (bomFormat "CycloneDX")`
- `unsupported CycloneDX version "1.2"; supported versions are …`
- `invalid CycloneDX document: …`

API messages are always in English, whatever the instance's users read: they end up in CI logs.
