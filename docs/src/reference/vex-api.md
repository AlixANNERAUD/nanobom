# VEX API

nanobom exports a project's findings as a CycloneDX VEX document and imports VEX statements
into a project. Why and when to use them is explained in [VEX](../explanation/vex.md); the steps
are in [Exchange VEX statements](../how-to/vex.md).

## Endpoints

```text
GET /api/organizations/{organization}/projects/{project}/vex
PUT /api/organizations/{organization}/projects/{project}/vex
```

| Method | Authentication | Does |
| --- | --- | --- |
| `GET` | `Authorization: Bearer nanobom_…` (an [upload token](upload-api.md#tokens)), or the session of a signed-in member (any role) | Returns the project's findings as a CycloneDX 1.6 JSON document |
| `PUT` | `Authorization: Bearer nanobom_…` only | Applies the statements of a CycloneDX VEX document to the project's open findings |

A token reaches the projects it may upload to: an organization token any project of its
organization, a project token its own project. Any other project, like a missing one, is a `404`:
unlike uploads, these endpoints never create a project.

Slugs are case-insensitive. The body of a `PUT` may be at most `NANOBOM_MAXIMUM_SBOM_SIZE` MiB
(16 by default). The **Export VEX** button of the project page links to the `GET` endpoint.

## Export

The response is `200` with `Content-Type: application/vnd.cyclonedx+json` and
`Content-Disposition: attachment; filename="{organization}-{project}.vex.cdx.json"`.

| Part of the document | Content |
| --- | --- |
| `specVersion` | `1.6` |
| `serialNumber` | A new random `urn:uuid:` at each export |
| `metadata.timestamp` | The time of the export, UTC |
| `metadata.tools.components` | nanobom and its version |
| `metadata.component` | The project: its name, `bom-ref` `{organization}/{project}` |
| `components` | Each component that has a finding, with `bom-ref` and `purl` set to its package URL |
| `vulnerabilities` | One entry per finding, open, ignored or fixed, sorted by identifier then package URL |

Each entry of `vulnerabilities`:

| Field | Content |
| --- | --- |
| `id` | The finding's vulnerability identifier (`GHSA-…`, `CVE-…`, `RUSTSEC-…`) |
| `source` | Where the identifier is published: NVD for `CVE-`, GitHub Advisories for `GHSA-`, OSV otherwise, with the URL of the record |
| `references` | The aliases, each with its `source` |
| `ratings` | The severity, with the CVSS score, method (`CVSSv2`, `CVSSv3`, `CVSSv31`, `CVSSv4`) and vector when known |
| `description` | The OSV summary |
| `published`, `updated` | The OSV record's dates |
| `analysis` | See the mapping below; `firstIssued` is when the finding was first seen, `lastUpdated` its latest change |
| `affects` | `[{"ref": "<package URL>"}]`, a `bom-ref` of `components` |

### Mapping of findings

| Finding | `analysis.state` | `analysis.justification` | `analysis.detail` |
| --- | --- | --- | --- |
| Open | `in_triage` | | |
| Ignored with a justification | `not_affected` | The justification | The reason |
| Ignored as **False positive** | `false_positive` | | The reason |
| Ignored without a justification | `in_triage` | | The reason |
| Fixed | `resolved` | | |

The justifications are those of CycloneDX:

| Value | In the interface |
| --- | --- |
| `code_not_present` | Vulnerable code not present |
| `code_not_reachable` | Vulnerable code not reachable |
| `requires_configuration` | Requires a configuration not in use |
| `requires_dependency` | Requires a dependency not present |
| `requires_environment` | Requires an environment not present |
| `protected_by_compiler` | Protected by the compiler |
| `protected_at_runtime` | Protected at runtime |
| `protected_at_perimeter` | Protected at the perimeter |
| `protected_by_mitigating_control` | Protected by a mitigating control |

**False positive** is offered in the same list. It is not a CycloneDX justification but the
`false_positive` state, which takes none.

## Import

The body is a CycloneDX JSON document, specification **1.4 to 1.7** (earlier versions have no
`vulnerabilities`). Only `vulnerabilities` and the `bom-ref`s of `components` and
`metadata.component` are read; an entry without `analysis.state` is not a statement and is left
out.

### Which findings a statement covers

A statement covers a finding of the project when both hold:

- **Vulnerability**: its `id`, or the `id` of one of its `references`, equals the finding's
  identifier or one of its aliases, ignoring case. A statement about `CVE-2021-23337` covers a
  finding filed as `GHSA-35jh-r3h4-6jhm` with that alias.
- **Component**: one of its `affects[].ref` resolves to the finding's package URL, compared
  without qualifiers and subpath. A reference resolves when it is the `bom-ref` of a component of
  the same document with a `purl`, or is a package URL itself. A BOM-Link
  (`urn:cdx:{serial}/{version}#{ref}`) is read the same way from its fragment, percent-decoded.

A package URL without a version covers nothing: it would cover every version of the package.
`affects[].versions` is not read.

### What it does

| `analysis.state` | Effect on covered findings |
| --- | --- |
| `not_affected` | Open findings are ignored, with `analysis.justification` (if it is one of the values above) |
| `false_positive` | Open findings are ignored, as **False positive** |
| `resolved`, `resolved_with_pedigree`, `exploitable`, `in_triage` | None; reported as `informational` |

An ignore made by an import:

- has `analysis.detail` as its reason, cut to 2,000 characters; without a detail, the reason is
  `VEX statement: not_affected (code_not_reachable)` or `VEX statement: false_positive`;
- has no expiry;
- is recorded in the finding's history as made by the upload token, by name.

Ignored and fixed findings are left as they are, so importing the same document again changes
nothing. The whole import is one transaction.

### Response

`200` with what was done:

```json
{
  "statements": 3,
  "ignored": 1,
  "already_ignored": 1,
  "skipped": 1,
  "results": [
    {
      "vulnerability": "CVE-2021-23337",
      "component": "pkg:npm/lodash@4.17.20",
      "state": "not_affected",
      "result": "ignored",
      "findings": [17]
    }
  ]
}
```

| Field | |
| --- | --- |
| `statements` | Statements read (entries with an `analysis.state`) |
| `ignored` | Findings this import ignored |
| `already_ignored` | Covered findings that were already ignored |
| `skipped` | Statement targets that changed nothing, for any `result` below except `ignored` and `already_ignored` |
| `results` | One entry per target (`affects[].ref`) of each statement, the first 500 |
| `results[].vulnerability` | The statement's `id` (or its first reference's) |
| `results[].component` | The `affects[].ref` as written; `null` when `affects` is empty |
| `results[].findings` | The identifiers of the findings covered |

| `result` | Meaning |
| --- | --- |
| `ignored` | Open findings were ignored |
| `already_ignored` | The covered findings were already ignored |
| `no_matching_finding` | No open or ignored finding of the project is covered |
| `informational` | The state does not ignore findings |
| `unresolved_reference` | The reference is neither a `bom-ref` of the document nor a package URL |
| `no_version` | The package URL has no version |
| `no_target` | `affects` is empty |

## Statements inside an SBOM

An SBOM sent to the [upload API](upload-api.md) may carry statements in its own
`vulnerabilities`, and they are imported like a VEX document, with the upload's token. The
response then has a `vex` object, shaped like the import response above.

- With `wait` or `fail_on`, they are imported **after** the evaluation and **before** the gate:
  they also cover the findings this upload's run opened, and `fail_on` does not count what they
  ignore.
- Without, they are imported at once, so they cover only findings of earlier runs; findings the
  coming run opens are covered by the next upload with the same statements.

The [Dependency-Track API](upload-api.md#dependency-track-api) does not read them.

## Status codes and errors

Errors are English JSON, `{"error": "…"}`.

| Status | When |
| --- | --- |
| `200` | Exported, or imported |
| `401` | `GET`: neither a valid token nor a session; `PUT`: no valid token. The response has a `WWW-Authenticate: Bearer` header |
| `404` | The organization or project does not exist, or the token or member does not reach it |
| `413` | The body is larger than `NANOBOM_MAXIMUM_SBOM_SIZE` |
| `422` | Invalid document |
| `500` | A database error |

| Status | `error` |
| --- | --- |
| `401` | `a valid upload token is required in the Authorization header (Bearer)` |
| `401` | `sign in, or send an upload token in the Authorization header (Bearer)` (`GET` without either) |
| `404` | `not found` |
| `422` | `the VEX document is not valid JSON: …` |
| `422` | `the VEX document must be a CycloneDX JSON document (bomFormat "CycloneDX")` |
| `422` | `unsupported CycloneDX version "1.3" for a VEX document; supported versions are 1.4, 1.5, 1.6, 1.7` |
| `422` | `invalid CycloneDX VEX document: …` |
