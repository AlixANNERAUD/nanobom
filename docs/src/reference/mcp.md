# MCP endpoint

nanobom serves its data as tools for assistants that speak the
[Model Context Protocol](https://modelcontextprotocol.io) (MCP): Claude Code, Claude Desktop,
VS Code, Cursor and other MCP clients. The tools read what the [read API](read-api.md) reads,
with the same tokens; they change nothing. Connecting a client is described in
[Query nanobom from an assistant](../how-to/assistant.md).

## Endpoint

| | |
| --- | --- |
| URL | `/mcp`, under the public URL: `https://nanobom.example.com/mcp` |
| Transport | Streamable HTTP, stateless: every request is a `POST` answered on its own in JSON, with no session (`Mcp-Session-Id`) and no server-to-client stream |
| Protocol versions | `2024-11-05` to `2026-07-28` |
| Server name | `nanobom`, with the instance's version |
| Setting | None: the endpoint is always on (see [Why it is always on](#why-it-is-always-on)) |

Requests send `Content-Type: application/json` and accept both `application/json` and
`text/event-stream`, as the transport requires; MCP clients do so by themselves.

## Authentication

Exactly as on the read API, with a token only:

| Sends | Reads |
| --- | --- |
| `Authorization: Bearer nanobom_…`, or `X-Api-Key: nanobom_…`, a token of either [scope](upload-api.md#tokens) | Its organization, as a viewer; a project token, its project only |

The session cookie of the interface authenticates nothing here: a request without a token is
`401`, whatever cookie it carries. A request with an `Origin` header, which browsers add and MCP
clients do not, is `403`, and no CORS header is sent: a web page cannot drive the endpoint.

Anything out of the token's reach is reported as not found, exactly like something that does not
exist. Projects are named by slug within the token's organization.

## Status codes

The token is checked first: a request without a valid token is `401`, whatever else is wrong
with it.

| Status | When |
| --- | --- |
| `200` | A JSON-RPC answer, including tool errors (see [Errors](#errors)) |
| `202` | A notification (`notifications/initialized`), which has no answer |
| `400` | The body is not a JSON-RPC message, or `MCP-Protocol-Version` names an unknown version |
| `401` | No token, or one that is not valid (revoked or mistyped): `{"error": "…"}` with `WWW-Authenticate: Bearer` |
| `403` | The request has an `Origin` header |
| `405` | Any method but `POST` |
| `406` | `Accept` does not list both `application/json` and `text/event-stream` |
| `413` | The body is larger than 64 KiB |
| `415` | `Content-Type` is not `application/json` |

## Tools

Every tool is read-only (`readOnlyHint`) and describes its inputs in a JSON schema, which
clients read from `tools/list`. Answers are JSON objects, as structured content and as text.

| Tool | Inputs | Answers |
| --- | --- | --- |
| `list_projects` | None | The projects the token reaches, by organization and slug: open issues of their active versions by severity (a vulnerability of a package counted once), `known_exploited`, `ignored`, `last_upload_at`, `stale`, `url` |
| `list_versions` | `project` | The project's [versions](versions.md), newest first: `name` (`""` for the unnamed version), `latest`, `active`, `created_at`, `last_upload_at`, open findings by severity |
| `list_findings` | `project`, `version`, `status`, `minimum_severity`, `known_exploited_only`, `component` | The findings of a version, most urgent first ([prioritization](../explanation/prioritization.md)), with `total`, the number matching the filters |
| `get_finding` | `id` | One finding in full: identifiers and aliases, severity and CVSS vector, exploitation (KEV, EPSS), fixed versions, [dependency paths](../explanation/dependency-paths.md), triage, the status of each version of the project, and the advisory |
| `affected_by` | `vulnerability`, `any_status`, `include_inactive` | The findings of a vulnerability across the projects the token reaches, by project and version |
| `search_components` | `name`, `license`, `include_inactive` | Components by name (and version prefix), license or both, one match per project version, as the [component search](read-api.md) |
| `license_violations` | `project`, `version` | The components of a version that the [license policy](license-policy.md) forbids or warns about, forbidden first, with `policy_active` and the `forbidden` and `warned` counts |

### Inputs

| Input | Tools | Values | Default |
| --- | --- | --- | --- |
| `project` | `list_versions`, `list_findings`, `license_violations` | A project slug, case-insensitive | Required |
| `version` | `list_findings`, `license_violations` | A version name, case-sensitive; `""` for the unnamed version | The latest version |
| `status` | `list_findings` | `open`, `ignored` or `fixed` | `open` |
| `minimum_severity` | `list_findings` | `critical`, `high`, `medium`, `low` or `unknown`: that severity and above (`unknown` is the lowest) | Every severity |
| `known_exploited_only` | `list_findings` | Only vulnerabilities in CISA's KEV catalog | `false` |
| `component` | `list_findings` | Text the component name contains, ignoring case | Every component |
| `id` | `get_finding` | A finding identifier, from `list_findings` or `affected_by` | Required |
| `vulnerability` | `affected_by` | An identifier or alias, ignoring case: `CVE-2021-23337` also finds findings filed under `GHSA-35jh-r3h4-6jhm`, which lists it as an alias | Required |
| `any_status` | `affected_by` | Also ignored and fixed findings | `false`: open ones |
| `include_inactive` | `affected_by`, `search_components` | Also [inactive versions](versions.md#states) | `false` |
| `name` | `search_components` | Text the name contains, optionally followed by a space or `@` and the start of the version: `openssl 3.`, `log4j-core@2.14` | |
| `license` | `search_components` | Text the license contains, ignoring case: `GPL` finds `GPL-3.0-only` and `LGPL-2.1-or-later` | |

`search_components` needs `name`, `license` or both. Unknown inputs are refused, not ignored.

### Example

```json
{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
 "params": {"name": "affected_by", "arguments": {"vulnerability": "CVE-2021-23337"}}}
```

```json
{
  "vulnerability": "CVE-2021-23337",
  "known_as": ["GHSA-35jh-r3h4-6jhm"],
  "items": [
    {
      "finding_id": 412,
      "organization": "acme",
      "project": "web",
      "version": "2.4",
      "version_latest": true,
      "version_active": true,
      "component": "lodash",
      "component_version": "4.17.20",
      "purl": "pkg:npm/lodash@4.17.20",
      "vulnerability_id": "GHSA-35jh-r3h4-6jhm",
      "severity": "high",
      "status": "open",
      "url": "https://nanobom.example.com/findings/412"
    }
  ],
  "truncated": false
}
```

`known_as` lists the identifiers the vulnerability is filed under in nanobom: the one asked for,
or those that list it as an alias, among the findings of the projects the token reaches. It is
empty when none of them has the vulnerability: it never reveals what other organizations have.

## Limits

| Limit | Value |
| --- | --- |
| Items in a list | 100; the answer has `"truncated": true` when there are more. `list_findings` also gives `total` |
| Advisory details | 4000 characters; `details_truncated` says when they were cut |
| Advisory references | 20; `references_truncated` says when there were more |
| Versions of a finding (`get_finding`) | 100; `versions_truncated` says when there were more |
| Request body | 64 KiB |

A truncated list calls for a narrower question: a filter on `list_findings`, a longer name or a
version prefix on `search_components`.

## Errors

A tool that cannot answer returns a result with `isError: true` and a message the assistant can
act on, in English: `not found: …` for a project, version or finding that does not exist or is
out of the token's reach, or what is wrong with the inputs: an unknown or missing field, a value
outside an enumeration (`failed to deserialize parameters: …`), an empty `vulnerability`, a
search with neither `name` nor `license`. A database failure is a JSON-RPC internal error,
without details.

## Untrusted text

Advisory summaries and details come from [OSV](https://osv.dev), written by third parties. An
advisory could hold text meant to steer an assistant ("ignore previous instructions…"), so
nanobom returns it only in delimited fields: `advisory_summary` in `list_findings`, and the
`advisory` object of `get_finding`, which carries a `notice` saying the text is data. The tool
descriptions and the server's instructions say the same. Ignore reasons are written by members
of the organization, or come from imported VEX documents.

The endpoint has no tool that changes anything, so text that steers an assistant can at most
mislead its answer; it cannot triage, upload or delete through nanobom.

## Why it is always on

The endpoint adds no reach to what the read API already gives: the same tokens, the same
domain functions and the same checks, and nothing the session cookie unlocks. Turning it off
would protect no data, so there is no setting. To keep a token from it, do not give that token
to an assistant; revoking the token stops both.
