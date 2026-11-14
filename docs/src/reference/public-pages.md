# Public pages

A project's public page shows the findings of one of its versions and how they were triaged, to
anyone with its address. It is off by default; admins, owners and instance administrators turn
it on, give it a new address and turn it off from the project page
([Publish a public page of a project](../how-to/public-page.md),
[permissions](accounts.md#organization-roles)).

## Endpoints

| Path | Returns |
| --- | --- |
| `GET /public/{key}` | The page, as a complete HTML document |
| `GET /public/{key}/vex.json` | The findings of the same version as a CycloneDX 1.6 VEX document |

`{key}` is 32 lowercase hexadecimal digits (128 random bits), drawn when the page is turned on
and again for each new address. It is the page's own: a [badge](badges.md) has a different key,
and turning one on, giving it a new address or turning it off leaves the other alone. The key
is the only authorization: no session or token is needed, and none is read, so a signed-in
member sees the same page as anyone else. The address names neither the organization nor the
project.

| Parameter | Meaning |
| --- | --- |
| `version` | The name of the [version](versions.md) to show (case-sensitive). Without it, the latest version. Empty (`version=`) names the unnamed version |
| `Accept-Language` (header, page only) | The language of the page, English or French; English when absent or not offered |

`HEAD` is answered like `GET`, without a body.

## Responses

| Status | When |
| --- | --- |
| `200` | The page or the document |
| `404` | The key is unknown, was replaced by a new address, or the page is off; the version is unknown; the query string is malformed (such as `version` given twice). The body is empty and does not say which, and the response is `Cache-Control: no-store` |

Headers of a `200`:

| Header | Value |
| --- | --- |
| `Content-Type` | `text/html; charset=utf-8` for the page, `application/vnd.cyclonedx+json` for the VEX document |
| `Cache-Control` | `public, max-age=300`: browsers and proxies may show a page up to five minutes old, including after it is turned off |
| `Vary` | Page only: `Accept-Language` |
| `Referrer-Policy` | `no-referrer`: following a link from the page to an advisory does not send the page's address, and its key, to the advisory's site |
| `X-Robots-Tag` | `noindex`: search engines that find the address do not list it |
| `X-Content-Type-Options` | `nosniff` |
| `Content-Security-Policy` | Page: `default-src 'none'; style-src 'unsafe-inline'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`, so it runs no script and cannot be framed. Document: `default-src 'none'; frame-ancestors 'none'` |

The page works without JavaScript and has none. Its stylesheet is inlined, as in the
[vulnerability report](report.md); it also carries `<meta name="robots" content="noindex">` and
`<meta name="referrer" content="no-referrer">`.

## What the page shows

The page follows the layout of the [vulnerability report](report.md) and shows only:

| Section | Content |
| --- | --- |
| Header | The project's name, the version's name, and the host serving it (not the nanobom release, which would tell anyone whether the instance runs one with a known flaw) |
| Warnings | Whether the project received no SBOM for longer than `NANOBOM_STALE_AFTER_DAYS` ([Configuration](configuration.md)), and whether the version is inactive |
| Scope and provenance | When the version's SBOM was uploaded, the number of components checked and of components without a package URL, the last check against OSV, and when the CISA KEV catalog and FIRST EPSS scores were last read |
| Summary | Open findings by severity, how many are known exploited, how many are ignored, how many were fixed in the last 90 days |
| Open vulnerabilities | For each: the identifier (linked to osv.dev), its aliases and summary, the component's name, version and package URL, the severity and CVSS score, whether it is known exploited, the EPSS percentile, the versions that fix it and the day it was first seen |
| Assessed by the maintainers | For each ignored finding: the identifier and aliases, the component, the severity, the VEX justification (or **None (accepted risk)**) and the day it was ignored |

Both lists show at most 500 findings, known exploited first, then by severity and EPSS; the page
says how many more there are.

The page never shows:

- the organization, its name or its slug, or the project's slug;
- who ignored a finding, a member's username or the name of the upload token that imported a
  VEX statement;
- the reason typed when ignoring a finding, nor when an ignore expires;
- the source commit or image tag of an upload, or the format of the SBOM;
- licenses and the license policy;
- dependency paths (which direct dependency pulls in a component);
- other versions, other projects, finding identifiers, or any link into the interface.

Package URLs are shown as the SBOM gives them, qualifiers included: a qualifier such as
`repository_url` that names a private registry appears on the page and in the VEX document.
Check the SBOM before turning the page on if its package URLs carry such qualifiers.

## The VEX document

`/public/{key}/vex.json` is the [VEX export](vex-api.md#export) of the same version, open, ignored
and fixed findings included, with two differences:

- no vulnerability has an `analysis.detail`, which carries the reason of an ignore in the
  members' export: `analysis.state` and `analysis.justification` remain;
- `metadata.component` has no `bom-ref`, which names the organization in the members' export;
  its `name` is the project's name and its `version` the version's name;
- the nanobom entry of `metadata.tools` has no `version`.

## Load

A page costs what the report costs: every finding of the version, and the OSV records of the
open ones. At most two pages or VEX documents are built at once across the instance; further
requests wait their turn, so a crawler or a script in a loop cannot keep more of the database
busy, away from uploads and checks. A cache in front of nanobom can serve repeated requests for
the five minutes of `Cache-Control`.

## Storage and logs

The key is stored in clear in the database, as a badge's is, so the project page can show the
address again. Request logs write public page paths as `/public/…`, without the key, at debug
level ([Metrics, health and logs](metrics.md#logs)). Deleting the project deletes its page.
