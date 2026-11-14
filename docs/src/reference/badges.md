# Badges

A project's badge is a small image of the open findings of one of its versions, for a README.
It is off by default; admins, owners and instance administrators turn it on, give it a new address and turn it off from
the project page ([Show a badge in a README](../how-to/badge.md),
[permissions](accounts.md#organization-roles)).

## Endpoints

| Path | Returns |
| --- | --- |
| `GET /badges/{key}.svg` | The badge as an SVG image |
| `GET /badges/{key}.json` | The badge in the [shields.io endpoint format](https://shields.io/badges/endpoint-badge) |

`{key}` is 32 lowercase hexadecimal digits (128 random bits), drawn when the badge is turned on
and again for each new address. The key is the only authorization: no session or token is
needed, and none is read. The address names neither the organization nor the project.

| Parameter | Meaning |
| --- | --- |
| `version` | The name of the [version](versions.md) to show (case-sensitive). Without it, the latest version. Empty (`version=`) names the unnamed version |

`HEAD` is answered like `GET`, without a body.

## Messages and colours

The label is always `vulnerabilities`, in English whatever the interface language. The message
counts the **open** findings of the version, as the project page's summary does: ignored and
fixed findings do not count. The colour is that of the worst open finding.

| Open findings | Message | Colour |
| --- | --- | --- |
| None | `none` | green `#1f883d` |
| Some known exploited ([CISA KEV](../explanation/prioritization.md)) | `N exploited`, then the counts below | red `#cf222e` |
| Worst is critical | the counts, e.g. `1 critical, 2 high` | red `#cf222e` |
| Worst is high | e.g. `2 high, 3 medium` | orange `#bc4c00` |
| Worst is medium | e.g. `3 medium` | yellow `#d4a72c`, dark text |
| Worst is low | e.g. `1 low` | yellow-green `#a2b82c`, dark text |
| Only unknown severity | e.g. `1 unknown` | grey `#6e7781` |
| The version never received an SBOM | `no SBOM` | grey `#6e7781` |

Counts are listed from the worst severity to the least (`critical`, `high`, `medium`, `low`,
`unknown`), zero counts left out, separated by `, `. A known exploited finding is also counted
under its severity.

The JSON document:

```json
{"schemaVersion":1,"label":"vulnerabilities","message":"1 critical, 2 high","color":"cf222e"}
```

## Responses

| Status | When |
| --- | --- |
| `200` | The badge |
| `304` | `If-None-Match` names the badge's current `ETag` (or is `*`) |
| `404` | The key is unknown, was replaced by a new address, or the badge is off; the version is unknown; the extension is neither `.svg` nor `.json`; the query string is malformed (such as `version` given twice). The body is empty and does not say which |

Headers of a `200`:

| Header | Value |
| --- | --- |
| `Content-Type` | `image/svg+xml; charset=utf-8` or `application/json` |
| `Cache-Control` | `public, max-age=300`: image proxies, such as GitHub's, may serve a badge up to five minutes old |
| `ETag` | A strong tag of the body; badges are never compressed, so it names the bytes sent |
| `X-Content-Type-Options` | `nosniff` |
| `Content-Security-Policy` | SVG only: `default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'`, so the image opened on its own runs nothing |

A `304` carries the `ETag` and `Cache-Control` headers.

## What a badge exposes

To anyone with its address:

- the open findings of a version, by severity, and how many are known exploited;
- whether the version has received an SBOM;
- with `?version=`, whether a version of that name exists.

Not the project's or the organization's name, the findings themselves, the components or
anything else. The Markdown snippet of the project page links the image to the project page,
which only members can open, or to the project's [public page](public-pages.md) while it is on.
The badge's key never opens the public page, which has a key of its own.

The key is stored in clear in the database, unlike API tokens, so the project page can show the
snippet again. Request logs write badge paths as `/badges/…`, without the key, at debug level
([Metrics, health and logs](metrics.md#logs)).
