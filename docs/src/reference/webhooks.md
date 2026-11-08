# Webhook payloads

nanobom sends JSON documents with `POST` to webhooks:

| Event | Sent to | When |
| --- | --- | --- |
| `findings.new` | the organization's webhook | after a successful run that opened or reopened findings worth reporting, or found open findings newly known exploited |
| `projects.stale` | the organization's webhook | after a successful scheduled run, when projects became stale |
| `run.failed` | `NANOBOM_FAILURE_WEBHOOK_URL` (instance) | when a run fails |

An organization's webhook is configured in **Settings → Webhook** (URL, minimum severity, only
known exploited vulnerabilities, enabled); see [Get notified](../how-to/notifications.md).

## Delivery

- One `POST` per document, `Content-Type: application/json`, with the `User-Agent`
  `nanobom/<version>`.
- Any `2xx` answer is a success. There is no retry: a failed delivery is logged (`webhook delivery
  failed`, or `failure webhook delivery failed`) and shown in the organization's settings, with
  the time and outcome of the last delivery; the findings stay visible in the interface.
- A delivery that takes more than 15 seconds fails.
- Requests are not signed.
- Deliveries happen after uploads waiting for the run have been answered, so they never slow
  CI down.
- New fields may be added to the documents in later versions.

## `findings.new`

After each successful run, each organization with an enabled webhook receives one document
listing its findings that are:

- **new** or **reopened** by this run, at or above the minimum severity, or known exploited at any
  severity;
- open, known exploited, and never notified as such: findings reported earlier that CISA has
  added to its catalog since, sent once with the `exploited` reason.

With **Only known exploited vulnerabilities**, only the known exploited ones among them are sent.
Nothing is sent when nothing remains after filtering. Ignored findings are never sent.

```json
{
  "event": "findings.new",
  "organization": {
    "slug": "acme",
    "name": "Acme",
    "url": "https://nanobom.example.org/organizations/acme"
  },
  "run": { "id": 42, "trigger": "scheduled", "started_at": "2026-11-08T03:00:00.081+00:00" },
  "count": 1,
  "highest_severity": "high",
  "known_exploited_count": 1,
  "findings": [
    {
      "project": "web",
      "component": "pkg:npm/lodash@4.17.20",
      "vulnerability": "GHSA-35jh-r3h4-6jhm",
      "aliases": ["CVE-2021-23337"],
      "severity": "high",
      "cvss_score": 7.2,
      "summary": "Command Injection in lodash",
      "reopened": false,
      "reason": "new",
      "known_exploited": true,
      "kev_due_date": "2026-11-29",
      "epss": 0.0149,
      "epss_percentile": 0.78,
      "url": "https://nanobom.example.org/findings/17"
    }
  ]
}
```

| Field | |
| --- | --- |
| `organization` | Slug, display name and page of the organization |
| `run` | The run that found them: identifier, `trigger` (`upload`, `scheduled` or `manual`) and start time |
| `count` | Number of entries in `findings` |
| `highest_severity` | The highest severity among them |
| `known_exploited_count` | How many of them are known exploited |
| `findings[].project` | Project slug |
| `findings[].component` | The component's package URL |
| `findings[].vulnerability` | The finding's identifier; `aliases` lists the others |
| `findings[].severity` | `critical`, `high`, `medium`, `low` or `unknown` |
| `findings[].cvss_score` | CVSS base score of the finding's record, or `null` |
| `findings[].summary` | One-line summary from OSV, or `null` |
| `findings[].reason` | `new`, `reopened` or `exploited` |
| `findings[].reopened` | `true` when `reason` is `reopened` |
| `findings[].known_exploited` | In CISA's KEV catalog |
| `findings[].kev_due_date` | CISA's due date, or `null` |
| `findings[].epss`, `epss_percentile` | EPSS score and percentile, from 0 to 1, or `null` |
| `findings[].url` | The finding's page |

Every known exploited open finding of a run's scope is marked as notified once that run is over,
whether a webhook received it or not: enabling a webhook later does not replay old findings.

## `projects.stale`

After a **successful scheduled** run (and unless `NANOBOM_STALE_AFTER_DAYS` is `0`), each
organization with an enabled webhook receives the projects that became
[stale](../explanation/findings.md#stale-projects) since they were last notified, whatever the
minimum severity and the known exploited option:

```json
{
  "event": "projects.stale",
  "organization": {
    "slug": "acme",
    "name": "Acme",
    "url": "https://nanobom.example.org/organizations/acme"
  },
  "projects": [
    {
      "project": "web",
      "last_upload_at": "2026-09-30T14:21:07.512+00:00",
      "url": "https://nanobom.example.org/organizations/acme/projects/web"
    }
  ]
}
```

| Field | |
| --- | --- |
| `organization` | Slug, display name and page of the organization |
| `projects[].project` | Project slug |
| `projects[].last_upload_at` | Time of the project's last upload; `null` for a project that never received an SBOM |
| `projects[].url` | The project's page |

A project is notified once per stale period: again only if it receives an SBOM and later goes
stale again. Projects of an organization without an enabled webhook are not marked as notified,
so enabling one sends the currently stale projects after the next scheduled run.

## `run.failed`

Sent to `NANOBOM_FAILURE_WEBHOOK_URL` for every failed run of the instance, whatever its
organization:

```json
{
  "event": "run.failed",
  "instance_url": "https://nanobom.example.org/",
  "run": { "id": 43, "trigger": "upload", "started_at": "2026-11-08T10:12:31.904+00:00" },
  "scope": "project",
  "error": "querying vulnerabilities failed: …"
}
```

| Field | |
| --- | --- |
| `instance_url` | `NANOBOM_PUBLIC_URL` |
| `run` | Identifier, `trigger` (`upload`, `scheduled` or `manual`) and start time |
| `scope` | `all` (the scheduled run), `organization` or `project` |
| `error` | Why the run failed; it may name the packages of any organization |
