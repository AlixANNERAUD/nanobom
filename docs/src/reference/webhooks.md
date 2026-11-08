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
- Each document is recorded in the database before it is sent, then posted right away. All the
  documents of a run are recorded before the first is posted, so a receiver that hangs delays
  the others but a restart meanwhile loses none. Deliveries happen after uploads waiting for the
  run have been answered, so they never slow CI down.
- An attempt that takes more than 15 seconds fails.
- How the receiver's answer is handled:

  | Answer | Outcome |
  | --- | --- |
  | `2xx` | Delivered |
  | `4xx`, except `408` and `429` | Failed for good: the receiver refuses the document and would refuse it again, so it is not retried |
  | `408`, `429`, `5xx`, any other status, a network error or a timeout | Retried |

- Retries come 1 minute after the first attempt, then 10 minutes after the first retry, then
  1 hour after the second; when the third retry fails, the delivery is abandoned. Due retries are
  looked for every 30 seconds, so one can come up to 30 seconds late. The schedule survives a
  restart; an attempt cut short by a restart is retried 2 minutes later.
- Every attempt that fails is logged (`webhook delivery failed`, with the delivery, its event,
  the attempt number and the status) and counted by `nanobom_webhook_deliveries_total`
  ([metrics](metrics.md)). The latest deliveries to an organization's webhook are listed in its
  settings.
- Removing an organization's webhook, disabling it or changing its URL abandons its deliveries
  still waiting for a retry, including one whose attempt is in progress: they never go to an
  address the admins replaced or turned off. In the same way, the `run.failed` deliveries still
  waiting for a retry are abandoned at startup when `NANOBOM_FAILURE_WEBHOOK_URL` changed or was
  removed.
- Delivered and abandoned deliveries are deleted after 30 days.
- A document can arrive more than once, when the receiver accepted it but its answer was lost or
  came after 15 seconds. The `event`, with the run's `id` for `findings.new` and `run.failed`,
  identifies it.
- The document is the one prepared after the run: a retry sends it unchanged, even if the
  findings changed since.
- Requests are not signed.
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
whether a webhook received it or not: enabling a webhook later does not replay old findings. A
finding notified to a receiver that is down is not lost: its delivery is retried (see
[Delivery](#delivery)), and never prepared a second time.

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
organization, including a run that stopped unexpectedly (a bug, or nanobom stopped while it
was running: such a run is closed at the next start, and its document is sent by the retry loop
within 30 seconds, so an unreachable receiver does not delay the startup):

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
| `error` | Why the run failed; it may name the packages of any organization. `the run stopped unexpectedly` for a run that did not end normally |
