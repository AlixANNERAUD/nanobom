# Webhook payloads and emails

nanobom sends documents with `POST` to webhooks, as JSON or, for an organization's webhook,
as a message for Slack or Microsoft Teams, and emails them to an organization's recipients:

| Event | Sent to | When |
| --- | --- | --- |
| `findings.new` | the organization's webhook and email recipients | after a successful run that opened or reopened findings worth reporting, or found open findings newly known exploited |
| `projects.stale` | the organization's webhook and email recipients | after a successful scheduled run, when projects became stale |
| `run.failed` | `NANOBOM_FAILURE_WEBHOOK_URL` (instance) | when a run fails |

An organization's webhook is configured in **Settings → Webhook** (URL, format, minimum severity,
only known exploited vulnerabilities, enabled), its email recipients in **Settings → Email
notifications** (recipients, language, minimum severity, only known exploited vulnerabilities);
see [Get notified](../how-to/notifications.md). The webhook and the email apply their own
filters: each gets the findings that pass its own.

## Formats

The **Format** of an organization's webhook says what its `findings.new` and `projects.stale`
events are posted as:

| Format | Posted as | For |
| --- | --- | --- |
| `json` (default) | The JSON documents described below | Your own receiver, Home Assistant, n8n |
| `slack` | A Slack message: `text` and Block Kit `blocks` ([Slack messages](#slack-messages)) | A Slack [Incoming Webhook](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks) |
| `teams` | A `message` with an Adaptive Card ([Microsoft Teams messages](#microsoft-teams-messages)) | A Microsoft Teams Workflows webhook |

`run.failed`, which goes to the instance's `NANOBOM_FAILURE_WEBHOOK_URL` and not to an
organization's webhook, is always JSON. The same filters apply to every format: minimum severity,
known exploited findings, which projects are reported. The format is stored per organization,
`json` for webhooks created before it existed.

The body is written when the delivery is recorded, so a retry posts exactly what the first
attempt did. Changing the format abandons the deliveries waiting for a retry, as changing the URL
does.

### Slack messages

The body is `{"text": …, "blocks": […]}`, the payload of a Slack Incoming Webhook. `text` is the
notification preview and the fallback of clients that do not display blocks. Texts are in English
whatever the language of the interface, since nanobom does not know the readers' language.

`findings.new`:

| Block | Content |
| --- | --- |
| `header` | `Acme: 3 new findings (highest severity: critical, 1 known exploited)` |
| one `section` per finding, at most 10 | `*<finding page\|vulnerability id>* - severity - reopened - known exploited`, then the component's package URL in code and the project, `Versions:` the project versions (at most 5, `unnamed version` for the unnamed one) when the project names versions, the OSV summary, and `Introduced via` the project's direct dependencies (at most 5) when the SBOM's dependency graph says |
| `context` | `N more findings not shown.` when some were left out, and a link to the organization |

`projects.stale`: a `header` (`Acme: 2 projects stopped sending SBOMs`), one `section` per project
at most 10 (`*<project page\|slug>* - last SBOM 2026-09-30 14:21 UTC`, or `never received an SBOM`)
and the same `context`.

The tags after the identifier are the severity, `reopened` for a reopened finding, and `known
exploited` (`newly known exploited` for an open finding that CISA added to its catalog after it
was reported). Findings come in the order of the JSON document.

Limits that nanobom stays within: a section's text is clipped to 3000 characters (Slack's limit),
the header to 150, and a message has at most 12 blocks. Values that come from SBOMs and
vulnerability records are clipped too, and `&`, `<` and `>` in them are escaped as `&amp;`,
`&lt;` and `&gt;`, as Slack requires, so that a package name cannot mention a channel
(`<!channel>`) or add a link. Slack has no other escape: `*`, `_` and `~` in a value can still
format it.

Slack answers `200` with the body `ok`. Bad requests (`400`) and revoked webhooks (`404`) are
not retried.

### Microsoft Teams messages

The body is the envelope Teams' **Workflows** webhooks accept, a `message` with one Adaptive Card
attachment, not the `MessageCard` format of the Office 365 connectors that Microsoft
[retired](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook)
in May 2026:

```json
{
  "type": "message",
  "attachments": [
    {
      "contentType": "application/vnd.microsoft.card.adaptive",
      "contentUrl": null,
      "content": {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.2",
        "msteams": { "width": "Full" },
        "body": [ … ],
        "actions": [
          { "type": "Action.OpenUrl", "title": "Open Acme in nanobom", "url": "https://nanobom.example.org/organizations/acme" }
        ]
      }
    }
  ]
}
```

The `body` has the same content as the Slack message, in English: a bold title, then one
container per finding or project (at most 10) with the vulnerability identifier linking to its
page, its tags, the component and project, the `Versions:` line, the summary and the `Introduced via` line, and a last
line counting what was left out. Known exploited findings are in the card's attention color. The
button opens the organization's page.

Texts are Markdown, as Adaptive Cards allow in a `TextBlock`; `\`, `*`, `_`, `[`, `]`, `` ` ``,
`<` and `>` in values from SBOMs are backslash-escaped, so a value cannot add a link or
formatting. Teams refuses incoming messages above 28 KB: nanobom lists fewer items, and says how
many were left out, until the message is under 24 KB.

A Workflows webhook usually answers `202 Accepted` before the workflow posts the card, so a
delivery shown as delivered can still fail inside Power Automate (see the workflow's run
history).

## Emails

When the instance has an SMTP server (`NANOBOM_SMTP_URL`, see
[configuration](configuration.md#email)), an organization's `findings.new` and `projects.stale`
events are also emailed to its recipients:

- **One message per event and organization**, sent to each recipient separately: the SMTP
  envelope of each copy holds one recipient, so an address the SMTP server refuses fails alone
  and the others still get the email. The `To` header lists every recipient: they are the
  organization's own people, and seeing who else was told helps them coordinate. At most 20
  recipients; use a mailing list for more.
- **From** `NANOBOM_SMTP_FROM`.
- **Language**: English or French, chosen per organization (English by default).
- **Subject**: `nanobom: 3 new vulnerabilities in acme/web` (the organization's slug and the
  project when every finding is in one project, the organization's name otherwise) and
  `nanobom: 2 projects stopped sending SBOMs`; in French, `nanobom : 3 nouvelles vulnérabilités
  dans acme/web` and `nanobom : 2 projets n’envoient plus de SBOM`.
- **Body**: a plain-text part and an HTML alternative with the same content: a headline (the
  organization and the number of findings or projects), the highest severity and the number of
  known exploited findings, then up to 50 findings, each with its identifier linking to its page,
  its severity and tags (`reopened`, `known exploited`, `newly known exploited`), the component and
  project, the project versions when the project names versions (`unnamed version`, or
  `version sans nom` in French, for the unnamed one), the summary and the direct dependencies
  that introduce it; for stale projects, each
  project linking to its page with the time of its last SBOM. A line counts the items left out,
  a link opens the organization, and a footer says why the reader gets the email and links to
  the organization's settings.
- Values from the data (names, components, summaries) are kept on one line and clipped (100
  characters for names, 250 for components, 300 for summaries); the HTML part escapes them.
- Links use `NANOBOM_PUBLIC_URL`.

`run.failed` is not emailed: it goes to the failure webhook only.

The **Send a test email** button of the settings sends a test message to each saved recipient at
once and shows the SMTP server's reply for each address it refuses. The test message names the
organization by its slug, never its display name, since it goes on demand to addresses nobody
verified. Test emails are limited to one every 30 seconds per organization, one every 30 seconds
per user, and 10 every 10 minutes for the whole instance.

## Delivery

Webhook documents and emails go through the same queue, with the same retries.

- One `POST` per document, `Content-Type: application/json`, with the `User-Agent`
  `nanobom/<version>`; the body is in the webhook's [format](#formats).
- Each document is recorded in the database before it is sent, then posted right away. All the
  documents of a run are recorded before the first is posted, so a receiver that hangs delays
  the others but a restart meanwhile loses none. Deliveries happen after uploads waiting for the
  run have been answered, so they never slow CI down.
- An attempt that takes more than 15 seconds fails.
- How the receiver's answer is handled:

  | Answer | Outcome |
  | --- | --- |
  | `2xx` (`200 ok` from Slack, `202 Accepted` from a Teams Workflows webhook, `204` from most receivers) | Delivered |
  | `4xx`, except `408` and `429` | Failed for good: the receiver refuses the document and would refuse it again, so it is not retried |
  | `408`, `429`, `5xx`, any other status, a network error or a timeout | Retried |

- Each recipient of an email is a delivery of its own, retried and abandoned on its own. Its copy
  is sent in one connection; each SMTP command may take 15 seconds, the whole message 60. How
  the SMTP server's reply is handled:

  | Reply | Outcome |
  | --- | --- |
  | `2xx` (`250` once the message is queued) | Delivered |
  | `5xx` (unknown mailbox, refused as spam, authentication failed) | Failed for good, not retried |
  | `4xx` (mailbox busy, greylisting), a network or TLS error, or a timeout | Retried |
  | No SMTP server configured any more | Failed for good |

- Retries come 1 minute after the first attempt, then 10 minutes after the first retry, then
  1 hour after the second; when the third retry fails, the delivery is abandoned. Due retries are
  looked for every 30 seconds, so one can come up to 30 seconds late. The schedule survives a
  restart; an attempt cut short by a restart is retried 2 minutes later.
- Every attempt that fails is logged (`notification delivery failed`, with the delivery, its
  channel, its event, the attempt number and the status) and counted by
  `nanobom_webhook_deliveries_total` ([metrics](metrics.md)). The latest deliveries of an
  organization, webhook and email, are listed in its settings with their channel, and the
  recipient of each email.
- Removing an organization's webhook, disabling it or changing its URL or format abandons its deliveries
  still waiting for an attempt or a retry: no new attempt goes to an address the admins replaced
  or turned off. An attempt already in progress at that moment is not stopped, so its request
  may still reach the old address; its result is not recorded and it is not retried. A delivery
  abandoned before any attempt was recorded shows as **Cancelled** in the settings, one
  abandoned after a failed attempt as **Failed**. In the same way, the `run.failed` deliveries
  still waiting for a retry are abandoned at startup when `NANOBOM_FAILURE_WEBHOOK_URL` changed
  or was removed.
- Changing an organization's email recipients or language, or removing its email settings,
  abandons its emails still waiting for an attempt or a retry, the same way; changing only its
  filters does not. All pending emails are abandoned at startup when `NANOBOM_SMTP_URL` was
  removed.
- Delivered and abandoned deliveries are deleted after 30 days.
- A document can arrive more than once, when the receiver accepted it but its answer was lost or
  came after 15 seconds. The `event`, with the run's `id` for `findings.new` and `run.failed`,
  identifies it.
- The document is the one prepared after the run: a retry sends it unchanged (in the same
  format), even if the findings changed since.
- Requests are not signed.
- New fields may be added to the documents in later versions.

## `findings.new`

These are the JSON documents; the other [formats](#formats) carry the same findings.

After each successful run, each organization with an enabled webhook receives one document
listing its findings that are:

- **new** or **reopened** by this run, at or above the minimum severity, or known exploited at any
  severity;
- open, known exploited, and never notified as such: findings reported earlier that CISA has
  added to its catalog since, sent once with the `exploited` reason.

With **Only known exploited vulnerabilities**, only the known exploited ones among them are sent.
Nothing is sent when nothing remains after filtering. Ignored findings are never sent.

A project with several [versions](../explanation/concepts.md#versions) has one finding per
version. They are sent as **one entry per project, vulnerability and component** (package
URL), with the versions it stands for in `versions`: a new advisory against a dependency five
versions share is one entry, not five. Two components hit by one advisory, such as a direct
`pkg:npm/lodash@4.17.20` and a nested `pkg:npm/lodash@4.17.15`, stay two entries, each with its
own `introduced_via`; a project that never names versions gets one entry per finding. Findings
a new version inherits from the latest one when it is created are not new, and are never sent.
[Inactive versions](versions.md#states) are not evaluated, so they send nothing, known exploited
findings included; made active again, a version's next run sends what it missed.

Rarely, a run already in progress when an upload creates a version announces an advisory for
both versions though the new one inherited the finding, or announces again, for the new
version, a finding that just became known exploited.

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
      "introduced_via": ["web-framework"],
      "versions": ["2.4", "3.0"],
      "url": "https://nanobom.example.org/findings/17"
    }
  ]
}
```

| Field | |
| --- | --- |
| `organization` | Slug, display name and page of the organization |
| `run` | The run that found them: identifier, `trigger` (`upload`, `scheduled` or `manual`) and start time |
| `count` | Number of entries in `findings`, one per project, vulnerability and component |
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
| `findings[].introduced_via` | The names of the project's direct dependencies that lead to the component, sorted; the component's own name when it is one; empty when the SBOM's dependency graph does not say ([Dependency paths](../explanation/dependency-paths.md)) |
| `findings[].versions` | The names of the project versions the entry stands for, sorted; `""` is the unnamed version, the only one of a project that never names versions. `introduced_via` and `url` are those of the latest version's finding when the latest version is among them, of the first one otherwise; `severity`, `cvss_score` and `known_exploited` are the highest among them, and `reason` the first of `new`, `reopened`, `exploited` |
| `findings[].url` | The finding's page |

Every known exploited open finding of a run's scope is marked as notified once that run is over,
whether a webhook received it or not: enabling a webhook later does not replay old findings. A
finding notified to a receiver that is down is not lost: its delivery is retried (see
[Delivery](#delivery)), and never prepared a second time.

## `projects.stale`

After a **successful scheduled** run (and unless `NANOBOM_STALE_AFTER_DAYS` is `0`), each
organization with an enabled webhook or email recipients receives the projects that became
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
stale again. Projects of an organization without an enabled webhook or email recipients are not
marked as notified, so configuring either sends the currently stale projects after the next
scheduled run.

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
