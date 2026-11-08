# Notifications

nanobom sends JSON documents with `POST` to webhooks:

| Event | Sent to | When |
| --- | --- | --- |
| `findings.new` | the organization's webhook | after a successful run that opened or reopened findings worth reporting, or found open findings newly known exploited |
| `projects.stale` | the organization's webhook | after a scheduled run, when projects became stale |
| `run.failed` | `NANOBOM_FAILURE_WEBHOOK_URL` (instance) | when a run fails |

## Organization webhook

An organization's admins configure one webhook in **Settings → Webhook**:

- **URL**: an `http` or `https` address;
- **Minimum severity**: findings below it are not sent (known exploited ones always are);
- **Only known exploited vulnerabilities**: send only known exploited findings, whatever their
  severity;
- **Enabled**: unchecked, nothing is sent.

The settings page shows the time and outcome of the last delivery (the HTTP status, or the
error). **Remove webhook** deletes the configuration.

### `findings.new`

After each successful run, each organization with an enabled webhook receives one document
listing its findings that are:

- **new** or **reopened** by this run, at or above the minimum severity, or known exploited at any
  severity;
- open, known exploited, and never notified as such: findings reported earlier that CISA has
  added to its catalog since, sent once with the `exploited` reason.

With **Only known exploited vulnerabilities**, only the known exploited ones among them are sent.
Nothing is sent when nothing remains after filtering.

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

After an upgrade from a version without exploitation signals, the first run delivers every open
known exploited finding of its scope once with the `exploited` reason, since none had been
notified as such.

### `projects.stale`

After a **successful scheduled** run (and unless `NANOBOM_STALE_AFTER_DAYS` is `0`), each
organization with an enabled webhook receives the projects that
became [stale](findings/triage.md#stale-projects) since they were last notified, whatever the
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

`last_upload_at` is `null` for a project that never received an SBOM. A project is notified once
per stale period: again only if it receives an SBOM and later goes stale again. Projects of an
organization without an enabled webhook are not marked as notified, so enabling one sends the
currently stale projects after the next scheduled run.

## Failure webhook

`NANOBOM_FAILURE_WEBHOOK_URL` is the operator's alarm: it receives every failed run of the
instance, whatever its organization.

```json
{
  "event": "run.failed",
  "instance_url": "https://nanobom.example.org/",
  "run": { "id": 43, "trigger": "upload", "started_at": "2026-11-08T10:12:31.904+00:00" },
  "scope": "project",
  "error": "querying vulnerabilities failed: …"
}
```

`scope` is `all` (the scheduled run), `organization` or `project`. Since the error may name the
packages of any organization, send it to the operators, not to an organization's channel.

## Delivery

- One `POST` per document, `Content-Type: application/json`, with the `User-Agent`
  `nanobom/<version>`.
- Any `2xx` answer is a success. There is no retry: a failed delivery is logged (`webhook delivery
  failed`) and shown in the settings; the findings stay visible in the interface.
- A delivery that takes more than 15 seconds fails. Answer quickly and do slow work afterwards.
- Requests are not signed. Use an unguessable URL (most receivers put a random identifier in the
  path) over `https`, and treat the content as a hint to look at nanobom, not as an authority.
- Deliveries happen after uploads waiting for the run have been answered, so they never slow
  CI down.

## Receiving them

### Home Assistant

[`examples/home-assistant.yaml`](https://github.com/AlixANNERAUD/nanobom/blob/main/examples/home-assistant.yaml)
turns `findings.new` into phone notifications. Set the organization's webhook to
`https://home-assistant.example.org/api/webhook/nanobom-acme`, then add the automation:

```yaml
alias: nanobom new vulnerabilities
triggers:
  - trigger: webhook
    webhook_id: nanobom-acme
    allowed_methods: [POST]
    local_only: false
conditions:
  - condition: template
    value_template: "{{ trigger.json.event == 'findings.new' }}"
actions:
  - action: notify.mobile_app_phone
    data:
      title: >-
        {{ trigger.json.count }} new {{ trigger.json.highest_severity }}
        vulnerabilities in {{ trigger.json.organization.name }}
        {% if trigger.json.known_exploited_count > 0 %}
        ({{ trigger.json.known_exploited_count }} known exploited)
        {% endif %}
      message: >-
        {% for finding in trigger.json.findings[:5] %}
        {{ '[exploited] ' if finding.known_exploited }}{{ finding.vulnerability }} ({{ finding.severity }}) in {{ finding.component }}, {{ finding.project }}
        {% endfor %}
      data:
        url: "{{ trigger.json.findings[0].url }}"
```

`local_only: false` is needed when nanobom is not on Home Assistant's local network.

### A minimal receiver

A receiver that turns every event into one chat line, with Python's standard library only; adapt
`forward` to your chat's incoming webhook:

```python
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


def describe(event):
    kind = event["event"]
    if kind == "findings.new":
        exploited = event["known_exploited_count"]
        line = (f"{event['count']} new findings in {event['organization']['name']}, "
                f"highest {event['highest_severity']}")
        if exploited:
            line += f", {exploited} known exploited"
        return line + f": {event['organization']['url']}"
    if kind == "projects.stale":
        names = ", ".join(project["project"] for project in event["projects"])
        return f"No SBOM received lately in {event['organization']['name']}: {names}"
    if kind == "run.failed":
        return f"nanobom run {event['run']['id']} ({event['scope']}) failed: {event['error']}"
    return f"Unknown nanobom event {kind}"


def forward(line):
    print(line, flush=True)  # replace with a POST to your chat


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(204)  # answer first: nanobom waits 15 seconds at most
        self.end_headers()
        forward(describe(json.loads(body)))


HTTPServer(("0.0.0.0", 9000), Receiver).serve_forever()
```

New fields may be added to the documents in later versions; ignore the ones you do not know
rather than rejecting the request.
