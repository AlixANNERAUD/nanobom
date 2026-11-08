# Get notified

nanobom posts JSON documents to webhooks: new findings and stale projects to each organization's
webhook, failed runs to the instance's failure webhook. The documents, and when each is sent, are
described in the [webhook reference](../reference/webhooks.md).

## Send an organization's new findings to a webhook

An organization's admins configure one webhook in **Settings → Webhook**:

- **URL**: an `http` or `https` address;
- **Minimum severity**: findings below it are not sent (known exploited ones always are);
- **Only known exploited vulnerabilities**: send only known exploited findings, whatever their
  severity;
- **Enabled**: unchecked, nothing is sent, and deliveries waiting for a retry are abandoned.

Then **Save webhook**. After the next run that opens findings, **Recent deliveries** on the
settings page lists the documents sent, newest first: the event, whether it is **Sending** (its
first attempt is in progress), was **Delivered**, is **Retrying** (with the time of the next
attempt) or **Failed**, the number of attempts, and the time and answer of the last attempt (the
HTTP status, or the error). **Remove webhook** deletes the configuration and abandons the
deliveries still waiting for a retry; disabling the webhook or changing its URL abandons them
too, so retries never go to the old address.

A receiver that is down for a while misses nothing: failed deliveries are retried after 1 minute,
10 minutes and 1 hour. A `4xx` answer other than `408` and `429` is not retried, so fix the
receiver or the URL and wait for the next document. The rules are in the
[webhook reference](../reference/webhooks.md#delivery).

Requests are not signed: use an unguessable URL (most receivers put a random identifier in the
path) over `https`, and answer within 15 seconds. A document can arrive twice when an answer is
lost; receivers that must not act twice can remember the run's `id` per event.

## Receive them in Home Assistant

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

## Forward them to a chat

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

Ignore fields you do not know rather than rejecting the request: later versions may add some.

## Be told about stale projects

A project is stale when no SBOM arrived for `NANOBOM_STALE_AFTER_DAYS` (30 by default); see
[stale projects](../explanation/findings.md#stale-projects). An organization with an enabled
webhook receives its newly stale projects as `projects.stale` after scheduled runs, whatever the
minimum severity and the known exploited option. Nothing else is needed.

Choose the threshold above the longest normal gap between two builds: a library released twice a
year would be stale most of the time with the default, so either raise the threshold or upload
its SBOM from a scheduled pipeline. `NANOBOM_STALE_AFTER_DAYS=0` turns the feature off.

## Report failed runs to the operators

Set `NANOBOM_FAILURE_WEBHOOK_URL` to the operators' webhook:

```sh
NANOBOM_FAILURE_WEBHOOK_URL=https://hooks.example.org/nanobom-ops/7f3c9a
```

It receives a `run.failed` document for every failed run of the instance, whatever its
organization. Changing or removing the variable abandons, at the next start, the `run.failed`
deliveries still waiting for a retry to the previous address. Since the error may name the
packages of any organization, send it to the operators, not to an organization's channel. Pair
it with the [alert rules](monitoring.md#add-alert-rules), which also catch a schedule that
stopped running.
