# Get notified

nanobom posts to webhooks and sends emails: new findings and stale projects to each
organization's webhook and email recipients, failed runs to the instance's failure webhook. An
organization's webhook receives JSON documents, or messages that Slack and Microsoft Teams show
in a channel. The documents, the messages, the emails, and when each is sent, are described in
the [webhook and email reference](../reference/webhooks.md).

## Send an organization's new findings to a webhook

An organization's admins configure one webhook in **Settings → Webhook**:

- **URL**: an `http` or `https` address;
- **Format**: **JSON document** (the default), **Slack message** or **Microsoft Teams message
  (Workflows)**; see [Post to Slack](#post-to-slack) and
  [Post to Microsoft Teams](#post-to-microsoft-teams);
- **Minimum severity**: findings below it are not sent (known exploited ones always are);
- **Only known exploited vulnerabilities**: send only known exploited findings, whatever their
  severity;
- **Enabled**: unchecked, nothing is sent, and deliveries waiting for a retry are abandoned.

Then **Save webhook**. After the next run that opens findings, **Recent deliveries** on the
settings page lists the documents sent, newest first: the event, whether it is **Sending** (its
first attempt is in progress), was **Delivered**, is **Retrying** (with the time of the next
attempt), **Failed** or **Cancelled** (the webhook was removed, disabled or moved before an
attempt was recorded), the number of attempts, and the time and answer of the last attempt (the
HTTP status, or the error). **Remove webhook** deletes the configuration and abandons the
deliveries still waiting for a retry; disabling the webhook or changing its URL abandons them
too, so retries never go to the old address, and changing its format does as well, since their
bodies were written for the previous one.

A receiver that is down for a while misses nothing: failed deliveries are retried after 1 minute,
10 minutes and 1 hour. A `4xx` answer other than `408` and `429` is not retried, so fix the
receiver or the URL and wait for the next document. The rules are in the
[webhook reference](../reference/webhooks.md#delivery).

Requests are not signed: use an unguessable URL (most receivers put a random identifier in the
path) over `https`, and answer within 15 seconds. A document can arrive twice when an answer is
lost; receivers that must not act twice can remember the run's `id` per event.

## Post to Slack

nanobom posts to a Slack [Incoming Webhook](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks):

1. Open [api.slack.com/apps](https://api.slack.com/apps), choose **Create New App**, then
   **From scratch**; name it `nanobom` and pick your workspace.
2. In the app's **Incoming Webhooks** page, turn **Activate Incoming Webhooks** on.
3. Choose **Add New Webhook to Workspace**, pick the channel that should receive the alerts and
   allow the app. Slack shows a URL like
   `https://hooks.slack.com/services/T0000/B0000/XXXXXXXX`; copy it. Anyone with this URL can
   post to the channel, so keep it secret.
4. In nanobom, open the organization's **Settings → Webhook**, paste the URL, set **Format** to
   **Slack message** and choose the minimum severity. Then **Save webhook**.

The next run that opens findings posts a message with a header (organization, number of
findings, highest severity), then up to 10 findings: the vulnerability identifier linking to its
page in nanobom, the component, the severity, whether it is known exploited and which direct
dependency introduces it. A last line counts the findings left out and links to the
organization. Messages are in English whatever the language of the interface; what they contain
is in the [webhook reference](../reference/webhooks.md#slack-messages).

Slack answers `200` with `ok`. A `400` (`invalid_payload`, `invalid_blocks`) or a `404`
(`no_service`: the webhook was revoked, or the URL is wrong) is not retried and shows as
**Failed** in **Recent deliveries**; fix the URL and wait for the next message.

## Post to Microsoft Teams

The connectors that Teams used to offer for incoming webhooks were
[retired](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook)
in favor of the **Workflows** app (Power Automate). nanobom sends what a Workflows webhook
accepts: a `message` carrying an [Adaptive Card](https://adaptivecards.microsoft.com), not the
`MessageCard` format of the old connectors, which a Workflows webhook does not render.

1. In Teams, open the channel that should receive the alerts, choose **More options (…)** next to
   its name, then **Workflows**.
2. Choose the template **Send webhook alerts to a channel**, name the workflow and sign in the
   connections it asks for, then **Next**.
3. Pick the team and the channel, then **Add workflow**.
4. Copy the **webhook URL** Teams shows (it is also on the workflow's page in Power Automate). It
   is a long `https://…logic.azure.com/…` address that carries its own key: keep it secret.
5. In nanobom, open the organization's **Settings → Webhook**, paste the URL, set **Format** to
   **Microsoft Teams message (Workflows)** and choose the minimum severity. Then **Save webhook**.

The next run that opens findings posts a card with the same content as the Slack message: a
title, up to 10 findings and a **Open … in nanobom** button. What it contains is in the
[webhook reference](../reference/webhooks.md#microsoft-teams-messages).

A Workflows webhook usually answers `202 Accepted` as soon as it has received the request, before
the workflow posts the card: nanobom counts it as delivered. If cards do not show up in the
channel while **Recent deliveries** says **Delivered**, look at the workflow's run history in
Power Automate: the workflow runs under the account of whoever created it, so it can stop working
when that account loses access to the channel.

## Send them by email

Emails go through an SMTP server of yours, which the operator configures once for the instance;
then each organization's admins choose who receives its emails.

1. Set the SMTP server and the sender, then restart nanobom:

   ```sh
   NANOBOM_SMTP_URL=smtps://nanobom%40example.org:app-password@smtp.example.org
   NANOBOM_SMTP_FROM="nanobom <nanobom@example.org>"
   ```

   `smtps://` connects with TLS on port 465; for a server that only offers STARTTLS on port 587,
   use `smtp://…:587?tls=required`. Percent-encode the user and password (`@` becomes `%40`).
   Most providers (Google Workspace, Microsoft 365, Amazon SES, Mailgun, Postmark…) give SMTP
   credentials for applications; use those rather than a person's password. Every option is in
   the [configuration reference](../reference/configuration.md#email). The log says
   `email notifications are on` at startup.
2. In nanobom, open the organization's **Settings → Email notifications** and fill in:
   - **Recipients**: one address per line (or separated by commas), at most 20; a team's
     mailing list is easier to keep up to date than a list of people;
   - **Language**: English or French;
   - **Minimum severity** and **Only known exploited vulnerabilities**, which work as for the
     webhook and independently of it.

   Then **Save email settings**.
3. Choose **Send a test email**. The page says **Test email sent** once the SMTP server accepted
   it, or shows its reply, such as `permanent error (535): authentication failed` for wrong
   credentials. A test can be sent every 30 seconds.

The next run that opens findings sends one email to all the recipients, with a subject such as
`nanobom: 3 new vulnerabilities in acme/web` and the findings, each linking to its page in
nanobom. Stale projects are emailed too. What an email contains is in the
[reference](../reference/webhooks.md#emails).

Emails show in **Recent deliveries** with the webhook's, marked **Email**. An SMTP reply in the
`4xx` range (greylisting, a full mailbox) is retried like a webhook; a `5xx` reply (an unknown
address, a message refused as spam) is not, and the delivery shows as **Failed** with the reply.
Changing the recipients or the language abandons the emails waiting for a retry; **Remove email
notifications** turns email off for the organization.

If emails land in spam, make sure the sender's domain allows your SMTP server to send for it
(SPF, DKIM): nanobom does not sign messages itself.

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

## Forward them to another chat

For a chat nanobom does not format, keep the **JSON document** format and put a small receiver in
between. This one turns every event into one chat line, with Python's standard library only;
adapt `forward` to your chat's incoming webhook:

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
webhook or email recipients receives its newly stale projects as `projects.stale` after
scheduled runs, whatever the minimum severity and the known exploited option. Nothing else is
needed.

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
