# Metrics, health and logs

## `/healthz`

`GET /healthz` answers `200 {"status": "ok"}` when the database answers, and
`503 {"status": "unavailable"}` otherwise. It does not check OSV, CISA or FIRST. It needs no
authentication.

## `/metrics`

`GET /metrics` serves Prometheus metrics, without authentication. Labels are instance-wide, never
per organization or project, so the number of series stays small and the endpoint reveals nothing
about a particular organization.

| Metric | Type | |
| --- | --- | --- |
| `nanobom_open_findings{severity}` | gauge | Open findings of the active project versions across the instance, by severity (`critical`, `high`, `medium`, `low`, `unknown`); ignored findings and [inactive versions](versions.md#states) are not counted |
| `nanobom_open_findings_known_exploited` | gauge | Open findings of the active project versions with a CVE in CISA's KEV catalog |
| `nanobom_stale_projects` | gauge | Projects whose SBOM stopped coming |
| `nanobom_last_successful_run_timestamp_seconds` | gauge | Unix time at which the last successful run started |
| `nanobom_runs_total{status}` | counter | Runs, by status (`succeeded`, `failed`) |
| `nanobom_run_failures_total` | counter | Runs that could not complete |
| `nanobom_run_duration_seconds` | histogram | Duration of runs |
| `nanobom_osv_request_errors_total{kind}` | counter | Failed requests to OSV, retries included; `kind` is `status` (an error status) or `request` (network error or unreadable answer) |
| `nanobom_exploitation_refresh_failures_total` | counter | Refreshes of exploitation data that failed or were abandoned, including those where only one of KEV and EPSS failed; a refresh counts once even when both failed |
| `nanobom_webhook_deliveries_total{channel, outcome}` | counter | Delivery attempts, by channel (`webhook` or `email`, where each recipient of an email is a delivery of its own) and outcome: `delivered`, `retried` (the attempt failed and another is scheduled) or `abandoned` (the attempt failed and no retry follows: refused by the receiver, or the last retry) |

Gauges are computed from the database at startup and after each run. `nanobom_stale_projects`
is also recomputed on each scrape, since projects go stale with time alone (with
`NANOBOM_SCHEDULE=off` and few uploads, runs can be rare); if that fails, the scrape serves the
last value. `nanobom_last_successful_run_timestamp_seconds` only appears after the first
successful run.
Counters start at zero at each start, and appear only once something has been counted: a missing
`nanobom_run_failures_total` means no run failed since the start.

## Logs

nanobom writes one JSON object per line on standard error (`NANOBOM_LOG_FORMAT=text` for
humans; standard output is kept for command results), with the event's fields at the top level:

```json
{"timestamp":"2026-11-08T03:00:41.120Z","level":"INFO","message":"run succeeded","run":42,"scope":"all","components":1834,"vulnerabilities":97,"new":2,"fixed":5,"seconds":38.2,"target":"nanobom_domain::evaluation"}
```

Every request is logged once answered, with its method, path, status and duration. Query strings
are left out, since they can carry search terms; requests to `/healthz`, `/metrics`,
[badges](badges.md) and static assets are logged at debug level only. Badge paths are logged as
`/badges/…`: their key is their authorization. `NANOBOM_LOG_LEVEL=info,nanobom=debug` shows
them, and more detail from nanobom's own crates.

### Log messages

| Message | Level | Meaning |
| --- | --- | --- |
| `run failed; findings left unchanged` | error | A run could not complete; `error` says why |
| `OSV request failed, retrying` | warn | A request to OSV failed and is retried |
| `notification delivery failed` | warn | A webhook (an organization's, or the failure webhook) did not answer with a `2xx`, or an SMTP server did not accept an email; `channel`, `attempt` and `status` say which channel, which attempt and why. See [Delivery](webhooks.md#delivery) for retries |
| `test email failed` | warn | The **Send a test email** button of an organization's settings got no `2xx` from the SMTP server for at least one recipient; `status` gives each refused address and why |
| `a stage of a run panicked; the worker continues` | error | A bug stopped a run, or the work after it; the run is recorded as failed |
| `a run interrupted by a restart is recorded as failed` | warn | nanobom was stopped during a run; the run is closed at startup and sent to the failure webhook |
| `refreshing exploitation data failed` | warn | KEV or EPSS could not be downloaded, or did not answer within its 25 seconds; `feed` names it when the other feed was still stored |
| `the KEV catalog could not be downloaded; using the copy in memory` | warn | A KEV outage: the catalog downloaded `hours` ago is used instead |
| `cross-site request refused` | warn | A form submission came from another origin, often a wrong `NANOBOM_PUBLIC_URL` |
| `OpenID Connect sign-in refused` | warn | A single sign-on attempt failed; `error` says why |
| `starting the OpenID Connect sign-in failed` | error | The sign-in could not start, for example because discovery failed; `error` says why |
| `database error` | error | An unexpected database failure |
