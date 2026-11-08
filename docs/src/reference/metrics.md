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
| `nanobom_open_findings{severity}` | gauge | Open findings across the instance, by severity (`critical`, `high`, `medium`, `low`, `unknown`); ignored findings are not counted |
| `nanobom_open_findings_known_exploited` | gauge | Open findings with a CVE in CISA's KEV catalog |
| `nanobom_stale_projects` | gauge | Projects whose SBOM stopped coming |
| `nanobom_last_successful_run_timestamp_seconds` | gauge | Unix time at which the last successful run started |
| `nanobom_runs_total{status}` | counter | Runs, by status (`succeeded`, `failed`) |
| `nanobom_run_failures_total` | counter | Runs that could not complete |
| `nanobom_run_duration_seconds` | histogram | Duration of runs |
| `nanobom_osv_request_errors_total{kind}` | counter | Failed requests to OSV, retries included; `kind` is `status` (an error status) or `request` (network error or unreadable answer) |
| `nanobom_exploitation_refresh_failures_total` | counter | Refreshes of exploitation data that failed or were abandoned |

Gauges are computed from the database at startup and after each run;
`nanobom_last_successful_run_timestamp_seconds` only appears after the first successful run.
Counters start at zero at each start, and appear only once something has been counted: a missing
`nanobom_run_failures_total` means no run failed since the start.

## Logs

nanobom writes one JSON object per line on standard output (`NANOBOM_LOG_FORMAT=text` for
humans), with the event's fields at the top level:

```json
{"timestamp":"2026-11-08T03:00:41.120Z","level":"INFO","message":"run succeeded","run":42,"scope":"all","components":1834,"vulnerabilities":97,"new":2,"fixed":5,"seconds":38.2,"target":"nanobom_domain::evaluation"}
```

Every request is logged once answered, with its method, path, status and duration. Query strings
are left out, since they can carry search terms; requests to `/healthz`, `/metrics` and static
assets are logged at debug level only. `NANOBOM_LOG_LEVEL=info,nanobom=debug` shows them, and more
detail from nanobom's own crates.

### Log messages

| Message | Level | Meaning |
| --- | --- | --- |
| `run failed; findings left unchanged` | error | A run could not complete; `error` says why |
| `OSV request failed, retrying` | warn | A request to OSV failed and is retried |
| `webhook delivery failed` | warn | An organization's webhook did not answer with a `2xx` |
| `failure webhook delivery failed` | error | The failure webhook itself could not be reached |
| `refreshing exploitation data failed` | warn | KEV or EPSS could not be downloaded |
| `cross-site request refused` | warn | A form submission came from another origin, often a wrong `NANOBOM_PUBLIC_URL` |
| `OpenID Connect sign-in refused` | warn | A single sign-on attempt failed; `error` says why |
| `starting the OpenID Connect sign-in failed` | error | The sign-in could not start, for example because discovery failed; `error` says why |
| `database error` | error | An unexpected database failure |
