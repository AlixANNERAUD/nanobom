# Monitor with Prometheus

nanobom serves Prometheus metrics at `/metrics` and a health endpoint at `/healthz`; the metrics,
the health answers and the log messages are listed in the
[metrics and logs reference](../reference/metrics.md).

## Check health

Point your orchestrator or supervisor at `GET /healthz`, which answers `200` when the database
answers. The container image already checks itself with `nanobom healthcheck`, which requests
`/healthz` over loopback (the image has no shell or `curl`). Outside containers, the same command
works in any supervisor; `--url` checks another address.

The health check does not cover OSV, CISA or FIRST: an orchestrator restarting nanobom would not
bring them back. Their outages show in failed runs and in the metrics.

## Scrape the metrics

```yaml
# prometheus.yml
scrape_configs:
  - job_name: nanobom
    static_configs:
      - targets: ["nanobom.internal:8080"]
```

`/metrics` needs no authentication: keep it internal at the proxy
([Run behind a reverse proxy](reverse-proxy.md)), or scrape nanobom on a private network.

## Add alert rules

```yaml
groups:
  - name: nanobom
    rules:
      # Nothing has been checked against OSV for a day and a half: the nightly run failed,
      # or the schedule is off. Matches any successful run, uploads included.
      - alert: NanobomNoRecentSuccessfulRun
        expr: time() - nanobom_last_successful_run_timestamp_seconds > 36 * 3600
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "nanobom has not completed a run for {{ $value | humanizeDuration }}"

      - alert: NanobomRunsFailing
        expr: increase(nanobom_run_failures_total[6h]) > 0
        labels:
          severity: warning
        annotations:
          summary: "nanobom runs are failing (OSV unreachable?); findings are not up to date"

      - alert: NanobomKnownExploitedFindings
        expr: nanobom_open_findings_known_exploited > 0
        for: 1h
        labels:
          severity: critical
        annotations:
          summary: "{{ $value }} open findings are known to be exploited in the wild"

      - alert: NanobomStaleProjects
        expr: nanobom_stale_projects > 0
        for: 1d
        labels:
          severity: info
        annotations:
          summary: "{{ $value }} projects have not received an SBOM lately"

      - alert: NanobomExploitationDataFailing
        expr: increase(nanobom_exploitation_refresh_failures_total[1d]) >= 3
        labels:
          severity: info
        annotations:
          summary: "KEV or EPSS downloads keep failing; exploitation data is getting old"

      - alert: NanobomDown
        expr: up{job="nanobom"} == 0
        for: 5m
        labels:
          severity: critical
```

Adjust the first rule to your schedule: with `NANOBOM_SCHEDULE=0 */6 * * *`, a few hours is enough.
On a new instance, `nanobom_last_successful_run_timestamp_seconds` only appears after the first
successful run.

The known exploited and stale project alerts are about the projects, not about nanobom: route
them to the people who fix dependencies, or rely on the organizations'
[webhooks](notifications.md) instead.

## Alert on logs

nanobom writes one JSON object per line on standard output. If you collect logs, alert on the
messages listed in the [logs reference](../reference/metrics.md#log-messages), first of all
`run failed; findings left unchanged`, `failure webhook delivery failed` and `database error`.
