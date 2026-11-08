# Architecture

nanobom is one process and one SQLite file. There is no worker to scale, no cache to warm and no
queue to drain: running it well comes down to a reverse proxy in front, a backup of the file,
and a few alerts.

It is a Rust workspace. The web interface is written with [Leptos](https://leptos.dev), rendered
on the server, and works without JavaScript; a small WebAssembly bundle adds interactivity where
the browser runs it.

## Crates

| Crate | Role |
| --- | --- |
| `domain` | Everything with business rules: SBOM parsing and the inventory, runs and findings, exploitation data, notifications, organizations, memberships, tokens, users. All database access goes through it, and every function touching organization data takes an `Actor` and checks its permission (`access.rs`). |
| `osv` | The OSV client (batch queries, record details, retries) and CVSS-based severity. |
| `authentication` | Sessions stored in the database, password and OpenID Connect sign-in, claims and group mapping, cross-site request checks. |
| `entity` | SeaORM entities, generated from the migrations by `mise run entities`; never edited by hand. |
| `migration` | The database schema, as SeaORM migrations. |
| `app` | The Leptos interface: pages, components, server functions, translations. |
| `frontend` | The WebAssembly entry point of the interface. |
| `server` | The `nanobom` binary: command line, HTTP server, upload API, run queue, metrics. |

```text
                    ┌──────────────────── server: the nanobom binary ───────────────────┐
  CI  ─ PUT SBOM ──►│ api ──────────────► domain::inventory (parse, replace components)  │
                    │  │                                                                  │
                    │  └── run request ─► runner ◄── schedule, "Check now" (app)          │
                    │                       │                                            │
  browser ─────────►│ authentication ─► app (pages, server functions) ─► domain          │
                    │ (sessions, CSRF,                                    (access checks)│
                    │  OIDC)                                                             │
  Prometheus ──────►│ /metrics, /healthz                                                 │
                    └─────────────────────────────────────┬─────────────────────────────┘
                                                          │
                                           SQLite (SeaORM entities, migrations)
```

## The run pipeline

```text
run request (upload, schedule, manual)
  └─► runner queue: one run at a time; requests for a scope already waiting are merged
        └─► domain::evaluation::Evaluator::run
              1. ignored findings whose expiry passed return to open
              2. versioned components of the scope are collected
              3. osv: one batch query per 1,000 distinct package URLs,
                 then the records that are new or modified since they were cached
              4. per project, in one transaction: reported identifiers are grouped by alias,
                 severity is computed, findings are opened, reopened or fixed, events recorded
              5. the run is recorded as succeeded or failed (a failure changes no finding)
        └─► if it succeeded: exploitation data (KEV, EPSS) refreshed for the scope (≤ 60 s)
        └─► uploads waiting for this run are answered
        └─► gauges updated; webhook documents queued and posted (findings.new;
            projects.stale after scheduled runs), or run.failed to the failure webhook

webhook retry loop (every 30 s): due deliveries posted again, a few at a time;
  delivered and abandoned ones deleted after 30 days
```

Exploitation data comes before the waiting uploads so that `fail_on=exploited` sees the CVEs of
this run; notifications come after, so slow webhooks never hold CI. Webhook documents are stored
before their first attempt, so a receiver that is down gets them once it is back (see
[Delivery](../reference/webhooks.md#delivery)). A run that panics, or that a restart interrupts,
is recorded as failed and notified like any failed run. The rules each step applies
are described in [How findings are kept up to date](findings.md).

## One process per database

Runs are serialized inside the process, and the schedule runs in it. Two servers on the same
database would each run the schedule and send every webhook twice: one instance runs one
process.

## Resources

nanobom does its work in short bursts, after uploads and at night, and is idle the rest of the
time. What makes it grow:

- **Memory** peaks during uploads: each request body is held in memory, and parsing an SBOM takes
  a few times its size, with two SBOMs parsed at a time at most. Raise
  `NANOBOM_MAXIMUM_SBOM_SIZE` with that in mind.
- **Disk** holds the components of each project's latest SBOM, the findings and their history,
  and the cached vulnerability records. Old uploads only keep their metadata (date, commit, tag,
  counts), not their components, so the database grows with the number of projects and findings,
  not with the number of uploads.
- **Run duration** depends on the number of distinct package URLs (one OSV request per 1,000) and
  on how many vulnerability records are new or modified (fetched 8 at a time). The first run of a
  large instance takes the longest; later ones reuse the cache. Watch
  `nanobom_run_duration_seconds`, and keep `NANOBOM_UPLOAD_WAIT_SECONDS` above the usual duration
  of a project's run plus the time it may wait behind the nightly run.
