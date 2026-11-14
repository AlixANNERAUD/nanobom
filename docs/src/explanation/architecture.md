# Architecture

nanobom is one process and one database, a SQLite file by default or PostgreSQL. There is no
worker to scale, no cache to warm and no queue to drain: running it well comes down to a reverse
proxy in front, a backup of the database, and a few alerts.

It is a Rust workspace. The web interface is written with [Leptos](https://leptos.dev), rendered
on the server, and works without JavaScript; a small WebAssembly bundle adds interactivity where
the browser runs it.

## Crates

| Crate | Role |
| --- | --- |
| `domain` | Everything with business rules: SBOM parsing and the inventory, runs and findings, exploitation data, notifications, organizations, memberships, tokens, users. All database access goes through it, and every function touching organization data takes an `Actor` (a `Reader`, user or token, for reads) and checks its permission (`access.rs`). |
| `osv` | The OSV client (batch queries, record details, retries) and CVSS-based severity. |
| `authentication` | Sessions stored in the database, password and OpenID Connect sign-in, claims and group mapping, cross-site request checks. |
| `entity` | SeaORM entities, generated from the migrations by `mise run entities`; never edited by hand. |
| `migration` | The database schema, as SeaORM migrations. |
| `app` | The Leptos interface: pages, components, server functions, translations. |
| `frontend` | The WebAssembly entry point of the interface. |
| `server` | The `nanobom` binary: command line, HTTP server, upload and read APIs, MCP endpoint, badges, public pages, run queue, metrics. |

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
  README image ────►│ badges ───────────► domain::badges (key, open finding counts)      │
  visitor ─────────►│ public_pages ─────► domain::public_pages (key, allowlisted page)   │
                    └─────────────────────────────────────┬─────────────────────────────┘
                                                          │
                                SQLite or PostgreSQL (SeaORM entities, migrations)
```

## The run pipeline

```text
run request (upload, schedule, manual)
  └─► runner queue: one run at a time; requests for a scope already waiting are merged
        └─► domain::evaluation::Evaluator::run
              1. ignored findings whose expiry passed return to open
              2. components of the scope that have a package version are collected
              3. osv: one batch query per 1,000 distinct package URLs,
                 then the records that are new or modified since they were cached
              4. per project version, in one transaction: identifiers are grouped by alias,
                 severity is computed, findings are opened, reopened or fixed, events recorded
              5. the run is recorded as succeeded or failed (a failure changes no finding)
        └─► if it succeeded: exploitation data (KEV, EPSS) refreshed for the scope (≤ 60 s)
        └─► uploads waiting for this run are answered
        └─► gauges updated; webhook documents and emails queued and sent (findings.new;
            projects.stale after scheduled runs), or run.failed to the failure webhook

delivery retry loop (every 30 s): due webhook posts and emails sent again, a few at a time;
  delivered and abandoned ones deleted after 30 days
```

Exploitation data comes before the waiting uploads so that `fail_on=exploited` sees the CVEs of
this run; notifications come after, so slow webhooks never hold CI. Webhook documents and emails
are stored before their first attempt, so a receiver that is down gets them once it is back (see
[Delivery](../reference/webhooks.md#delivery)). A run that panics, or that a restart interrupts,
is recorded as failed and notified like any failed run; at startup the failure document is only
queued, and the retry loop posts it, so the server listens without waiting for the receiver. The
rules each step applies are described in [How findings are kept up to date](findings.md).

## One process per database

Runs are serialized inside the process, and the schedule runs in it. Two servers on the same
database would each run the schedule and send every webhook twice: one instance runs one
process. The startup also assumes it: it closes every run still `running` in the database as
interrupted, so a rolling deploy that starts a new instance while the old one is still running a
check would record the old instance's live run as failed.

## SQLite or PostgreSQL

Both hold the same schema and run the same code, and the test suite runs on both. The choice is
about operations, not features.

SQLite is the default because it needs nothing: the database is a file next to the process, it
is created on the first start, and `nanobom backup` copies it while nanobom runs. One nanobom
process is the only writer anyway, and its load (bursts after uploads and at night) is far from
what a single SQLite file handles. Pick it unless something below applies.

PostgreSQL fits when the database should live outside the nanobom host:

- **You already run PostgreSQL**, with its monitoring, its backups (`pg_dump`, continuous
  archiving, point-in-time recovery) and the people who look after them, and want nanobom's data
  covered by the same routine instead of a file with its own backup job.
- **A managed database** (from a cloud provider or a platform team) takes backups, replication
  and upgrades off your hands, and lets the nanobom container stay stateless, which suits
  platforms where containers have no durable volume.
- **A shared database server** gathers the data of several services in one place, with access
  control, encryption in transit and auditing set once.

PostgreSQL does not make nanobom scale out: there is still
[one process per database](#one-process-per-database). It adds a server to run (or pay for), a
network hop, and a password to keep. nanobom has no tool to move data between the two, so choose
at installation; see [Run on PostgreSQL](../how-to/postgresql.md).

On SQLite, timestamps are stored as text and compared as text, which is correct because nanobom
writes every timestamp in UTC; PostgreSQL stores them as `timestamp with time zone`. Queries
whose result order matters state it (`ORDER BY`), since PostgreSQL, unlike SQLite, returns rows
in no particular order otherwise.

SQLite lets one connection write at a time. Every transaction that writes takes the write lock
when it starts (`BEGIN IMMEDIATE`), and a connection waits up to 10 seconds for it while another
holds it, so concurrent writes (an upload during a run, a form, the webhook retries) queue up
instead of failing. A transaction that took the lock only at its first write could fail at once
if another connection had written since it started reading. PostgreSQL locks rows, not the
database, and needs none of this.

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
