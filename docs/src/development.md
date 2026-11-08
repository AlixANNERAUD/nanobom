# Development

nanobom is a Rust workspace. The web interface is written with [Leptos](https://leptos.dev),
rendered on the server, and works without JavaScript; a small WebAssembly bundle adds
interactivity where the browser runs it.

## Architecture

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

### The run pipeline

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
        └─► gauges updated; webhooks sent (findings.new; projects.stale after scheduled
            runs), or run.failed to the failure webhook
```

Exploitation data comes before the waiting uploads so that `fail_on=exploited` sees the CVEs of
this run; notifications come after, so slow webhooks never hold CI.

## Running locally

[mise](https://mise.jdx.dev) installs the pinned toolchain (Rust, cargo-leptos, cargo-nextest,
cargo-deny, wasm-bindgen, mdBook…) and runs the tasks. Every cargo command goes through it
(`mise run …` or `mise exec -- cargo …`), since it also sets up the target directory.

```sh
mise install
mise run dev      # server with live reload on http://127.0.0.1:3000
mise run check    # formatting, clippy, tests and cargo-deny, as CI
mise run test     # tests only (cargo-nextest)
mise run coverage # tests with coverage, written to lcov.info
mise run build    # release binary and site in target/
mise run docs     # this book, in docs/book
```

The default database path, `/data/nanobom.db`, suits the container image, not a workstation. Put
local settings in a `mise.local.toml`, which git ignores:

```toml
[env]
NANOBOM_DATABASE_URL = "sqlite://nanobom-dev.db"
NANOBOM_LOG_FORMAT = "text"
```

Then create an administrator with
`mise exec -- cargo run -p nanobom -- create-administrator --username admin`.

To run the release build: `mise run build`, then
`NANOBOM_SITE_ROOT=target/site target/release/nanobom serve`.

## Tests

`mise run test` runs every test with cargo-nextest. Tests never call real network services: OSV,
CISA, FIRST and webhooks are replaced by [wiremock](https://docs.rs/wiremock) servers or by the
helpers of `nanobom_domain::testing`.

- `crates/domain/tests/` tests the domain against a temporary database, with SBOM fixtures from
  real generators in `crates/domain/tests/fixtures/`.
- `crates/server/tests/server/` drives the HTTP server end to end (uploads, sign-in, the
  interface, operations); `common.rs` starts a server on a fresh database.
- Unit tests sit next to the code they test.

## Database changes

1. Add a migration to `crates/migration/src/` and list it in `lib.rs`. Never edit a migration
   that was released: instances have already applied it.
2. Regenerate the entities with `mise run entities` (it applies the migrations to a temporary
   database and runs `sea-orm-cli`).

Migrations run at startup on SQLite; keep them compatible with existing data.

## Translations

Texts of the interface are in `crates/app/locales/en.json` and `fr.json`, used through the
`t!`, `tf!` and `tp!` macros; messages of the domain (validation errors) are in
`crates/domain/locales/`. Every key must exist in every language: a missing one fails the build.

To add a language:

1. copy `en.json` to `<tag>.json` in both locale directories, and translate every message
   (`language.name` is the language's name in itself, shown in the language switch);
2. add the tag to `EMBEDDED_I18N_LOCALES` in `.cargo/config.toml`.

The upload API's messages stay in English on purpose: they are read in CI logs.

## Documentation

This book lives in `docs/` and is built with [mdBook](https://rust-lang.github.io/mdBook/):
`mise run docs` builds it into `docs/book/`, and `mise exec -- mdbook serve docs --port 3001` serves it with
live reload on <http://localhost:3001> (port 3000 is the development server's). It is published to GitHub Pages from `main`. Document
behavior where users and operators look for it, and check options, defaults and messages against
the code.

## Contributing

- Pull request titles follow [Conventional Commits](https://www.conventionalcommits.org)
  (`feat: add SPDX uploads`, `fix(osv): retry on timeouts`); CI checks them. Pull requests are
  squash-merged, so the title becomes the commit on `main`, from which the version bump and the
  changelog are derived.
- Run `mise run check` before pushing; CI runs the same checks, plus the release build and the
  container image.
- Keep comments and documentation about what the code does not say: why, constraints,
  trade-offs.

## Releasing

Releases are automated with release-plz through a release pull request; merging it tags the
version, builds the archives and the images, and publishes the release.
[RELEASING.md](https://github.com/AlixANNERAUD/nanobom/blob/main/RELEASING.md) describes the
process and the required repository settings.
