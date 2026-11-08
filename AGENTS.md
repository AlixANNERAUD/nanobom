# AGENTS.md

Guidance for coding agents working on nanobom, a self-hosted SBOM vulnerability tracker in Rust.
Read this before changing anything; the [guide](https://alixanneraud.github.io/nanobom/) explains
the product, and the crate-level rustdoc explains each crate.

## Layout

A Cargo workspace, one crate per concern:

| Crate | Role |
| --- | --- |
| `crates/domain` | All database access and business rules: inventory, OSV matching, findings, exploitation data (KEV, EPSS), notifications, organizations and access control |
| `crates/osv` | OSV schema types, the OSV client and severity scoring |
| `crates/authentication` | Sessions, local accounts, OpenID Connect, the cross-site request check |
| `crates/entity` | SeaORM entities, **generated**: never edit by hand, run `mise run entities` after a migration |
| `crates/migration` | Database schema (SQLite and PostgreSQL) |
| `crates/app` | Leptos interface (server-rendered, islands), English and French |
| `crates/frontend` | WebAssembly entry point of the interface |
| `crates/server` | The `nanobom` binary: command line, HTTP API, run worker, webhook retries, metrics |

Also: `docs/` (mdBook guide), `examples/` (CI and Home Assistant), `compose.yaml`, `Dockerfile`,
`.github/workflows/` (CI, docs, releases).

## Commands

Everything goes through [mise](https://mise.jdx.dev), which pins the toolchain. Plain `cargo` may
fail: the build directory is set up by mise.

| Command | Does |
| --- | --- |
| `mise install` | Installs the pinned tools |
| `mise run format` | Formats the code |
| `mise run lint` | rustfmt check, clippy with `-D warnings` for the server and for the WebAssembly frontend |
| `mise run test` | The test suite (nextest) |
| `mise run check` | What CI runs: lint, tests, cargo-deny |
| `mise run dev` / `mise run dev-admin` | Development server on http://127.0.0.1:3000 with a local database / its first administrator |
| `mise run entities` | Regenerates `crates/entity` from the migrations |
| `mise run docs` | Builds the guide into `docs/book` |
| `mise run build` | Release binary and site |

Builds are heavy: run one cargo command at a time, and prefer focused tests
(`mise exec -- cargo nextest run -p nanobom-domain <filter>`) while iterating, the full suite once
before committing.

## Rules

**Code**
- Every function reading or changing organization data lives in `crates/domain`, takes an `Actor`
  and authorizes it. Data of another organization is reported as not found, never forbidden.
- Integer columns are 64 bits, enumerations are stored as text, timestamps are UTC with time zone.
  On SQLite, timestamps are compared as text, which is only correct because every write uses
  UTC.
- Errors shown to users are `Problem` variants (`crates/domain/src/problem.rs`), translated in
  `crates/domain/locales/`. The upload API answers in English.
- Every interface string goes through `t!`/`tf!`/`tp!` with keys in **both**
  `crates/app/locales/en.json` and `fr.json`: builds are strict and fail on a missing key.
- The interface works without JavaScript: actions are plain forms posting to server functions.
- Tests never call real services (OSV, CISA, FIRST, webhooks): use `wiremock` and the helpers in
  `nanobom_domain::testing` and `crates/server/tests/server/common.rs`.
- Comments and rustdoc explain what is not obvious (why, invariants, trade-offs); never restate
  the code.

**Documentation**
- The guide in `docs/src` follows [Diátaxis](https://diataxis.fr): `tutorials/`, `how-to/`,
  `reference/`, `explanation/`, one type per page; facts live in the reference and other pages
  link to them. Update it with any user-visible change, and check option names, defaults and
  messages against the code.
- Plain, concise English. Never use em dashes (the long dash): use a hyphen or a comma.

**Git and pull requests**
- Branch from `main`; open a pull request; never push to `main` directly.
- Commits and pull request titles follow [Conventional Commits](https://www.conventionalcommits.org)
  (`feat:`, `fix:`, `perf:`, `docs:`, `ci:`, `test:`, `refactor:`, `build:`), imperative, with
  an explanatory body. CI checks pull request titles; release-plz builds versions and the
  changelog from them (see [RELEASING.md](RELEASING.md)).
- Do not mention AI tools or assistants in commits or pull requests, and add no
  `Co-Authored-By` or "Generated with" lines.
- Actions in workflows are referenced by release tag (`actions/checkout@v7.0.1`).
