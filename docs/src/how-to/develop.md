# Develop and contribute

nanobom is a Rust workspace; how its crates fit together is described in
[Architecture](../explanation/architecture.md).

## Run nanobom locally

[mise](https://mise.jdx.dev) installs the pinned toolchain (Rust, cargo-leptos, cargo-nextest,
cargo-deny, wasm-bindgen, mdBook…) and runs the tasks. Every cargo command goes through it
(`mise run …` or `mise exec -- cargo …`), since it also sets up the target directory.

```sh
mise install
mise run dev           # server with live reload on http://127.0.0.1:3000
mise run dev-admin     # first administrator of the development database
mise run check         # formatting, clippy, rustdoc, tests and cargo-deny, as CI
mise run test          # tests only (cargo-nextest)
mise run test-postgres # tests on PostgreSQL (see below)
mise run coverage      # tests with coverage, written to lcov.info
mise run build         # release binary and site in target/
mise run docs          # this book, in docs/book
mise run doc           # the API documentation (rustdoc); broken links fail it
mise run sbom          # CycloneDX SBOM of the server, in crates/server/sbom.json
```

`mise run dev` needs neither `/data` nor root. It runs `cargo leptos watch -- serve` (cargo-leptos
passes what follows `--` to the `nanobom` binary, which requires a subcommand) with development
settings that match `site-addr` and `site-root` in `Cargo.toml`: a SQLite database in
`target/dev/nanobom.db`, the site in `target/site`, scheduled runs off, text logs, and
<http://127.0.0.1:3000> as the public URL. The first build takes a few minutes (it compiles the
server and the browser bundle); later changes rebuild and reload the page.

Create the first administrator in that database, then sign in at <http://127.0.0.1:3000/login>:

```sh
mise run dev-admin   # username "admin"; asks for the password
```

Delete `target/dev/` to start over with an empty database.

To run the release build: `mise run build`, then
`NANOBOM_SITE_ROOT=target/site target/release/nanobom serve`.

## Run the tests

`mise run test` runs every test with cargo-nextest. Tests never call real network services: OSV,
CISA, FIRST and webhooks are replaced by [wiremock](https://docs.rs/wiremock) servers or by the
helpers of `nanobom_domain::testing`.

- `crates/domain/tests/` tests the domain against a temporary database, with SBOM fixtures from
  real generators in `crates/domain/tests/fixtures/`.
- `crates/server/tests/server/` drives the HTTP server end to end (uploads, sign-in, the
  interface, operations); `common.rs` starts a server on a fresh database.
- Unit tests sit next to the code they test.

Tests use an in-memory SQLite database each. To run them on PostgreSQL, as CI also does, start an
empty database and point `NANOBOM_TEST_DATABASE_URL` at it; the schema is dropped and recreated
for each test, so `mise run test-postgres` runs them one at a time:

```sh
docker run -d --name nanobom-test-postgres -p 127.0.0.1:5432:5432 \
  -e POSTGRES_USER=nanobom -e POSTGRES_PASSWORD=nanobom -e POSTGRES_DB=nanobom postgres:17-alpine
NANOBOM_TEST_DATABASE_URL=postgres://nanobom:nanobom@localhost:5432/nanobom mise run test-postgres
docker rm -f nanobom-test-postgres
```

Never point it at a database you care about: every test empties it.

## Change the database schema

1. Add a migration to `crates/migration/src/` and list it in `lib.rs`. Never edit a migration
   that was released: instances have already applied it.
2. Regenerate the entities with `mise run entities` (it applies the migrations to a temporary
   database and runs `sea-orm-cli`).

Migrations run at startup, on SQLite and on PostgreSQL: write them with SeaORM's schema builder
rather than SQL of one database, keep them compatible with existing data, and run the tests on
both.

## Add a language

Texts of the interface are in `crates/app/locales/en.json` and `fr.json`, used through the
`t!`, `tf!` and `tp!` macros; messages of the domain (validation errors) are in
`crates/domain/locales/`. Every key must exist in every language: a missing one fails the build.

1. Copy `en.json` to `<tag>.json` in both locale directories, and translate every message
   (`language.name` is the language's name in itself, shown in the account menu).
2. Add the tag to `available_locales` in the `embedded_i18n::i18n!` call at the root of both
   crates, `crates/app/src/lib.rs` and `crates/domain/src/lib.rs`.

The upload API's messages stay in English on purpose: they are read in CI logs.

## Write documentation

This book lives in `docs/` and is built with [mdBook](https://rust-lang.github.io/mdBook/):
`mise run docs` builds it into `docs/book/`, and `mise exec -- mdbook serve docs --port 3001`
serves it with live reload on <http://localhost:3001> (port 3000 is the development server's).
It is published to GitHub Pages from `main`.

It follows [Diátaxis](https://diataxis.fr): tutorials teach, how-to guides reach a goal,
reference describes, explanation gives the why. Put each page in the part of its type, link to
the reference rather than repeating a fact, and check options, defaults and messages against the
code.

## Contribute

- Pull request titles follow [Conventional Commits](https://www.conventionalcommits.org)
  (`feat: add SPDX uploads`, `fix(osv): retry on timeouts`); CI checks them. Pull requests are
  squash-merged, so the title becomes the commit on `main`, from which the version bump and the
  changelog are derived.
- Run `mise run check` before pushing; CI runs the same checks, plus the release build and the
  container image.
- `main` is protected: changes arrive through pull requests, which merge once the
  `CI passed` and `Pull request title` checks succeed. `CI passed` succeeds when every CI job
  does, except coverage, which depends on Codecov being up.
- Keep comments and documentation about what the code does not say: why, constraints,
  trade-offs.

## Release

Releases are automated with release-plz through a release pull request; merging it tags the
version, builds the archives and the images, and publishes the release.
[RELEASING.md](https://github.com/AlixANNERAUD/nanobom/blob/main/RELEASING.md) describes the
process and the required repository settings.
