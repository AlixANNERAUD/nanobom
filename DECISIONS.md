# Decisions

Choices made while building nanobom, with the reasons and the alternatives considered. Newest at
the bottom of each section.

## Project layout and tooling

- **Cargo workspace with one crate per concern.** `entity` (SeaORM entities), `migration`
  (schema), `domain` (inventory, OSV, findings, organizations and the access rules, testable
  without HTTP), `app` (Leptos interface, `ssr` and `hydrate` features), `frontend` (the
  WebAssembly entry point) and `server` (the `nanobom` binary: CLI, HTTP, authentication).
  Server-only crates never reach the browser bundle. Alternative: the single-crate Leptos
  template, which mixes server code behind `cfg` attributes everywhere.
- **mise for tools and tasks.** `mise.toml` pins Rust, cargo-leptos, cargo-nextest, cargo-deny
  and the wasm-bindgen CLI (which must match the `wasm-bindgen` version in `Cargo.lock`).
  `mise run check` runs what CI runs. Local builds go through mr-boxington for shared compiler
  caching; CI selects `MISE_ENV=ci`, which turns that off and relies on `rust-cache` instead, so CI
  does not depend on a local cache layout.
- **Server-side commands exclude `nanobom-frontend`.** Building the browser crate and the server
  in one Cargo invocation would unify the `ssr` and `hydrate` features of the interface crate.
  The frontend is linted separately for `wasm32-unknown-unknown`.
- **cargo-deny ignores RUSTSEC-2024-0436** (`paste` is unmaintained). It is a compile-time macro
  pulled in by Leptos with no known vulnerability; drop the exception when Leptos moves off it.
- **GitHub Actions are pinned by commit SHA**, with the release tag in a comment.

## Dependencies

- **reqwest 0.12 rather than 0.13.** `openidconnect` 4 is built on reqwest 0.12; using the same
  version keeps one HTTP client in the binary, with rustls and ring (no OpenSSL, no C toolchain
  beyond what ring needs).
- **tower-sessions 0.14**, the version `axum-login` 0.18 is built on.
- **`tower_governor` without default features**, which would otherwise pull in `tonic`.
- **password-auth 1.0** rather than 2.0, which was released two days before this choice; both use
  Argon2id.
- **Own session store on top of SeaORM.** `tower-sessions-sqlx-store` 0.15 is built on sqlx 0.8,
  while SeaORM 2 uses sqlx 0.9, so the two cannot share a connection pool. A `SessionStore`
  implemented with SeaORM (about a hundred lines) uses the same pool, works on every database
  SeaORM supports and its table is created by our migrations. Alternative: SeaORM 1.1 (sqlx 0.8),
  an older major version.
