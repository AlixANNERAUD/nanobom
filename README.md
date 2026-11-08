# nanobom

[![CI](https://github.com/AlixANNERAUD/nanobom/actions/workflows/ci.yml/badge.svg)](https://github.com/AlixANNERAUD/nanobom/actions/workflows/ci.yml)
[![codecov](https://codecov.io/github/AlixANNERAUD/nanobom/graph/badge.svg)](https://codecov.io/github/AlixANNERAUD/nanobom)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A lightweight, self-hosted SBOM vulnerability tracker. Your CI uploads a CycloneDX SBOM of each
project; nanobom checks every component against [OSV](https://osv.dev) after each upload and
every night, keeps a history of the vulnerabilities found (open, ignored, fixed), and tells you
about new ones through a webhook.

- **One binary, one SQLite file.** No queue, no cache server; about 20 MB of container image.
- **Organizations and roles** (viewer, member, admin, owner), each organization isolated from the
  others; local accounts and OpenID Connect single sign-on, with roles mapped from groups.
- **Findings with a lifecycle**: opened, fixed when the component goes away, reopened when it
  comes back, ignored with a reason and an optional expiry. OSV aliases (GHSA, CVE, …) of one
  vulnerability are merged into one finding.
- **Webhooks** per organization for new findings above a severity, and an instance-wide webhook
  when a run fails.
- **Works without JavaScript**, in English and French, light and dark.
- **Operations**: `/healthz`, Prometheus `/metrics`, JSON logs, online backups.

## Quick start

With Docker Compose, from a clone of this repository ([`compose.yaml`](compose.yaml)):

```sh
docker compose up -d --wait

# The first instance administrator; the password is read from standard input.
docker compose exec nanobom /app/nanobom create-administrator --username admin
```

It uses the published image, or builds it from the checkout when there is none. Settings go in
the environment or a `.env` file (`NANOBOM_PUBLIC_URL`, `NANOBOM_PORT`, …). Without Compose:

```sh
docker run -d --name nanobom -p 8080:8080 -v nanobom-data:/data \
  -e NANOBOM_PUBLIC_URL=http://localhost:8080 \
  ghcr.io/alixanneraud/nanobom:latest
docker exec -it nanobom /app/nanobom create-administrator --username admin
```

Open <http://localhost:8080>, sign in, and create an organization (every user also gets a
personal one). In its settings, create an **upload token**: it is shown once.

[`examples/compose.yaml`](examples/compose.yaml) runs nanobom with Docker Compose behind a
reverse proxy. Images exist for amd64 and arm64; release archives with the binary and its
`site` directory are attached to each [release](https://github.com/AlixANNERAUD/nanobom/releases)
for running without containers (`NANOBOM_SITE_ROOT` points at the `site` directory).

## Uploading SBOMs

One request per project and build: the SBOM replaces the project's components, and the project
is created by its first upload.

```sh
curl --fail-with-body -X PUT \
  -H "Authorization: Bearer $NANOBOM_TOKEN" \
  --data-binary @sbom.json \
  "https://nanobom.example.org/api/organizations/acme/projects/web/sbom?source_commit=$COMMIT&image_tag=$TAG"
```

| | |
| --- | --- |
| Formats | CycloneDX JSON, specification 1.3 to 1.7 |
| Tokens | Organization tokens may create projects; project tokens upload to their project only |
| Metadata | `source_commit` and `image_tag` query parameters, both optional, shown in the history |
| Responses | `201` project created, `200` updated, `401` no valid token, `403` token of another project, `404` unknown organization, `413` too large (`NANOBOM_MAXIMUM_SBOM_SIZE`), `422` invalid document; errors are `{"error": "…"}` |

The response lists the components without a package URL, which OSV cannot match: most often a
generator setting. Generators that work well:

| Ecosystem | Command |
| --- | --- |
| Rust | `cargo cyclonedx --format json` ([cargo-cyclonedx](https://github.com/CycloneDX/cyclonedx-rust-cargo)) |
| npm | `npx @cyclonedx/cyclonedx-npm --output-file sbom.json` |
| Python | `cyclonedx-py environment --output-file sbom.json` |
| Container images, anything else | `syft <image or directory> -o cyclonedx-json=sbom.json` ([Syft](https://github.com/anchore/syft)) |

Complete pipelines: [GitHub Actions](examples/github-actions.yml),
[GitLab CI](examples/gitlab-ci.yml). Upload tokens can also be managed from the command line:
`nanobom token create --organization acme --name CI [--project web]`, `token list`,
`token revoke --id N`.

## Findings and runs

A run queries OSV for the package URLs of its scope (one project after an upload, an
organization on demand, everything on the schedule), then updates findings:

- a vulnerability reported for a component opens a finding, named after the smallest of its
  identifiers; later runs match it through any alias, so a new CVE for a GHSA does not duplicate it;
- a finding whose component disappears, or that OSV no longer reports (withdrawn records
  included), is fixed; if it comes back, it is reopened;
- an ignored finding stays ignored until its expiry date, if any, then opens again.

Severity is the highest of the group: CVSS 4.0, then 3.1, 3.0 and 2.0 base scores, then the
severity the advisory database gives, else unknown. A run that cannot reach OSV changes nothing
and calls the failure webhook. Runs are serialized: one at a time.

## Webhooks

Each organization can set one webhook (Settings → Webhook) and a minimum severity. After a run
with new or reopened findings at or above it, nanobom POSTs:

```json
{
  "event": "findings.new",
  "organization": { "slug": "acme", "name": "Acme", "url": "https://nanobom.example.org/organizations/acme" },
  "run": { "id": 42, "trigger": "scheduled", "started_at": "2026-11-08T03:00:00Z" },
  "count": 1,
  "highest_severity": "critical",
  "findings": [
    {
      "project": "web",
      "component": "pkg:npm/lodash@4.17.20",
      "vulnerability": "GHSA-35jh-r3h4-6jhm",
      "aliases": ["CVE-2021-23337"],
      "severity": "high",
      "cvss_score": 7.2,
      "summary": "Command Injection in lodash",
      "reopened": false,
      "url": "https://nanobom.example.org/findings/17"
    }
  ]
}
```

`NANOBOM_FAILURE_WEBHOOK_URL` receives `{"event": "run.failed", "instance_url", "run", "scope",
"error"}` when a run fails. Severities are `critical`, `high`, `medium`, `low` and `unknown`.
[`examples/home-assistant.yaml`](examples/home-assistant.yaml) turns new findings into phone
notifications with Home Assistant.

## Sign-in

Local accounts are on by default (`NANOBOM_LOCAL_ACCOUNTS`); passwords are hashed with Argon2id
and sign-in attempts are rate limited per client address. Instance administrators create users
and reset passwords from the administration page.

OpenID Connect is enabled by `NANOBOM_OIDC_ISSUER` and `NANOBOM_OIDC_CLIENT_ID` (authorization
code flow with PKCE; the redirect URI is `<public URL>/auth/oidc/callback`). Users are matched by
issuer and subject, never by email address. A claim can grant instance administration, and a
groups claim maps to organization roles at each sign-in:

```sh
NANOBOM_OIDC_GROUPS_CLAIM=groups
NANOBOM_OIDC_GROUP_MAPPING="security=acme:admin;developers=acme:member;auditors=acme:viewer"
NANOBOM_OIDC_ADMINISTRATOR_CLAIM=groups
NANOBOM_OIDC_ADMINISTRATOR_VALUE=nanobom-admins
```

Organizations named by the mapping are created when missing. Roles from the provider are kept
apart from those given in nanobom; a member has the higher of the two.

## Configuration

Every option is an environment variable (or a command-line flag, see `nanobom serve --help`).

| Variable | Default | |
| --- | --- | --- |
| `NANOBOM_PUBLIC_URL` | `http://localhost:8080` | Address users reach nanobom at: links, sign-in redirects, cross-site checks; cookies are `Secure` when it is https |
| `NANOBOM_DATABASE_URL` | `sqlite:///data/nanobom.db` | SQLite database, created if missing |
| `NANOBOM_LISTEN_ADDRESS` | `0.0.0.0:8080` | Address and port to listen on |
| `NANOBOM_SITE_ROOT` | `site` | The web interface's assets (`/app/site` in the image) |
| `NANOBOM_SCHEDULE` | `0 3 * * *` | When everything is re-evaluated: cron in UTC, or `off` |
| `NANOBOM_RUN_AFTER_UPLOAD` | `true` | Evaluate a project right after each upload |
| `NANOBOM_OSV_URL` | `https://api.osv.dev/` | OSV API |
| `NANOBOM_MAXIMUM_SBOM_SIZE` | `16` | Largest SBOM, in MiB |
| `NANOBOM_FAILURE_WEBHOOK_URL` | | Called when a run fails |
| `NANOBOM_LOCAL_ACCOUNTS` | `true` | Sign-in with username or email address and password |
| `NANOBOM_PASSWORD_MINIMUM_LENGTH` | `12` | Minimum length of local passwords |
| `NANOBOM_PERSONAL_ORGANIZATIONS` | `true` | Give each new user an organization of their own |
| `NANOBOM_SESSION_INACTIVITY_DAYS` | `7` | Sign users out after this many idle days |
| `NANOBOM_TRUST_FORWARDED_HEADERS` | `false` | Read client addresses from `X-Forwarded-For`; only behind a proxy that sets it |
| `NANOBOM_OIDC_ISSUER`, `NANOBOM_OIDC_CLIENT_ID`, `NANOBOM_OIDC_CLIENT_SECRET` | | OpenID Connect provider and client; the secret is optional for public clients |
| `NANOBOM_OIDC_SCOPES` | `openid profile email` | Scopes to request |
| `NANOBOM_OIDC_CREATE_USERS` | `true` | Create users at their first sign-in |
| `NANOBOM_OIDC_ADMINISTRATOR_CLAIM`, `NANOBOM_OIDC_ADMINISTRATOR_VALUE` | | Claim (and value) granting instance administration |
| `NANOBOM_OIDC_GROUPS_CLAIM`, `NANOBOM_OIDC_GROUP_MAPPING` | | Groups claim and `group=organization:role;…` mapping |
| `NANOBOM_OIDC_BUTTON_LABEL` | `Sign in with single sign-on` | Label of the sign-in button |
| `NANOBOM_LOG_FORMAT` | `json` | `json` or `text` |
| `NANOBOM_LOG_LEVEL` | `info` | [`tracing` filter](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html), such as `info,nanobom=debug` |

## Operations

- **Health**: `GET /healthz` answers 200 when the database does, 503 otherwise. The image's
  health check runs `nanobom healthcheck`, which asks it over loopback.
- **Metrics**: `GET /metrics` in the Prometheus format: `nanobom_open_findings{severity}`,
  `nanobom_runs_total{status}`, `nanobom_run_failures_total`, `nanobom_run_duration_seconds`,
  `nanobom_last_successful_run_timestamp_seconds` and `nanobom_osv_request_errors_total`. Labels
  are instance-wide, so their number stays small. Alert on the last successful run getting old.
- **Logs**: one JSON object per line on standard output, one line per request (paths without
  query strings; probes and assets at debug level).
- **Backups**: `nanobom backup /data/backups/nanobom-$(date +%F).db` writes a consistent copy of
  the live database (`VACUUM INTO`); it never overwrites a file.
- **Upgrades**: migrations run when the server starts (`nanobom migrate` runs them alone).

Run it behind a reverse proxy that terminates TLS, with `NANOBOM_PUBLIC_URL` set to its https
address.

## Development

[mise](https://mise.jdx.dev) installs the pinned toolchain (Rust, cargo-leptos, cargo-nextest,
cargo-deny, wasm-bindgen) and runs the tasks:

```sh
mise install
mise run dev      # server with live reload on http://127.0.0.1:3000
mise run check    # formatting, clippy, tests and cargo-deny, as CI
mise run coverage # tests with coverage, written to lcov.info
mise run build    # release binary and site in target/
```

Pull request titles follow [Conventional Commits](https://www.conventionalcommits.org)
(`feat: …`, `fix: …`): they become the commits on `main` from which releases and the
[changelog](CHANGELOG.md) are made. [RELEASING.md](RELEASING.md) describes the release process.

The workspace has one crate per concern: `domain` (inventory, OSV matching, findings,
organizations and the access rules), `osv`, `authentication`, `entity` and `migration`
(SeaORM), `app` (the Leptos interface) and `server` (the `nanobom` binary). Interface texts are
in `crates/app/locales/` and domain messages in `crates/domain/locales/`; a message missing from
a language fails the build.

## License

[Apache-2.0](LICENSE).
