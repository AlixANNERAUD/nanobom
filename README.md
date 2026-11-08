# nanobom

[![CI](https://github.com/AlixANNERAUD/nanobom/actions/workflows/ci.yml/badge.svg)](https://github.com/AlixANNERAUD/nanobom/actions/workflows/ci.yml)
[![codecov](https://codecov.io/github/AlixANNERAUD/nanobom/graph/badge.svg)](https://codecov.io/github/AlixANNERAUD/nanobom)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A lightweight, self-hosted SBOM vulnerability tracker. Your CI uploads a CycloneDX SBOM of each
project; nanobom checks every component against [OSV](https://osv.dev) after each upload and
every night, keeps a history of the vulnerabilities found (open, ignored, fixed), and tells you
about new ones through a webhook.

**Documentation:** the [user and operator guide](https://alixanneraud.github.io/nanobom/) covers
installation, CI integration, prioritization, single sign-on and operations in detail.

- **One binary, one SQLite file.** No queue, no cache server; about 20 MB of container image.
- **Organizations and roles** (viewer, member, admin, owner), each organization isolated from the
  others; local accounts and OpenID Connect single sign-on, with roles mapped from groups.
- **Findings with a lifecycle**: opened, fixed when the component goes away, reopened when it
  comes back, ignored with a reason and an optional expiry. OSV aliases (GHSA, CVE, …) of one
  vulnerability are merged into one finding.
- **Exploitation signals**: findings are matched against CISA's Known Exploited Vulnerabilities
  catalog and FIRST's EPSS scores, and listed with known exploited ones first.
- **A CI gate**: an upload can wait for its evaluation and fail the pipeline when open findings
  reach a severity, or are known exploited.
- **Webhooks** per organization for new findings above a severity (and for known exploited ones
  at any severity), for projects whose SBOM stopped coming, and an instance-wide webhook when a
  run fails.
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
| Gate | `wait=true` waits for the project's evaluation and returns it; `fail_on=critical`, `high`, `medium`, `low` or `exploited` (case-insensitive) implies `wait` and fails the upload when it is met |
| Responses | `201` project created, `200` updated, `401` no valid token, `403` token of another project, `404` unknown organization, `409` open findings reach `fail_on`, `413` too large (`NANOBOM_MAXIMUM_SBOM_SIZE`), `422` invalid document or parameter, `503` evaluation did not complete (with `fail_on`); errors are `{"error": "…"}` |

The response lists the components without a package URL, which OSV cannot match: most often a
generator setting. Generators that work well:

| Ecosystem | Command |
| --- | --- |
| Rust | `cargo cyclonedx --format json` ([cargo-cyclonedx](https://github.com/CycloneDX/cyclonedx-rust-cargo)) |
| npm | `npx @cyclonedx/cyclonedx-npm --output-file sbom.json` |
| Python | `cyclonedx-py environment --output-file sbom.json` |
| Container images, anything else | `syft <image or directory> -o cyclonedx-json=sbom.json` ([Syft](https://github.com/anchore/syft)) |

### Failing a pipeline on findings

With `wait` or `fail_on`, the request returns once the project has been evaluated, or after
`NANOBOM_UPLOAD_WAIT_SECONDS`. The SBOM is stored in any case. The evaluation is added to the
response:

```sh
curl --fail-with-body -X PUT \
  -H "Authorization: Bearer $NANOBOM_TOKEN" \
  --data-binary @sbom.json \
  "https://nanobom.example.org/api/organizations/acme/projects/web/sbom?fail_on=high"
```

```json
{
  "error": "2 open findings at or above high",
  "organization": "acme",
  "project": "web",
  "project_id": 3,
  "project_created": false,
  "upload_id": 58,
  "component_count": 212,
  "components_without_purl": 0,
  "skipped": [],
  "evaluation": {
    "status": "succeeded",
    "run_id": 42,
    "open": { "critical": 0, "high": 2, "medium": 5, "low": 1, "unknown": 0 },
    "known_exploited": 1,
    "findings": [
      {
        "vulnerability": "GHSA-35jh-r3h4-6jhm",
        "component": "pkg:npm/lodash@4.17.20",
        "severity": "high",
        "known_exploited": true,
        "url": "https://nanobom.example.org/findings/17"
      }
    ]
  }
}
```

`evaluation.status` is `succeeded`, `failed` (OSV was unreachable) or `timed_out`, in which case
`run_id` is `null` and the run still finishes in the background. `open` counts the project's open
findings, ignored ones excluded; `findings` lists the most severe first (known exploited ones
first among equals), at most 100; `known_exploited` counts all of them. `error` is present only
when the upload fails:

| Status | Meaning |
| --- | --- |
| `409` | The evaluation succeeded and open findings reach `fail_on`: at or above that severity, or known exploited for `exploited` |
| `503` | With `fail_on`, the evaluation failed or timed out, so the findings are not up to date; the gate does not pass |

Without `fail_on`, `wait=true` only adds the evaluation, and the status stays `200` or `201`.
A project is evaluated when waiting even if `NANOBOM_RUN_AFTER_UPLOAD` is `false`. `fail_on` is
trimmed and case-insensitive. Invalid parameters are refused with a `422` before anything is
stored, with one of these errors:

- `wait must be true or false`;
- `fail_on must be critical, high, medium, low or exploited`;
- `fail_on=exploited needs exploitation data (NANOBOM_EXPLOITATION_DATA)`, when
  `NANOBOM_EXPLOITATION_DATA` is `false`: no finding could ever be known exploited.

To stop gating a pipeline, remove `fail_on` from the URL.

A reverse proxy in front of nanobom must let the request wait: with nginx, set
`proxy_read_timeout` above `NANOBOM_UPLOAD_WAIT_SECONDS` (300 seconds by default), or lower the
setting.

On GitHub Actions, the [nanobom action](https://github.com/AlixANNERAUD/nanobom-action) does
all of this in one step, generating the SBOM with Syft when none is given, and lists the
project's open findings in the job summary:

```yaml
- uses: AlixANNERAUD/nanobom-action@v1
  with:
    url: ${{ vars.NANOBOM_URL }}
    token: ${{ secrets.NANOBOM_TOKEN }}
    organization: acme
    fail-on: high
```

Complete pipelines, both failing on high findings: [GitHub Actions](examples/github-actions.yml),
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

### Exploitation signals

Severity says how bad a vulnerability could be, not whether anyone uses it. After each
successful run, nanobom downloads, for the CVEs of the scope's open and ignored findings (the
CVEs among a finding's identifier and aliases):

- the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  (KEV) catalog: a finding with a CVE in it is **known exploited**, with the date CISA added it,
  its remediation due date and whether ransomware campaigns use it. The catalog is kept in
  memory for 12 hours;
- the [EPSS](https://www.first.org/epss/) score and percentile from FIRST: the estimated
  probability of exploitation in the next 30 days, refreshed when older than 24 hours.

A finding with several CVEs takes the most alarming of each signal. Findings are ordered known
exploited first, then by severity, then by EPSS score within a severity (findings without one
last) and by CVSS score; the findings list can be limited to known exploited ones. The refresh
runs before uploads waiting for the run are answered, so `fail_on=exploited` sees the CVEs the
run found, and is abandoned after 60 seconds. If a download fails or the refresh is abandoned,
the previous exploitation data is kept, the run is not affected and
`nanobom_exploitation_refresh_failures_total` increases; after a failed download of the KEV
catalog, refreshes fail at once for 5 minutes instead of retrying it.
`NANOBOM_EXPLOITATION_DATA=false` turns this off, for instances that cannot reach those services
(open findings are then never known exploited, and `fail_on=exploited` is refused).

### Stale projects

A project whose last upload (or creation, if it never received an SBOM) is older than
`NANOBOM_STALE_AFTER_DAYS` is flagged **stale** in the interface and counted by
`nanobom_stale_projects`: its CI job probably stopped. Its organization's webhook is notified
once per stale period, after a scheduled run (see below). `0` turns the feature off.

## Webhooks

Each organization can set one webhook (Settings → Webhook), a minimum severity, and whether to
deliver only known exploited findings. After a successful run, nanobom POSTs `findings.new`
for the findings that are new or reopened at or above the minimum severity, and for known
exploited ones at any severity:

```json
{
  "event": "findings.new",
  "organization": { "slug": "acme", "name": "Acme", "url": "https://nanobom.example.org/organizations/acme" },
  "run": { "id": 42, "trigger": "scheduled", "started_at": "2026-11-08T03:00:00Z" },
  "count": 1,
  "highest_severity": "high",
  "known_exploited_count": 1,
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
      "reason": "new",
      "known_exploited": true,
      "kev_due_date": "2026-11-29",
      "epss": 0.0149,
      "epss_percentile": 0.78,
      "url": "https://nanobom.example.org/findings/17"
    }
  ]
}
```

`reason` is `new`, `reopened` (`reopened` is true then) or `exploited`: an open finding that
became known exploited after it was reported, delivered once. `kev_due_date`, `epss` and
`epss_percentile` are `null` when unknown. With the exploited-only option, only known exploited
findings are delivered. After an upgrade to the version that added exploitation signals, the first
run delivers every open known exploited finding of its scope once with the `exploited` reason, as
none had been notified as such.

After a scheduled run, projects that became stale (see above) are sent as `projects.stale`,
whatever the minimum severity and the exploited-only option:

```json
{
  "event": "projects.stale",
  "organization": { "slug": "acme", "name": "Acme", "url": "https://nanobom.example.org/organizations/acme" },
  "projects": [
    {
      "project": "web",
      "last_upload_at": "2026-09-30T14:21:07Z",
      "url": "https://nanobom.example.org/organizations/acme/projects/web"
    }
  ]
}
```

`last_upload_at` is `null` for a project that never received an SBOM. A project is notified
again only if it uploads an SBOM and later becomes stale again.

`NANOBOM_FAILURE_WEBHOOK_URL` receives `{"event": "run.failed", "instance_url", "run", "scope",
"error"}` when a run fails. Severities are `critical`, `high`, `medium`, `low` and `unknown`.
[`examples/home-assistant.yaml`](examples/home-assistant.yaml) turns new findings into phone
notifications with Home Assistant, flagging the known exploited ones.

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
| `NANOBOM_UPLOAD_WAIT_SECONDS` | `300` | Longest an upload with `wait` or `fail_on` waits for its evaluation |
| `NANOBOM_OSV_URL` | `https://api.osv.dev/` | OSV API |
| `NANOBOM_EXPLOITATION_DATA` | `true` | Download exploitation data (CISA KEV, FIRST EPSS) after each run |
| `NANOBOM_KEV_URL` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | CISA Known Exploited Vulnerabilities catalog (JSON) |
| `NANOBOM_EPSS_URL` | `https://api.first.org/data/v1/epss` | FIRST EPSS API |
| `NANOBOM_STALE_AFTER_DAYS` | `30` | Days without an SBOM after which a project is stale; `0` disables the feature |
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
  `nanobom_open_findings_known_exploited`, `nanobom_stale_projects`,
  `nanobom_runs_total{status}`, `nanobom_run_failures_total`, `nanobom_run_duration_seconds`,
  `nanobom_last_successful_run_timestamp_seconds`, `nanobom_osv_request_errors_total` and
  `nanobom_exploitation_refresh_failures_total`. Labels are instance-wide, so their number stays
  small. Alert on the last successful run getting old, on open known exploited findings, and on
  stale projects.
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
