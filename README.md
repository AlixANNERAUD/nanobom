<h1 align="center">nanobom</h1>

<p align="center">
  <strong>The lightweight, self-hosted SBOM vulnerability tracker.</strong><br>
  Know what you ship, see what is actually exploited, and stop it in CI,
  with one container and a SQLite file (or PostgreSQL).
</p>

<p align="center">
  <a href="https://github.com/AlixANNERAUD/nanobom/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/AlixANNERAUD/nanobom/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://codecov.io/github/AlixANNERAUD/nanobom"><img alt="Coverage" src="https://codecov.io/github/AlixANNERAUD/nanobom/graph/badge.svg"></a>
  <a href="https://alixanneraud.github.io/nanobom/"><img alt="Documentation" src="https://img.shields.io/badge/docs-guide-blue"></a>
  <a href="https://github.com/AlixANNERAUD/nanobom-action"><img alt="GitHub Action" src="https://img.shields.io/badge/GitHub%20Action-nanobom--action-2088FF?logo=githubactions&logoColor=white"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
</p>

---

Your CI uploads a **CycloneDX or SPDX SBOM** of each project. nanobom checks every component against
**[OSV](https://osv.dev)** after each upload and every night, keeps the history of each
vulnerability (open, ignored, fixed, reopened), tells you which ones are **known to be exploited
(CISA KEV)** or likely to be (**EPSS**), and can **fail the pipeline** before a vulnerable build
ships.

It is built for small teams, homelabs and anyone who wants software composition analysis without
running a Java stack, a database server and a vulnerability-database mirror: a lightweight,
self-hosted alternative to heavier platforms such as OWASP Dependency-Track.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/src/images/project-dark.png">
    <img
      src="docs/src/images/project-light.png"
      width="900"
      alt="A project in nanobom: a bar of its open findings by severity, then one line per finding with its severity and score, a tag on the known exploited ones, the component, the direct dependency that brings it in and its EPSS percentile."
    >
  </picture>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/src/images/organization-dark.png">
    <img
      src="docs/src/images/organization-light.png"
      width="49%"
      alt="An organization in nanobom: each project with a bar of its open findings and their counts by severity, then the recent runs."
    >
  </picture>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/src/images/finding-dark.png">
    <img
      src="docs/src/images/finding-light.png"
      width="49%"
      alt="A finding in nanobom: the advisory text, the affected component with its version and CVSS vector, and the dependency that introduces it."
    >
  </picture>
</p>

## Try it in two minutes

```sh
git clone https://github.com/AlixANNERAUD/nanobom && cd nanobom
docker compose up -d --wait
docker compose exec nanobom /app/nanobom create-administrator --username admin
```

Open <http://localhost:8080>, sign in, create an upload token in your organization's settings,
and upload an SBOM:

```sh
curl -X PUT -H "Authorization: Bearer $NANOBOM_TOKEN" --data-binary @sbom.json \
  "http://localhost:8080/api/organizations/admin/projects/my-app/sbom?wait=true"
```

The [first-scan tutorial](https://alixanneraud.github.io/nanobom/tutorials/first-scan.html) walks
through it with a sample SBOM.

## Gate your CI in one step

```yaml
- uses: AlixANNERAUD/nanobom-action@v1
  with:
    url: ${{ vars.NANOBOM_URL }}
    token: ${{ secrets.NANOBOM_TOKEN }}
    organization: acme
    fail-on: high        # or critical, medium, low, exploited
```

The [nanobom action](https://github.com/AlixANNERAUD/nanobom-action) generates the SBOM with Syft
when you don't have one, uploads it, writes the project's open vulnerabilities to the job summary
and fails the job when they cross your threshold. GitLab CI does the same with the
[GitLab CI template](https://alixanneraud.github.io/nanobom/how-to/upload-from-ci.html#gitlab-ci),
and any other CI with a single `curl` call: see
[uploading from CI](https://alixanneraud.github.io/nanobom/how-to/upload-from-ci.html).
Pipelines that upload to Dependency-Track (gh-upload-sbom, the Jenkins and Maven plugins, scripts)
upload to nanobom with a new address and key: see [Dependency-Track clients](https://alixanneraud.github.io/nanobom/how-to/dependency-track-clients.html).

## What you get

**Know what you ship**
- CycloneDX 1.3 to 1.7 and SPDX 2.2 and 2.3 (JSON) from any generator: cargo-cyclonedx,
  cyclonedx-npm, cyclonedx-py, Syft and Trivy for container images and anything else, GitHub's
  dependency graph export.
- Every component matched against OSV, which aggregates GitHub, PyPI, RustSec, Go, npm, Debian,
  Alpine and more; aliases (GHSA, CVE, …) of one vulnerability merged into one finding.
- A history per project: uploads with their commit and image tag, findings opened, fixed,
  reopened or ignored with a reason and an expiry date.
- Several versions per project, for maintenance branches next to the main one: each with its own
  findings and triage, a new version starting with the triage of the latest one, a
  vulnerability that hits several versions announced once, each finding showing where every
  version stands, and old versions made inactive (kept, no longer checked) or deleted.

**Fix what matters first**
- Known-exploited vulnerabilities (CISA KEV) flagged, with their remediation due date.
- EPSS exploitation probability to order what is left; severity from CVSS 4.0 down to 2.0.
- The direct dependency that pulls in each vulnerable component, from the SBOM's dependency
  graph: what to upgrade.
- Search across every project: "which of our services ship `openssl 3.0`?"
  Each component's license is kept from the SBOM, and searchable too.

**Stop it before it ships**
- `fail_on` on uploads: fail the build on critical, high, … or known-exploited findings, or on
  licenses your organization forbids.
- A license policy per organization: allow, warn about or forbid SPDX licenses (an allowlist if
  you want), with each project's violations and SPDX `AND`/`OR` expressions understood.
- CycloneDX VEX: export which vulnerabilities do not affect a project, and why, for customers
  and auditors; import a vendor's statements or your own to ignore findings.
- Notifications per organization for new and newly exploited vulnerabilities, and for projects
  whose SBOM stopped coming: webhooks as JSON or as messages posted straight to Slack and
  Microsoft Teams, and emails in English or French through your SMTP server; a Home Assistant
  example turns webhooks into phone notifications.

**Fits your stack**
- One container (about 20 MB compressed, amd64 and arm64) with its database, SQLite in a volume
  or PostgreSQL; no queue, no cache server, no vulnerability mirror to keep in sync.
- Organizations and roles, local accounts and OpenID Connect single sign-on (Keycloak, Zitadel,
  Authentik, …) with roles mapped from groups.
- A read-only JSON API, described in OpenAPI, for dashboards and scripts, with read-only tokens.
- Prometheus metrics, health check, JSON logs, online backups.
- Server-rendered interface that works without JavaScript, in English and French, light and
  dark.

## Documentation

The full guide lives at **<https://alixanneraud.github.io/nanobom/>**:

- **Tutorials** - [your first scan](https://alixanneraud.github.io/nanobom/tutorials/first-scan.html),
  [gate a repository's CI](https://alixanneraud.github.io/nanobom/tutorials/gate-ci.html).
- **How-to guides** - [install](https://alixanneraud.github.io/nanobom/how-to/install.html),
  [generate an SBOM](https://alixanneraud.github.io/nanobom/how-to/generate-sbom.html),
  [enforce a license policy](https://alixanneraud.github.io/nanobom/how-to/license-policy.html),
  [single sign-on](https://alixanneraud.github.io/nanobom/how-to/single-sign-on.html),
  [reverse proxy and TLS](https://alixanneraud.github.io/nanobom/how-to/reverse-proxy.html),
  [monitoring](https://alixanneraud.github.io/nanobom/how-to/monitoring.html),
  [backups and upgrades](https://alixanneraud.github.io/nanobom/how-to/maintenance.html),
  [troubleshooting](https://alixanneraud.github.io/nanobom/how-to/troubleshoot.html), …
- **Reference** - [configuration](https://alixanneraud.github.io/nanobom/reference/configuration.html),
  [upload API](https://alixanneraud.github.io/nanobom/reference/upload-api.html),
  [read API](https://alixanneraud.github.io/nanobom/reference/read-api.html),
  [webhook payloads and emails](https://alixanneraud.github.io/nanobom/reference/webhooks.html),
  [roles and permissions](https://alixanneraud.github.io/nanobom/reference/accounts.html),
  [metrics](https://alixanneraud.github.io/nanobom/reference/metrics.html).
- **Explanation** - [concepts](https://alixanneraud.github.io/nanobom/explanation/concepts.html),
  [how findings stay up to date](https://alixanneraud.github.io/nanobom/explanation/findings.html),
  [prioritization](https://alixanneraud.github.io/nanobom/explanation/prioritization.html),
  [dependency paths](https://alixanneraud.github.io/nanobom/explanation/dependency-paths.html),
  [security model](https://alixanneraud.github.io/nanobom/explanation/security.html),
  [architecture](https://alixanneraud.github.io/nanobom/explanation/architecture.html).

## Is nanobom for you?

Choose nanobom if you want vulnerability tracking for your SBOMs with almost no operations: one
small container, sensible defaults, answers in the CI job and a webhook when something new is
exploited.

Choose a larger platform such as [Dependency-Track](https://dependencytrack.org) if you need
full license compliance (obligations, attribution, licenses detected from source) or policy
engines with conditions beyond licenses and vulnerabilities, a broad plugin and integration
ecosystem, or very large portfolios managed by a dedicated team. nanobom deliberately stays small; see the
[issues](https://github.com/AlixANNERAUD/nanobom/issues) for what is planned next.

## Contributing

Issues and pull requests are welcome. Development uses [mise](https://mise.jdx.dev) for the
toolchain (`mise install`, then `mise run check` for what CI runs); pull request titles follow
[Conventional Commits](https://www.conventionalcommits.org), from which releases and the
changelog are made. See [develop and contribute](https://alixanneraud.github.io/nanobom/how-to/develop.html)
and [RELEASING.md](RELEASING.md).

## License

[Apache-2.0](LICENSE).
