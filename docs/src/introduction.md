# Introduction

nanobom is a self-hosted tracker of the vulnerabilities in the software you ship. Your CI
uploads a [CycloneDX](https://cyclonedx.org) SBOM (software bill of materials) of each project;
nanobom checks every component against [OSV](https://osv.dev) right after the upload and again
every night, keeps the history of what it found, and tells you when something new appears.

It is one binary and one SQLite file: no queue, no cache server, no scanner to keep up to date.
The container image is about 20 MB.

## What it does

- **Keeps an inventory.** Each upload replaces the project's list of components, so nanobom
  always knows what each project ships today, and can tell you which projects use a given
  package.
- **Matches it against OSV, every day.** New advisories appear for old versions all the time; the
  nightly run catches them without a new build.
- **Tracks findings over time.** A vulnerability affecting a component is a *finding*. It is
  fixed when the component goes away, reopened if it comes back, and can be ignored with a
  reason and an expiry date. Identifiers of the same vulnerability in different databases (a
  GHSA and its CVE, for instance) are merged into one finding.
- **Helps you prioritize.** Findings carry a severity from their CVSS scores, and two
  exploitation signals: whether CISA lists the vulnerability as exploited in the wild (KEV), and
  the EPSS probability of exploitation. Known exploited findings come first.
- **Gates CI.** An upload can wait for its evaluation and fail the pipeline when open findings
  reach a severity, or are known exploited.
- **Notifies you.** Each organization can send new findings and projects whose SBOM stopped
  coming to a webhook; the instance can report failed runs to another.
- **Separates teams.** Organizations are isolated from each other; members have one of four
  roles. Sign-in uses local accounts, OpenID Connect, or both, with roles mapped from your
  identity provider's groups.

## What it does not do

- **It does not generate SBOMs.** Your build does, with the generator of your ecosystem (see
  [Generate an SBOM](how-to/generate-sbom.md)). nanobom only reads CycloneDX JSON, versions 1.3
  to 1.7; SPDX is not supported.
- **It does not scan images or file systems.** It trusts the SBOM. A component missing from the
  SBOM is invisible to nanobom.
- **It only knows what OSV knows.** Components are matched by their
  [package URL](https://github.com/package-url/purl-spec) (`pkg:npm/lodash@4.17.20`); a component
  without one, or from an ecosystem OSV does not cover, cannot be checked. Vulnerabilities of
  your own code are out of scope.
- **It does not judge reachability.** A finding means a vulnerable version is present, not that
  the vulnerable code is called. Triage, with a reason kept in the history, is how you record
  that a finding does not apply.
- **It has no API besides uploads.** The web interface is the way to read findings and manage
  organizations; the HTTP API accepts SBOMs (and returns an evaluation for CI). Webhooks and
  Prometheus metrics are the machine-readable outputs.

## How this documentation is organized

It has four parts, one per need:

- **[Tutorials](tutorials/first-scan.md)** are lessons. Follow them in order, step by step, when
  you are new to nanobom: [Your first scan](tutorials/first-scan.md) runs it on your machine,
  [Gate a repository's CI](tutorials/gate-ci.md) wires a GitHub repository to it.
- **[How-to guides](how-to/install.md)** are recipes for a goal you already have: install an
  instance, upload from GitLab CI, set up single sign-on, back up the database, fix an upload
  that answers `503`.
- **[Reference](reference/configuration.md)** describes the machinery, completely and without
  commentary: every option, command, API field, webhook field, permission and metric. Look
  things up there.
- **[Explanation](explanation/concepts.md)** is background to read away from the keyboard: what
  organizations, runs and findings are, how findings are kept up to date, why exploitation
  signals come first, what protects what, how the code is laid out.

nanobom is free software under the
[Apache-2.0 license](https://github.com/AlixANNERAUD/nanobom/blob/main/LICENSE); the source,
issues and releases are on [GitHub](https://github.com/AlixANNERAUD/nanobom).
