# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4](https://github.com/AlixANNERAUD/nanobom/compare/v0.1.3...v0.1.4) - 2026-11-14

### Added

- publish an opt-in public page of a project's findings ([#99](https://github.com/AlixANNERAUD/nanobom/pull/99))
- add an About page and a version footer ([#100](https://github.com/AlixANNERAUD/nanobom/pull/100))

### Miscellaneous

- send the rate-limited sign-in attempts together ([#97](https://github.com/AlixANNERAUD/nanobom/pull/97))

## [0.1.3](https://github.com/AlixANNERAUD/nanobom/compare/v0.1.2...v0.1.3) - 2026-11-12

### Added

- add a status badge for projects ([#87](https://github.com/AlixANNERAUD/nanobom/pull/87))
- add a printable vulnerability report for project versions ([#90](https://github.com/AlixANNERAUD/nanobom/pull/90))
- create projects in the interface, each with its own upload token ([#91](https://github.com/AlixANNERAUD/nanobom/pull/91))
- list the components of a project version ([#93](https://github.com/AlixANNERAUD/nanobom/pull/93))
- add an MCP endpoint for assistants ([#94](https://github.com/AlixANNERAUD/nanobom/pull/94))

### Miscellaneous

- render a full vulnerability report ([#92](https://github.com/AlixANNERAUD/nanobom/pull/92))

## [0.1.2](https://github.com/AlixANNERAUD/nanobom/compare/v0.1.1...v0.1.2) - 2026-11-10

### Added

- give the interface a violet accent, bundled fonts and a mark ([#79](https://github.com/AlixANNERAUD/nanobom/pull/79))
- fit the header on one line with a user menu ([#80](https://github.com/AlixANNERAUD/nanobom/pull/80))
- summarize a project's findings and fit each on one line ([#81](https://github.com/AlixANNERAUD/nanobom/pull/81))
- show advisory text as formatted text ([#82](https://github.com/AlixANNERAUD/nanobom/pull/82))
- draw each project's findings and tabulate recent runs ([#84](https://github.com/AlixANNERAUD/nanobom/pull/84))

### Fixed

- apply the dark theme ([#77](https://github.com/AlixANNERAUD/nanobom/pull/77))
- escape page titles ([#83](https://github.com/AlixANNERAUD/nanobom/pull/83))

## [0.1.1](https://github.com/AlixANNERAUD/nanobom/compare/v0.1.0...v0.1.1) - 2026-11-09

### Miscellaneous

- use embedded-i18n 0.2 from crates.io ([#72](https://github.com/AlixANNERAUD/nanobom/pull/72))
- update Cargo.lock dependencies

## [0.1.0](https://github.com/AlixANNERAUD/nanobom/releases/tag/v0.1.0) - 2026-11-09

### Added

- notify known exploited findings and refresh exploitation after runs
- show exploitation signals in the interface
- let uploads wait for their evaluation and fail on findings
- flag and notify projects whose SBOM stopped coming
- retry failed webhook deliveries
- support PostgreSQL as the database
- accept uploads from Dependency-Track clients
- show which direct dependency introduces a vulnerable component
- post webhook notifications to Slack and Microsoft Teams ([#55](https://github.com/AlixANNERAUD/nanobom/pull/55))
- accept SPDX SBOMs ([#56](https://github.com/AlixANNERAUD/nanobom/pull/56))
- export and import CycloneDX VEX statements
- add a read-only API for projects, findings and runs
- cap waiting uploads and re-check tokens before answering
- store and show component licenses
- gate uploads and serve license violations in the read API
- edit the license policy and show violations in the interface
- send notifications by email
- upload SBOMs to named project versions
- choose the project version in the interface
- manage project versions in the interface and read them in the API

### Documentation

- document the server crate
- correct claims about failed runs, logs and redirects

### Fixed

- describe stale projects that never received an SBOM
- answer waiting uploads before webhook deliveries
- refuse fail_on=exploited without exploitation data
- keep a scheduled run scheduled when merged into a queued one
- keep the run worker alive after a panic in a run
- report the upload gate's outcome and counts accurately
- keep the OpenID Connect issuer exactly as configured
- mark runs that stop unexpectedly as failed
- record every webhook delivery before attempting any
- keep the webhook retry loop running after a panic
- abandon pending deliveries when a webhook is disabled or moved
- show a delivery whose first attempt is in progress as Sending
- never make logs more verbose with the PostgreSQL notice directive
- never redirect a form to another site through its Referer
- write logs to standard error
- fail interrupted runs and queue their webhooks in one transaction
- harden the Dependency-Track upload endpoint and its examples
- harden dependency paths and flag partial graphs ([#54](https://github.com/AlixANNERAUD/nanobom/pull/54))
- harden the read API (privacy of counts, caching, token writes)
- harden the exploitation feed refresh
- bound each exploitation feed and keep KEV data when EPSS fails
- omit the exploited badge tooltip when the KEV entry has no due date
- refresh the stale projects gauge on each metrics scrape
- judge invalid license text by the identifiers it names
- harden email delivery, test emails and SMTP credentials

### Miscellaneous

- cover KEV expiry, refresh failures, gauges and migrations

### Other

- Scaffold the workspace, tooling and CI
- Add the migrate and backup commands
- Add the SBOM upload endpoint
- Add organization webhooks and failure payloads
- Run evaluations on a schedule and after uploads
- Add sign-in routes and administration commands
- Add the web interface
- Add the healthcheck command, request logs and security headers
- Translate the interface into French
