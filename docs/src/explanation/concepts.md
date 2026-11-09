# Concepts

## Organizations

An **organization** owns projects, API tokens, a webhook, email recipients and members. Organizations are
isolated: a member of one sees nothing of the others, and an organization you do not belong to
answers "not found" rather than "forbidden", so its name does not leak.

Each organization has a **slug**, which appears in addresses and upload URLs
(`/organizations/acme`, `/api/organizations/acme/projects/web/sbom`), and a display name. Slugs
are case-insensitive: `Acme` and `acme` are the same organization (the rules are in the
[reference](../reference/accounts.md#names)).

Members have one of four [roles](../reference/accounts.md#organization-roles): viewer, member,
admin or owner. Instance administrators act as owners of every organization.

By default every new user also gets a **personal organization** named after their username,
which they own. It is an ordinary organization; the setting only saves a step for people
working alone.

## Projects

A **project** is one thing you ship: a service, a library, a container image. It is created by
its first upload with an organization-wide token (or never, with a project token: see
[tokens](../reference/upload-api.md#tokens)). Its slug follows the same rules as organization
slugs.

A project holds the components of the last SBOM of each of its [versions](#versions) only.
The history of uploads (when, to which version, from which commit or image tag, how many
components) is kept; the components of older uploads are not.

## Versions

A product often ships several releases at once: `3.x` is current while `2.x` still gets
security fixes. A **version** of a project is one of them. Each version has its own
components, findings and triage, so fixing lodash on the main branch does not hide that the
`2.4` maintenance branch still ships the vulnerable one, and ignoring a finding in `2.4` does
not ignore it in `3.0`, where the code may have changed.

CI names the version with each upload ([`version`](../reference/upload-api.md#versions)); a
project that never names one has a single, **unnamed** version and works as if versions did not
exist. One version is the **latest**: the project page, the read API and the VEX export show it
unless asked for another. A new version becomes the latest unless the upload says otherwise,
which is what a maintenance branch does (`latest=false`).

When an upload creates a version, the new version **inherits** the open and ignored findings of
the latest version, as Dependency-Track copies the audit trail when it clones a version: a
release branched from `main` has the same dependencies and the same reasons to ignore a
finding, and nobody should have to triage them again. Each inherited finding keeps its
status, its ignore (reason, justification, expiry) and its first-seen date, and its history
starts with one event naming the version it came from. The run after the upload then treats
inherited findings like any other: those whose component the new SBOM no longer has are fixed.

Inherited findings are **not announced**: they are not news, and announcing every finding of
the latest version each time a release branch is cut would bury the findings that are. A
vulnerability that appears in several versions at once (a new advisory against a dependency
they share) is announced once per affected component, with the list of versions it affects
([payloads](../reference/webhooks.md)). Fixed findings are not inherited: an ignore ends when its
finding is fixed, so they carry nothing the new version needs, and a vulnerability fixed in the
latest version but present in the new one is announced as new for it.

Versions also keep the database small: a project has at most 50 active versions. Organization
pages count a vulnerability of a package once per project, at its highest severity, however
many versions have it; the gate of an upload (`fail_on`) judges the version uploaded only.

## Uploads

An **upload** is one SBOM sent by CI. It replaces the components of one version of the project
entirely: a component missing from the new SBOM is gone, and its findings in that version are
fixed at the next run. Upload one SBOM per project, version and build, describing everything
the version ships.

Components are identified by their package URL. Components without one are counted and listed
in the upload's response but cannot be checked. The SBOM's dependency graph, when it has one, is
kept with the components and tells which direct dependency of the project pulls in each one
([Dependency paths](dependency-paths.md)). So is each component's license, as the SBOM states
it: one SPDX license expression, shown on findings and in search results
([how licenses are read](../reference/upload-api.md#the-document)). An organization's
**license policy** allows, warns about or forbids licenses; the components that break it are
computed from the last SBOM of a version whenever they are shown ([License policies](licenses.md)).

## Runs

A **run** matches the components of a scope against OSV and updates the findings. Runs start:

- after each upload, for that project (`upload` trigger);
- on the schedule, for every project of the instance (`scheduled`, by default every night at
  03:00 UTC);
- on demand, with **Check now** on an organization or project page (`manual`).

Runs execute one at a time. A run that cannot complete, because OSV is unreachable for example,
changes nothing: findings stay as they were, and the run is recorded as failed. A failure never
reads as "no vulnerabilities". See [How findings are kept up to date](findings.md).

## Findings

A **finding** is one vulnerability affecting one component of one version of a project. It has a
status:

| Status | Meaning | Becomes |
| --- | --- | --- |
| **Open** | The vulnerability affects a current component | *ignored* by a member; *fixed* when the component goes away or OSV stops reporting it |
| **Ignored** | A member decided it does not apply or is accepted, with a reason | *open* when restored or when its expiry date passes; *fixed* like an open one |
| **Fixed** | No longer affects the project | *open* again (**reopened**) if a run reports it again |

Every change is kept in the finding's history, with who did it, why, and which run.

```text
            upload / run reports it
                     │
                     ▼
   ┌──────────►   OPEN   ◄───────────────┐
   │             │    │                  │ restored, or
   │  ignored    │    │ component gone,  │ ignore expired
   │  (reason)   ▼    │ or OSV stops     │
   │         IGNORED ─┼─ reporting it ───┘
   │                  ▼
   └── reopened ── FIXED
```

One vulnerability often has several identifiers: a GitHub advisory (`GHSA-…`), a CVE, a RustSec
or PyPA advisory. OSV lists them as **aliases**, and nanobom merges identifiers that are aliases
of each other into one finding: a CVE published after the GHSA does not create a second finding
([aliases](findings.md#aliases)).

Each finding has a **severity**, critical, high, medium, low or unknown, from the CVSS scores of
its advisories ([severity](findings.md#severity)). Severity says how bad a vulnerability could
be, not whether anyone exploits it; that is what the
[exploitation signals](prioritization.md) are for.
