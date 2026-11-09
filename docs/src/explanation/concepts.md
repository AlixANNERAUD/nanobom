# Concepts

## Organizations

An **organization** owns projects, API tokens, a webhook and members. Organizations are
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

A project holds the components of its **latest** SBOM only. The history of uploads (when, from
which commit or image tag, how many components) is kept; the components of older uploads are
not.

## Uploads

An **upload** is one SBOM sent by CI. It replaces the project's components entirely: a
component missing from the new SBOM is gone, and its findings are fixed at the next run. Upload
one SBOM per project and build, describing everything the project ships.

Components are identified by their package URL. Components without one are counted and listed
in the upload's response but cannot be checked. The SBOM's dependency graph, when it has one, is
kept with the components and tells which direct dependency of the project pulls in each one
([Dependency paths](dependency-paths.md)).

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

A **finding** is one vulnerability affecting one component of one project. It has a status:

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
