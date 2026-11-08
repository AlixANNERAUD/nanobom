# Concepts

## Organizations

An **organization** owns projects, upload tokens, a webhook and members. Organizations are
isolated: a member of one sees nothing of the others, and an organization you do not belong to
answers "not found" rather than "forbidden", so its name does not leak.

Each organization has a **slug**, which appears in addresses and upload URLs
(`/organizations/acme`, `/api/organizations/acme/projects/web/sbom`), and a display name. Slugs
are 1 to 64 characters among lower-case letters, digits, `.`, `_` and `-`, starting with a
letter or a digit; upper-case letters are folded to lower case, so `Acme` and `acme` are the
same organization.

By default every new user also gets a **personal organization** named after their username,
which they own. It is an ordinary organization; the setting only saves a step for people
working alone. See [Accounts, organizations and access](access/README.md).

## Projects

A **project** is one thing you ship: a service, a library, a container image. It is created by
its first upload with an organization-wide token (or never, with a project token: see
[tokens](uploading/api.md#tokens)). Its slug follows the same rules as organization slugs.

A project holds the components of its **latest** SBOM only. The history of uploads (when, from
which commit or image tag, how many components) is kept; the components of older uploads are
not.

## Uploads

An **upload** is one SBOM sent by CI. It replaces the project's components entirely: a
component missing from the new SBOM is gone, and its findings are fixed at the next run. Upload
one SBOM per project and build, describing everything the project ships.

Components are identified by their package URL. Components without one are counted and listed
in the upload's response but cannot be checked: see
[Generating an SBOM](uploading/generators.md).

## Runs

A **run** matches the components of a scope against OSV and updates the findings. Runs start:

- after each upload, for that project (`upload` trigger);
- on the schedule, for every project of the instance (`scheduled`, by default every night at
  03:00 UTC);
- on demand, with **Check now** on an organization or project page (`manual`).

Runs execute one at a time. A run that cannot complete, because OSV is unreachable for example,
changes nothing: findings stay as they were, and the run is recorded as failed. A failure never
reads as "no vulnerabilities". See [Runs and matching](findings/runs.md).

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

## Aliases

One vulnerability often has several identifiers: a GitHub advisory (`GHSA-…`), a CVE, a
RustSec or PyPA advisory. OSV lists them as **aliases**. nanobom merges identifiers that are
aliases of each other into one finding, named after the smallest identifier it first saw, and
matches it through any of them later: a CVE published after the GHSA does not create a second
finding.

## Severity

Each finding has a severity: **critical**, **high**, **medium**, **low** or **unknown**. It comes
from the CVSS base score (critical from 9.0, high from 7.0, medium from 4.0, low below), using
the most recent CVSS version the advisory gives (4.0, then 3.1, 3.0, 2.0), else the qualitative
rating the advisory database gives (as GitHub advisories do), else unknown. When a finding
merges several identifiers, the highest severity among them wins.

Severity says how bad a vulnerability could be, not whether anyone exploits it; that is what
the [exploitation signals](findings/exploitation.md) are for.
