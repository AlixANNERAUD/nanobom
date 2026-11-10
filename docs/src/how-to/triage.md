# Triage findings

A project with a few hundred dependencies easily has dozens of findings. Why they are ordered as
they are is explained in [Prioritization](../explanation/prioritization.md); a reasonable
routine, from most to least urgent:

1. **Known exploited** findings, tagged **KEV** on the project page: someone exploits them in
   the wild. CISA gives federal agencies a due date to fix each one; it is a fair deadline for
   anyone.
2. **Critical and high** findings with a high EPSS score.
3. The rest, by severity, during regular dependency updates.

Findings that do not apply (vulnerable code not reachable, feature not compiled in, accepted
risk) are ignored with a reason, ideally with an expiry date so the decision is revisited.
Ignoring and restoring need the member role or above ([roles](../reference/accounts.md#organization-roles)).

## Choose what to upgrade

The vulnerable component is often not one your manifest names. On the finding's page,
**Introduced via** lists the paths from the project's direct dependencies to it, such as
`web-framework 2.1.0 → template-engine 0.9.0 → lodash 4.17.20`:

1. A component marked *direct dependency* is yours: upgrade it to a version listed under
   **Fixed in**.
2. Otherwise, upgrade the direct dependency that starts the path to a release that requires a
   fixed version of the component; its changelog, or the diff of your lock file, tells.
3. When no such release exists yet, force the transitive version with your package manager
   (npm `overrides`, Yarn `resolutions`, a Cargo `[patch]` section, Maven
   `<dependencyManagement>`), or ignore the finding with a reason and an expiry.

Each listed path needs the fix: a component reached through two direct dependencies stays until
both require a fixed version. The **Introduced via** column of the project page shows the direct
dependencies of every finding at a glance; findings that share one are often fixed by a single
upgrade. When the page says the SBOM does not tell the project's direct dependencies, its
generator left the graph out ([Dependency paths](../explanation/dependency-paths.md#limits)).

## Ignore a finding

On the finding's page, under **Triage**:

1. **Reason** (required, up to 2,000 characters): why it does not apply or is accepted. It is kept
   in the finding's history with your name, for whoever reads it next year.
2. **Justification** (optional): why the product is not affected, in the CycloneDX vocabulary
   (**Vulnerable code not reachable**, **Requires a configuration not in use**…), or **False
   positive**. Leave **None** for an accepted risk. [VEX exports](vex.md) state that the product
   is not affected only for findings ignored with a justification.
3. **Ignore until** (optional): a date, `YYYY-MM-DD`, after which the finding opens again.
4. Select **Ignore finding**.

Good reasons are specific and checkable:

- "Only the `sqlite` feature of sqlx is compiled; the PostgreSQL driver is not linked."
- "Affects the CLI parsing of `foo`; we only use its library API. Revisit when upgrading to 3.x."

An expiry date turns a decision into a reminder: ignore until the date of the planned upgrade,
not forever. Only open findings can be ignored. Findings can also be ignored by
[importing VEX statements](vex.md); the history then names the upload token instead of a member. What an ignored finding still does, and when it
opens again, is described in
[How findings are kept up to date](../explanation/findings.md#ignored-findings).

## Restore a finding

**Restore finding**, on the page of an ignored finding, returns it to open at once. Only ignored
findings can be restored; fixed findings need no action.

## Filter a project's findings

On the project page, filters narrow the findings by severity, status (open and ignored by
default, or one status, or all), ecosystem, or to **Only known exploited vulnerabilities**:
choose them and select **Filter**. For a project that names versions, the same form chooses the
[version shown](track-versions.md#read-one-version).

The summary under the project's name does not follow the filters: it always counts the open
findings of the version shown, by severity, and how many of them are known exploited.

## Find which projects use a package

The search box at the top of every page finds components across all the organizations you can
see:

| Query | Finds |
| --- | --- |
| `openssl` | components whose name contains `openssl` (case-insensitive) |
| `openssl 3.` | the same, with a version starting with `3.` |
| `lodash@4.17` | the same as `lodash 4.17` |
| `babel/core` | `@babel/core`; leave out a leading `@`, which would start the version |

Names include the namespace of the package URL (`@scope/name` for npm, `group/name` for Maven).
At most 200 results are shown. Search is the quickest answer to "are we affected?" when an
advisory is in the news, before the nightly run has even picked it up.

Results show each component's license. To find components by license, fill the license field
of the search page (`GPL` finds `GPL-3.0-only` and `MIT OR LGPL-2.1-or-later`), with or without
a name; components whose SBOM gives no license show **Unknown** and never match.

From a finding's page, **Also affected** lists the other components affected by the same
vulnerability in the organizations you can see.

## Check a project now

**Check now**, on an organization or project page (members and above), starts a run of that
scope instead of waiting for the next upload or the nightly run.

## Retire a project

A project whose SBOM stopped coming is flagged **Stale** ([stale projects](../explanation/findings.md#stale-projects)).
If it was retired, delete it from its page (admins): its components, upload history and findings
are deleted. With an organization token, a later upload under the same slug creates it again.
